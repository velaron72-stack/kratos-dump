// Address resolution from a memory map (/proc/<pid>/maps format) of a test process or a saved maps file.
// The library is never loaded or executed: only text is read.
#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

struct Mapping {
  u64 start = 0, end = 0, pgoff = 0, inode = 0;
  std::string perms, dev, path;
};

bool parse_maps_line(const std::string& line, Mapping& m) {
  // start-end perms offset dev inode [path]
  const char* p = line.c_str();
  char* e = nullptr;
  m.start = strtoull(p, &e, 16);
  if (e == p || *e != '-') return false;
  p = e + 1;
  m.end = strtoull(p, &e, 16);
  if (e == p || *e != ' ') return false;
  p = e + 1;
  const char* q = p;
  while (*q && *q != ' ') q++;
  m.perms.assign(p, q);
  if (m.perms.size() < 3) return false;
  while (*q == ' ') q++;
  p = q;
  m.pgoff = strtoull(p, &e, 16);
  if (e == p) return false;
  q = e;
  while (*q == ' ') q++;
  p = q;
  while (*q && *q != ' ') q++;
  m.dev.assign(p, q);
  while (*q == ' ') q++;
  p = q;
  m.inode = strtoull(p, &e, 10);
  if (e == p) return false;
  q = e;
  while (*q == ' ') q++;
  m.path = q;
  return m.end > m.start;
}

u64 align_down(u64 v, u64 a) { return v & ~(a - 1); }

}  // namespace

bool stage_dynamic(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  DynamicResult& d = lc.dyn;
  d = DynamicResult();
  d.ran = true;
  auto unavailable = [&](const std::string& why) {
    d.available = false;
    d.reason = why;
    rc.ledger.add_gap("unavailable", "dynamic address resolution", why, lc.index);
    rc.log->log(LogLevel::Warning, "dynamic", lc.display + ": " + why);
    stage_partial(why);
    return true;
  };
  if (!lc.elf_ok) return unavailable("the library is not a readable ELF file");

  // ---- source of the map ----
  std::string text, origin;
  const std::string scenario = cfg.s("dyn.scenario");
  if (scenario == "proc_pid") {
    i64 pid = cfg.i("dyn.pid");
    if (pid <= 0) return unavailable("no PID is set for the proc_pid scenario");
    origin = "/proc/" + std::to_string(pid) + "/maps";
  } else {
    origin = cfg.s("dyn.maps_path");
    if (origin.empty()) return unavailable("no path to a maps file is set");
  }
  if (!read_text_file(origin, text, 16u << 20)) return unavailable("cannot read " + origin + " (the file is missing or not accessible to the application)");

  std::vector<Mapping> maps;
  u64 bad_lines = 0;
  for (auto& ln : split(text, '\n')) {
    if (trim(ln).empty()) continue;
    Mapping m;
    if (parse_maps_line(ln, m)) maps.push_back(m);
    else bad_lines++;
  }
  if (maps.empty()) return unavailable("no valid memory map lines in " + origin);

  if (cfg.b("dyn.save_artifacts")) {
    std::lock_guard<std::mutex> g(rc.mu);
    std::string dst = path_join(rc.meta_dir, "dynamic_maps.txt");
    if (!path_exists(dst)) {
      mkdirs(rc.meta_dir);
      std::string err;
      if (write_text_file(dst, text, err)) {
        FileRec fr;
        fr.name = "dynamic_maps.txt";
        fr.rel_path = "metadata/dynamic_maps.txt";
        fr.bytes = text.size();
        rc.ledger.add_file(fr);
      } else {
        rc.warn("dynamic", "cannot save the map: " + err);
      }
    }
  }

  // ---- match mappings to this library ----
  const std::string lib_base = base_name(lc.entry_name.find('!') != std::string::npos ? lc.entry_name.substr(lc.entry_name.find('!') + 1) : lc.entry_name);
  const std::string inner = lc.entry_name.find('!') != std::string::npos ? lc.entry_name.substr(lc.entry_name.find('!') + 1) : lc.entry_name;
  u64 apk_data_off = 0, apk_len = 0;
  bool apk_stored = false;
  if (lc.from_apk && lc.entry_name.find('!') == std::string::npos && rc.zip) {
    const ZipEntry* e = rc.zip->find(lc.entry_name);
    if (e && e->method == 0 && e->data_ok) {
      apk_stored = true;
      apk_data_off = e->data_off;
      apk_len = e->uncomp_size;
    }
  }
  std::vector<const Mapping*> hits;
  u64 file_shift = 0;  // file offset = pgoff - file_shift
  bool via_apk = false;
  for (auto& m : maps) {
    if (m.path.empty() || m.path[0] == '[') continue;
    std::string bn = base_name(m.path);
    bool by_name = bn == lib_base || (m.path.find("!/") != std::string::npos && ends_with(m.path, "!/" + inner));
    if (by_name) hits.push_back(&m);
  }
  if (hits.empty() && apk_stored) {
    for (auto& m : maps) {
      if (!ends_with(to_lower(m.path), ".apk")) continue;
      if (m.pgoff >= apk_data_off && m.pgoff < apk_data_off + apk_len) hits.push_back(&m);
    }
    if (!hits.empty()) {
      via_apk = true;
      file_shift = apk_data_off;
    }
  }
  if (hits.empty()) return unavailable("the map has no mapping of " + lib_base);

  const Mapping* low = hits[0];
  for (auto* h : hits)
    if (h->start < low->start) low = h;
  d.base = low->start;
  d.module_path = low->path;
  d.maps_matched = hits.size();
  u64 file_off = low->pgoff - std::min(low->pgoff, file_shift);
  u64 va_at_start;
  if (!lc.elf.off_to_vaddr(file_off, va_at_start)) {
    va_at_start = lc.elf.min_load_vaddr;
    d.lines.push_back("note: the first mapping does not correspond to a loadable segment; the lowest PT_LOAD address is assumed");
  }
  d.bias = low->start - align_down(va_at_start, 0x1000);

  // consistency: every PT_LOAD must lie in a matched mapping
  for (auto& s : lc.elf.segs) {
    if (s.type != elf::PT_LOAD || s.memsz == 0) continue;
    d.loads_total++;
    u64 a = s.vaddr + d.bias;
    for (auto* h : hits)
      if (a >= h->start && a < h->end) {
        d.loads_consistent++;
        break;
      }
  }
  d.available = true;
  d.lines.push_back(strf("module mapping: %s", d.module_path.c_str()));
  d.lines.push_back(strf("lowest mapped address: 0x%llx", (unsigned long long)d.base));
  d.lines.push_back(strf("load bias: 0x%llx (runtime address = vaddr + bias)", (unsigned long long)d.bias));
  d.lines.push_back(strf("mappings matched: %zu%s", hits.size(), via_apk ? " (library mapped directly from the APK)" : ""));
  d.lines.push_back(strf("loadable segments inside matched mappings: %llu of %llu", (unsigned long long)d.loads_consistent, (unsigned long long)d.loads_total));
  if (d.loads_consistent != d.loads_total) {
    rc.ledger.add_gap("partial", "dynamic address resolution", "some loadable segments are not covered by the matched mappings (the library may be partly mapped or the map is from another build)", lc.index);
    stage_partial("segments not fully covered by the map");
  }
  if (bad_lines) d.lines.push_back(strf("lines of the map that could not be parsed: %llu", (unsigned long long)bad_lines));

  // ---- address table ----
  std::unique_ptr<ReportFile> rf = open_report(rc, lc, "dynamic_addresses.txt", "runtime addresses from a memory map", cfg.limit("limits.max_functions"));
  if (rf) {
    OutFile& f = rf->f();
    f.line("# map source: " + (rc.reproducible() ? std::string("(omitted in reproducible mode)") : origin));
    for (auto& l : d.lines) f.line("# " + l);
    f.line("# addresses below are computed from the map; the library was not loaded or executed");
    f.line("");
    f.line("segments (PT_LOAD)");
    f.line(strf("%-4s %-18s %-18s %-10s %s", "idx", "runtime_start", "runtime_end", "memsz", "flags"));
    for (auto& s : lc.elf.segs) {
      if (s.type != elf::PT_LOAD) continue;
      f.line(strf("%-4d 0x%016llx 0x%016llx 0x%-8llx %s", s.index, (unsigned long long)(s.vaddr + d.bias), (unsigned long long)(s.vaddr + s.memsz + d.bias),
                  (unsigned long long)s.memsz, seg_flags_str(s.flags).c_str()));
    }
    f.line("");
    f.line("named functions (runtime = vaddr + bias; T = Thumb, the real call address has bit 0 set)");
    f.line(strf("%-18s %-10s %-10s %s", "runtime", "rva", "size", "name"));
    for (auto& fn : lc.funcs.list) {
      if (fn.generated) continue;
      if (!f.object()) break;
      f.line(strf("0x%016llx 0x%08llx %-10s %s%s", (unsigned long long)(fn.vaddr + d.bias), (unsigned long long)lc.elf.rva(fn.vaddr),
                  fn.size_known ? strf("0x%llx", (unsigned long long)fn.size).c_str() : "-", fn.name.c_str(), fn.thumb ? "  T" : ""));
    }
    close_report(rc, *rf);
  }
  if (cfg.b("dyn.log")) {
    std::lock_guard<std::mutex> g(rc.mu);
    mkdirs(rc.logs_dir);
    FILE* lf = fopen(path_join(rc.logs_dir, "dynamic.log").c_str(), "ab");
    if (lf) {
      fprintf(lf, "[%s]\n", lc.display.c_str());
      for (auto& l : d.lines) fprintf(lf, "  %s\n", l.c_str());
      fclose(lf);
    }
  }
  rc.log->log(LogLevel::Ok, "dynamic", strf("%s: load bias 0x%llx from %zu mappings", lc.display.c_str(), (unsigned long long)d.bias, hits.size()));
  return true;
}

}  // namespace kratos
