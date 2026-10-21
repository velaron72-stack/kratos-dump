// Structure reports: sections, segments, relocations, imports and exports.
#include <cxxabi.h>

#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

std::string demangled_suffix(const Config& cfg, const std::string& n) {
  if (!cfg.b("func.demangle") || n.size() < 3 || n[0] != '_' || n[1] != 'Z' || n.size() > 4096) return "";
  int st = 0;
  char* d = abi::__cxa_demangle(n.c_str(), nullptr, nullptr, &st);
  std::string r = (st == 0 && d) ? std::string("  // ") + d : "";
  std::free(d);
  return r;
}

const ElfSymbol* sym_of(const ElfModel& m, u32 idx, u8 table) {
  const auto& t = table == 1 ? m.symtab : m.dynsym;
  // Tables are stored in index order starting at 0; look up directly and fall back to a search by index.
  if (idx < t.size() && t[idx].index == idx) return &t[idx];
  for (auto& s : t)
    if (s.index == idx) return &s;
  return nullptr;
}

const char* reloc_kind_name(u8 k) {
  switch (k) {
    case 0: return "REL";
    case 1: return "RELA";
    case 2: return "PLT";
    case 3: return "APS2";
    case 4: return "RELR";
  }
  return "?";
}

}  // namespace

bool stage_report_structure(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  const ElfModel& m = lc.elf;
  const AddrCols ac = AddrCols::from(cfg);
  const bool detailed = cfg.s("general.detail_level") == "detailed" || cfg.s("general.detail_level") == "full";
  const int depth = (int)cfg.i("general.depth");
  if (!lc.elf_ok) {
    for (const char* n : {"sections.txt", "segments.txt", "relocations.txt", "imports.txt", "exports.txt"}) report_unavailable(rc, lc.index, n, "the library is not a readable ELF file");
    return true;
  }

  // ---------------------------------------------------------------- sections
  if (report_wanted(rc, "out.sections")) {
    if (m.secs.empty()) {
      report_unavailable(rc, lc.index, "sections.txt", "no section table and no program headers to rebuild one from");
    } else if (auto rf = open_report(rc, lc, "sections.txt", "sections", 0)) {
      OutFile& f = rf->f();
      if (m.secs_reconstructed) f.line("# NOTE: the section table is missing or unusable; these are pseudo sections built from program headers (names and boundaries are approximate)");
      else if (!m.secs_ok) f.line("# NOTE: section table could not be read");
      f.line("# columns: idx name type flags " + ac.header() + "size link info align entsize");
      for (auto& s : m.secs) {
        u64 va = s.addr;
        bool hv = s.alloc() || s.synthetic;
        std::string line = strf("[%2d] %-24s %-14s %-6s ", s.index, s.name.c_str(), sec_type_name(s.type), sec_flags_str(s.flags).c_str());
        line += ac.fmt(m, s.has_file_data() || s.synthetic, s.offset, hv, va);
        line += strf("size=0x%llx link=%u info=%u align=%llu entsize=%llu", (unsigned long long)s.size, s.link, s.info, (unsigned long long)s.addralign, (unsigned long long)s.entsize);
        if (s.synthetic) line += "  [reconstructed]";
        if (s.flags & elf::SHF_COMPRESSED) line += "  [compressed]";
        if (s.has_file_data() && s.offset + s.size > lc.size) line += "  [extends beyond the file]";
        f.object();
        f.line(line);
      }
      f.line("");
      f.line(strf("# %zu sections", m.secs.size()));
      close_report(rc, *rf);
    }
  }

  // ---------------------------------------------------------------- segments
  if (report_wanted(rc, "out.segments")) {
    if (m.segs.empty()) {
      report_unavailable(rc, lc.index, "segments.txt", "program header table is missing or unreadable");
    } else if (auto rf = open_report(rc, lc, "segments.txt", "segments", 0)) {
      OutFile& f = rf->f();
      f.line(strf("# image base (lowest PT_LOAD address, page aligned): 0x%llx; RVA = vaddr - 0x%llx", (unsigned long long)m.load_base_rel, (unsigned long long)m.load_base_rel));
      if (m.phdr_assumed) f.line("# NOTE: e_phoff was invalid; the table was read from the standard position (inferred)");
      f.line("# columns: idx type flags " + ac.header() + "filesz memsz align paddr");
      for (auto& s : m.segs) {
        std::string line = strf("[%2d] %-14s %-4s ", s.index, seg_type_name(s.type), seg_flags_str(s.flags).c_str());
        line += ac.fmt(m, true, s.offset, true, s.vaddr);
        line += strf("filesz=0x%llx memsz=0x%llx align=0x%llx paddr=0x%llx", (unsigned long long)s.filesz, (unsigned long long)s.memsz, (unsigned long long)s.align,
                     (unsigned long long)s.paddr);
        if (s.synthetic) line += "  [reconstructed]";
        if (s.offset + s.filesz > lc.size) line += "  [extends beyond the file]";
        if ((s.flags & elf::PF_W) && (s.flags & elf::PF_X)) line += "  [W+X]";
        f.object();
        f.line(line);
      }
      f.line("");
      f.line(strf("# %zu segments", m.segs.size()));
      close_report(rc, *rf);
    }
  }

  // ---------------------------------------------------------------- relocations
  if (report_wanted(rc, "out.relocations")) {
    if (!cfg.b("lib.parse_relocs")) {
      report_skipped(rc, lc.index, "relocations.txt", "relocation parsing is disabled in the library settings");
    } else if (m.relocs.empty()) {
      report_unavailable(rc, lc.index, "relocations.txt", m.relocs_partial ? "relocation tables are unreadable" : "the library has no relocations");
    } else if (auto rf = open_report(rc, lc, "relocations.txt", "relocations", cfg.limit("limits.max_relocs"))) {
      OutFile& f = rf->f();
      if (m.relocs_from_dynamic) f.line("# NOTE: tables were located through the dynamic section (the section table is unusable)");
      if (m.relocs_partial) f.line("# NOTE: the relocation list is incomplete (damaged data or limit)");
      f.line("# columns: kind type " + ac.header() + "addend symbol");
      u64 n = 0;
      for (auto& r : m.relocs) {
        u64 off = 0;
        bool hv = m.vaddr_to_off(r.offset, off);
        std::string sym;
        if (r.sym) {
          const ElfSymbol* s = sym_of(m, r.sym, r.table);
          sym = s ? (s->name.empty() ? strf("<sym %u>", r.sym) : s->name) : strf("<sym %u unavailable>", r.sym);
        }
        std::string line = strf("%-5s %-26s ", reloc_kind_name(r.kind), reloc_type_name(m, r.type).c_str());
        line += ac.fmt(m, hv, off, true, r.offset);
        line += r.has_addend ? strf("%+lld ", (long long)r.addend) : std::string("-  ");
        line += sym.empty() ? "-" : sym;
        if (!f.object()) break;
        if (!f.line(line)) break;
        n++;
      }
      f.line("");
      f.line(strf("# %llu of %zu relocations written", (unsigned long long)n, m.relocs.size()));
      close_report(rc, *rf);
    }
  }

  if (depth < 2) {
    for (const char* k : {"out.imports", "out.exports"})
      if (report_wanted(rc, k)) report_skipped(rc, lc.index, std::string(k == std::string("out.imports") ? "imports.txt" : "exports.txt"), "analysis depth is below 2");
    return true;
  }

  // ---------------------------------------------------------------- imports
  const u64 max_sym = cfg.limit("limits.max_symbols");
  if (report_wanted(rc, "out.imports")) {
    if (!cfg.b("lib.parse_symbols")) {
      report_skipped(rc, lc.index, "imports.txt", "symbol parsing is disabled in the library settings");
    } else if (m.dynsym.empty() && m.needed.empty()) {
      report_unavailable(rc, lc.index, "imports.txt", "no dynamic symbol table and no dynamic dependencies were found");
    } else if (auto rf = open_report(rc, lc, "imports.txt", "imports", max_sym)) {
      OutFile& f = rf->f();
      if (m.dynsym_from_dynamic) f.line("# NOTE: dynamic symbols were located through the dynamic section (inferred table size)");
      if (m.reparsed_extra_symbols) f.line(strf("# NOTE: %llu symbols were added from indices referenced by relocations (recovered)", (unsigned long long)m.reparsed_extra_symbols));
      if (!m.soname.empty()) f.line("# SONAME: " + m.soname);
      for (auto& n : m.needed) f.line("# NEEDED: " + n);
      std::unordered_map<u32, std::vector<u64>> slots;
      for (auto& r : m.relocs)
        if (r.table == 0 && r.sym && (reloc_is_jump_slot(m, r.type) || reloc_is_glob_dat(m, r.type) || reloc_is_abs(m, r.type))) {
          auto& v = slots[r.sym];
          if (v.size() < 4) v.push_back(r.offset);
        }
      std::unordered_map<u64, u64> stub_of;
      for (auto& s : lc.scan.plt) stub_of[s.got] = s.addr;
      f.line("# columns: bind type got_slot plt_stub name");
      u64 n = 0;
      for (auto& s : m.dynsym) {
        if (!s.undefined() || s.index == 0 || s.name.empty()) continue;
        std::string got = "-", stub = "-";
        auto it = slots.find(s.index);
        if (it != slots.end()) {
          got.clear();
          for (u64 g : it->second) got += (got.empty() ? "" : ",") + strf("0x%llx", (unsigned long long)g);
          for (u64 g : it->second) {
            auto st = stub_of.find(g);
            if (st != stub_of.end()) {
              stub = strf("0x%llx", (unsigned long long)st->second);
              break;
            }
          }
        }
        if (!f.object()) break;
        if (!f.line(strf("%-6s %-8s %-12s %-12s %s%s", sym_bind_name(s.bind()), sym_type_name(s.type()), got.c_str(), stub.c_str(), s.name.c_str(), demangled_suffix(cfg, s.name).c_str())))
          break;
        n++;
      }
      f.line("");
      f.line(strf("# %llu imported symbols, %zu dependencies", (unsigned long long)n, m.needed.size()));
      if (detailed && lc.scan.ran && lc.scan.plt.empty()) f.line("# PLT stubs were not recognized, so the plt_stub column is empty");
      close_report(rc, *rf);
    }
  }

  // ---------------------------------------------------------------- exports
  if (report_wanted(rc, "out.exports")) {
    if (!cfg.b("lib.parse_symbols")) {
      report_skipped(rc, lc.index, "exports.txt", "symbol parsing is disabled in the library settings");
    } else if (m.dynsym.empty()) {
      report_unavailable(rc, lc.index, "exports.txt", "the dynamic symbol table is missing or unreadable");
    } else if (auto rf = open_report(rc, lc, "exports.txt", "exports", max_sym)) {
      OutFile& f = rf->f();
      if (m.dynsym_from_dynamic) f.line("# NOTE: dynamic symbols were located through the dynamic section (inferred table size)");
      f.line("# columns: " + ac.header() + "size bind type [section] name");
      const bool arm32 = m.arch == Arch::Arm;
      u64 n = 0;
      for (auto& s : m.dynsym) {
        if (s.undefined() || s.index == 0 || s.bind() == elf::STB_LOCAL || s.type() == elf::STT_SECTION || s.type() == elf::STT_FILE) continue;
        if (s.name.empty()) continue;
        u64 va = arm32 ? (s.value & ~(u64)1) : s.value;
        u64 off = 0;
        bool hv = s.shndx != elf::SHN_ABS && s.type() != elf::STT_TLS;
        bool ho = hv && m.vaddr_to_off(va, off);
        std::string line = ac.fmt(m, ho, off, hv, va);
        line += strf("%-8llx %-6s %-8s [%s] %s", (unsigned long long)s.size, sym_bind_name(s.bind()), sym_type_name(s.type()), sym_shndx_name(m, s.shndx).c_str(), s.name.c_str());
        if (arm32 && (s.value & 1) && s.type() == elf::STT_FUNC) line += " (thumb)";
        line += demangled_suffix(cfg, s.name);
        if (!f.object()) break;
        if (!f.line(line)) break;
        n++;
      }
      f.line("");
      f.line(strf("# %llu exported symbols", (unsigned long long)n));
      close_report(rc, *rf);
    }
  }
  return true;
}

}  // namespace kratos
