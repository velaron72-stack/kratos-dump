// APK handling: archive scan, library/metadata discovery, ABI validation, selection and extraction; standalone library input.
#include <unistd.h>

#include "kratos/stages.h"

namespace kratos {

namespace {

bool probe_elf(const u8* h, size_t n, ApkLib& l) {
  if (n < 20 || memcmp(h, "\x7f" "ELF", 4) != 0) return false;
  // Damaged class or byte order bytes are inferred from the other header fields: such a file is still a library to analyze.
  IdentGuess ig = n >= 24 ? elf_guess_ident(h, n, UINT64_MAX) : IdentGuess();
  if (!ig.valid) {
    if (h[4] != 1 && h[4] != 2) return false;
    if (h[5] != 1 && h[5] != 2) return false;
    ig.is64 = h[4] == 2;
    ig.le = h[5] == 1;
  }
  l.bits = ig.is64 ? 64 : 32;
  l.le = ig.le;
  u16 machine = rd16(h + 18, l.le);
  switch (machine) {
    case 183: l.arch = Arch::Arm64; break;
    case 40: l.arch = Arch::Arm; break;
    case 62: l.arch = Arch::X86_64; break;
    case 3: l.arch = Arch::X86; break;
    default: l.arch = Arch::Other; break;
  }
  return true;
}

bool ends_with_ci(const std::string& s, const std::string& suffix) {
  if (suffix.size() > s.size()) return false;
  return to_lower(s.substr(s.size() - suffix.size())) == to_lower(suffix);
}

bool matches_any_ci(const std::string& s, const std::vector<std::string>& needles) {
  for (auto& n : needles)
    if (!n.empty() && contains_ci(s, n)) return true;
  return false;
}

std::vector<std::string> split_trim(const std::string& s) {
  std::vector<std::string> out;
  for (auto& p : split(s, ',')) {
    std::string t = trim(p);
    if (!t.empty()) out.push_back(t);
  }
  return out;
}

struct ScanCtx {
  const Config& cfg;
  Logger& log;
  CancelToken* cancel;
  std::string temp_dir;
  ApkScan& out;
  std::map<std::string, std::shared_ptr<ZipArchive>>* keep;
  std::vector<std::string>* temp_files;
  std::vector<std::string> ext, inc, exc;
  bool validate, companions, nested;
  bool all_entries_scope;
  u64 probed = 0;
};

void scan_archive(ScanCtx& c, ZipArchive& z, const std::string& prefix, const std::string& nested_name, int level) {
  ApkScan& out = c.out;
  const auto& entries = z.entries();
  for (auto& w : z.warnings()) out.warnings.push_back((nested_name.empty() ? "" : nested_name + ": ") + w);
  if (level == 0) {
    out.recovered = z.recovered();
    out.zip64 = z.zip64();
  }
  u64 idx = 0;
  bool has_manifest = false;
  u64 dex_count = 0;
  for (auto& e : entries) {
    if ((++idx & 0x3ff) == 0 && c.cancel && c.cancel->cancelled()) return;
    if (e.is_dir) {
      if (level == 0) out.dirs++;
      continue;
    }
    if (level == 0) {
      out.entries++;
      out.total_uncompressed += e.uncomp_size;
      out.total_compressed += e.comp_size;
      out.methods[zip_method_name(e.method)]++;
      size_t sl = e.name.find('/');
      std::string top = sl == std::string::npos ? "(root)" : e.name.substr(0, sl + 1);
      auto& td = out.top_dirs[top];
      td.first++;
      td.second += e.uncomp_size;
    }
    const std::string full = prefix + e.name;
    const std::string bn = base_name(e.name);
    if (e.name == "AndroidManifest.xml") has_manifest = true;
    if (ends_with_ci(bn, ".dex")) dex_count++;

    // ---- library candidates ----
    bool is_lib = false;
    for (auto& x : c.ext)
      if (ends_with_ci(bn, x)) is_lib = true;
    if (is_lib && !c.inc.empty() && !matches_any_ci(e.name, c.inc)) is_lib = false;
    if (is_lib && !c.exc.empty() && matches_any_ci(e.name, c.exc)) is_lib = false;
    if (is_lib) {
      ApkLib l;
      l.entry = full;
      l.name = bn;
      l.size = e.uncomp_size;
      l.nested = nested_name;
      std::vector<std::string> parts = split(e.name, '/');
      if (parts.size() >= 3 && parts[0] == "lib") {
        l.abi = parts[1];
        out.has_lib_dir = true;
      } else {
        l.note = "outside lib/";
      }
      if (e.encrypted) {
        l.note = "encrypted entry: cannot be read";
      } else if (c.validate) {
        std::vector<u8> head;
        std::string err;
        if (z.read_head(e, 64, head, err)) {
          l.validated = true;
          l.is_elf = probe_elf(head.data(), head.size(), l);
          if (!l.is_elf) l.note = "not an ELF file (content does not start with an ELF header)";
          else {
            const char* exp = abi_for_arch(l.arch);
            if (!l.abi.empty() && exp[0] && l.abi != exp) l.note = "directory says " + l.abi + " but the ELF header says " + exp + " (content wins)";
          }
        } else {
          l.note = "entry cannot be read: " + err;
        }
      } else {
        l.is_elf = true;  // not checked
      }
      if (!l.abi.empty() && std::find(out.abis.begin(), out.abis.end(), l.abi) == out.abis.end()) out.abis.push_back(l.abi);
      if (e.duplicate) l.note += (l.note.empty() ? "" : "; ") + std::string("duplicate entry name: the last one is used by Android");
      out.libs.push_back(std::move(l));
    }

    // ---- metadata candidates (IL2CPP) ----
    bool by_name = to_lower(bn) == "global-metadata.dat";
    bool in_scope = c.all_entries_scope || e.name.compare(0, 7, "assets/") == 0 || e.name.compare(0, 8, "res/raw/") == 0;
    if (!is_lib && !e.encrypted && (by_name || (c.companions && in_scope && e.uncomp_size >= 256 && c.probed < 3000 && (ends_with_ci(bn, ".dat") || bn.find('.') == std::string::npos)))) {
      std::vector<u8> head;
      std::string err;
      c.probed += by_name ? 0 : 1;
      if (z.read_head(e, 8, head, err) && head.size() >= 4 && rd32(head.data(), true) == 0xFAB11BAFu) {
        MetaCandidate mc;
        mc.entry = full;
        mc.name = bn;
        mc.handler = "il2cpp";
        mc.size = e.uncomp_size;
        mc.note = by_name ? "recognized by name and signature" : "recognized by signature";
        out.metas.push_back(mc);
      } else if (by_name) {
        MetaCandidate mc;
        mc.entry = full;
        mc.name = bn;
        mc.handler = "il2cpp";
        mc.size = e.uncomp_size;
        mc.status = "invalid";
        mc.note = "name matches global-metadata.dat but the content has no IL2CPP signature";
        out.metas.push_back(mc);
      }
    }

    // ---- nested archives ----
    if (c.nested && level == 0 && ends_with_ci(bn, ".apk")) {
      out.nested_apks.push_back(e.name);
      std::shared_ptr<ByteSource> src = z.stored_view(e);
      std::string err;
      if (!src && !e.encrypted && e.uncomp_size <= (1ull << 30) && !c.temp_dir.empty()) {
        std::string tmp = unique_path(path_join(c.temp_dir, "nested_" + sanitize_filename(bn)));
        if (z.extract_to_file(e, tmp, 1ull << 30, false, err, c.cancel)) {
          auto fs = FdSource::open_path(tmp, err);
          if (fs) {
            src = std::shared_ptr<ByteSource>(fs.release());
            if (c.temp_files) c.temp_files->push_back(tmp);
          }
        }
      }
      if (!src) {
        out.warnings.push_back("nested archive " + e.name + " was not opened" + (err.empty() ? "" : ": " + err));
        continue;
      }
      std::string zerr;
      std::shared_ptr<ZipArchive> nz(ZipArchive::open(src, zerr).release());
      if (!nz) {
        out.warnings.push_back("nested archive " + e.name + " is not a readable archive: " + zerr);
        continue;
      }
      if (c.keep) (*c.keep)[e.name] = nz;
      scan_archive(c, *nz, e.name + "!", e.name, 1);
    }
  }
  if (level == 0) {
    if (has_manifest) out.related.push_back({"manifest", "AndroidManifest.xml", "present"});
    if (dex_count) out.related.push_back({"dex", "classes*.dex", strf("%llu dex file(s)", (unsigned long long)dex_count)});
  }
}

int abi_rank(const std::vector<std::string>& pri, const std::string& abi) {
  for (size_t i = 0; i < pri.size(); i++)
    if (pri[i] == abi) return (int)i;
  return 1000;
}

}  // namespace

static ApkScan scan_zip(ZipArchive& z, const Config& cfg, Logger& log, CancelToken* cancel, const std::string& temp_dir, std::map<std::string, std::shared_ptr<ZipArchive>>* keep,
                        std::vector<std::string>* temp_files) {
  ApkScan out;
  ScanCtx c{cfg, log, cancel, temp_dir, out, keep, temp_files, {}, {}, {}, cfg.b("apk.validate_formats"), cfg.b("apk.find_companions"), cfg.b("apk.scan_nested"), false, 0};
  c.ext = split_trim(cfg.s("apk.extensions"));
  if (c.ext.empty()) c.ext.push_back(".so");
  c.inc = split_trim(cfg.s("apk.include_filter"));
  c.exc = split_trim(cfg.s("apk.exclude_filter"));
  c.all_entries_scope = cfg.s("apk.companion_scope") == "all_entries";
  scan_archive(c, z, "", "", 0);

  // Architecture filter
  for (auto& l : out.libs) {
    if (l.is_elf && l.validated) {
      std::string a = arch_name(l.arch);
      if (!cfg.flag("lib.architectures", a)) {
        l.skipped_by_arch = true;
        l.note += (l.note.empty() ? "" : "; ") + std::string("skipped by the architecture setting");
      }
    }
  }
  // ABI restriction
  if (!cfg.b("apk.scan_all_abis") && !out.libs.empty()) {
    auto pri = split_trim(cfg.s("apk.abi_priority"));
    int best = 1000;
    for (auto& l : out.libs)
      if (!l.abi.empty()) best = std::min(best, abi_rank(pri, l.abi));
    for (auto& l : out.libs)
      if (!l.abi.empty() && abi_rank(pri, l.abi) != best) {
        l.skipped_by_arch = true;
        l.note += (l.note.empty() ? "" : "; ") + std::string("other ABI (the scan is limited to the preferred ABI)");
      }
  }
  out.ok = true;
  return out;
}

// Selection rules for automatic mode. Fills rank/selected_auto.
static void auto_select(ApkScan& s, const Config& cfg) {
  std::vector<size_t> cand;
  for (size_t i = 0; i < s.libs.size(); i++) {
    const ApkLib& l = s.libs[i];
    if (l.skipped_by_arch) continue;
    if (l.validated && !l.is_elf) continue;
    if (!l.validated && !cfg.b("apk.validate_formats") && false) continue;
    cand.push_back(i);
  }
  const std::string rule = cfg.s("apk.auto_select_rule");
  auto pri = split_trim(cfg.s("apk.abi_priority"));
  auto pat = split_trim(cfg.s("apk.name_pattern"));
  auto better = [&](size_t a, size_t b) {
    const ApkLib &x = s.libs[a], &y = s.libs[b];
    if (rule == "first") return a < b;
    if (rule == "name_match") {
      bool mx = pat.empty() || matches_any_ci(x.name, pat), my = pat.empty() || matches_any_ci(y.name, pat);
      if (mx != my) return mx;
    }
    if (rule == "abi_then_largest") {
      int rx = abi_rank(pri, x.abi), ry = abi_rank(pri, y.abi);
      if (rx != ry) return rx < ry;
    }
    if (x.size != y.size) return x.size > y.size;
    return a < b;
  };
  std::stable_sort(cand.begin(), cand.end(), better);
  size_t take = (size_t)std::max<i64>(1, cfg.i("apk.auto_extract_count"));
  for (size_t r = 0; r < cand.size(); r++) {
    s.libs[cand[r]].rank = (int)r;
    s.libs[cand[r]].selected_auto = r < take;
  }
}

ApkScan inspect_apk_only(int fd, const std::string& name, const Config& cfg, Logger& log, CancelToken* cancel, std::string& err, const std::string& temp_dir) {
  ApkScan out;
  std::shared_ptr<ByteSource> src;
  if (fd < 0) {
    err = "no file";
    return out;
  }
  src = std::make_shared<FdSource>(::dup(fd), true);
  std::unique_ptr<ZipArchive> z = ZipArchive::open(src, err);
  if (!z) {
    out.error = err;
    return out;
  }
  std::map<std::string, std::shared_ptr<ZipArchive>> nested;
  std::vector<std::string> temps;
  out = scan_zip(*z, cfg, log, cancel, temp_dir, temp_dir.empty() ? nullptr : &nested, temp_dir.empty() ? nullptr : &temps);
  nested.clear();  // close the nested archives before their scratch files are removed
  for (auto& t : temps) remove_file(t);
  auto_select(out, cfg);
  (void)name;
  return out;
}

ApkLib probe_library_source(const ByteSource& src, const std::string& name) {
  ApkLib l;
  l.name = name;
  l.entry = name;
  l.size = src.size();
  u8 head[64] = {0};
  size_t n = src.read_at(0, head, sizeof head);
  l.is_elf = probe_elf(head, n, l);
  l.validated = l.is_elf;
  if (!l.is_elf) l.note = n < 20 ? "the file is too short for an ELF header" : "the file does not start with an ELF signature or has invalid class/byte-order bytes";
  if (l.is_elf) l.abi = abi_for_arch(l.arch);
  return l;
}

bool stage_apk_scan(RunContext& rc) {
  rc.log->log(LogLevel::Info, "apk", "reading archive structure");
  if (!rc.apk_src) {
    rc.error("apk", "input archive is not open");
    return false;
  }
  std::string err;
  rc.zip = ZipArchive::open(rc.apk_src, err);
  if (!rc.zip) {
    rc.apk.error = err;
    rc.apk.ok = false;
    rc.error("apk", "the input is not a readable archive: " + err);
    rc.ledger.add_gap("unavailable", "APK structure", "the input is not a readable archive: " + err);
    return false;
  }
  rc.apk = scan_zip(*rc.zip, rc.cfg, *rc.log, rc.cancel, rc.req.temp_dir, &rc.nested_zips, &rc.temp_files);
  for (auto& w : rc.apk.warnings) rc.warn("apk", w);
  if (rc.zip->recovered()) {
    rc.warn("apk", "the central directory is damaged; entries were recovered by scanning local headers");
    rc.ledger.add_gap("inferred", "archive entries", "recovered by scanning local file headers (the central directory is damaged)");
    stage_partial("central directory damaged; entries recovered by scan");
  }
  auto_select(rc.apk, rc.cfg);
  size_t elf_count = 0;
  for (auto& l : rc.apk.libs)
    if (l.is_elf) elf_count++;
  rc.ledger.add_counter("apk.entries", rc.apk.entries);
  rc.ledger.add_counter("apk.libs", rc.apk.libs.size());
  rc.log->log(LogLevel::Ok, "apk",
              strf("%llu entries, %zu library candidates (%zu ELF), %zu metadata candidates, %zu nested archives", (unsigned long long)rc.apk.entries, rc.apk.libs.size(), elf_count,
                   rc.apk.metas.size(), rc.apk.nested_apks.size()));
  if (rc.apk.libs.empty()) {
    rc.ledger.add_gap("unavailable", "native libraries", "the archive contains no files matching the library extensions");
    rc.log->log(LogLevel::Warning, "apk", "no native libraries found; the run continues with archive structure and metadata only");
  }
  return true;
}

// Extracts one selected library; creates its LibContext.
static bool extract_one(RunContext& rc, const ApkLib& al, int index) {
  const Config& cfg = rc.cfg;
  auto lc = std::make_unique<LibContext>();
  lc->index = index;
  lc->from_apk = true;
  lc->entry_name = al.entry;
  lc->abi_dir = al.abi;
  lc->display = al.abi.empty() ? al.name : al.abi + "/" + al.name;
  lc->id = sanitize_filename((al.abi.empty() ? "" : al.abi + "_") + al.name);
  for (auto& o : rc.libs)
    if (o->id == lc->id) lc->id += "_" + std::to_string(index);
  lc->ledger = &rc.ledger;
  lc->reports_dir = path_join(rc.reports_root, lc->id);
  lc->rel_reports = path_join("reports", lc->id);

  // Locate the archive and the entry (outer or nested).
  ZipArchive* z = rc.zip.get();
  std::string entry = al.entry;
  if (!al.nested.empty()) {
    auto it = rc.nested_zips.find(al.nested);
    if (it == rc.nested_zips.end()) {
      rc.error("extract", "nested archive " + al.nested + " is not available");
      return false;
    }
    z = it->second.get();
    entry = al.entry.substr(al.nested.size() + 1);
  }
  const ZipEntry* e = z->find(entry);
  if (!e) {
    rc.error("extract", "entry " + al.entry + " not found in the archive");
    rc.ledger.add_gap("unavailable", "library " + al.entry, "entry not found", index);
    return false;
  }
  const bool keep = cfg.b("apk.extract_libraries");
  std::string dst;
  if (keep) {
    std::string dir = cfg.s("apk.library_layout") == "flat" || al.abi.empty() ? rc.libs_dir : path_join(rc.libs_dir, sanitize_filename(al.abi));
    mkdirs(dir);
    std::string fn = cfg.s("apk.library_layout") == "flat" && !al.abi.empty() ? sanitize_filename(al.abi + "_" + al.name) : sanitize_filename(al.name);
    dst = unique_path(path_join(dir, fn));
  } else {
    dst = unique_path(path_join(rc.req.temp_dir, "lib_" + lc->id));
    rc.temp_files.push_back(dst);
  }
  const u64 max_extract = cfg.limit("limits.max_extract_mb") * 1048576ull;
  std::string err;
  u64 written = 0;
  ExtractNote note;
  rc.log->log(LogLevel::Info, "extract", strf("extracting %s (%s)", al.entry.c_str(), human_size(e->uncomp_size).c_str()));
  rc.prog("extract", 0, e->uncomp_size, "extracting " + al.name);
  if (!z->extract_to_file(*e, dst, max_extract, cfg.b("general.verify_input"), err, rc.cancel, &written, &note)) {
    if (rc.cancel->cancelled()) return false;
    rc.error("extract", al.entry + ": " + err);
    rc.ledger.add_gap("unavailable", "library " + al.entry, "extraction failed: " + err, index);
    FileRec fr;
    fr.name = al.name;
    fr.rel_path = dst.size() > rc.run_dir.size() ? dst.substr(rc.run_dir.size() + 1) : dst;
    fr.ok = false;
    fr.error = err;
    fr.lib = index;
    if (keep) rc.ledger.add_file(fr);
    remove_file(dst);
    return false;
  }
  if (note.damaged) {
    rc.warn("extract", al.entry + ": the archive entry is damaged (" + note.text + "); the bytes that could be read were kept");
    rc.ledger.add_gap("partial", "library " + al.entry, "archive entry damaged: " + note.text + "; analysis uses the bytes that could be read", index);
    stage_partial(al.entry + ": archive entry damaged");
  }
  lc->local_path = dst;
  lc->extracted_ok = true;
  auto fs = FdSource::open_path(dst, err);
  if (!fs) {
    rc.error("extract", "cannot reopen " + dst + ": " + err);
    return false;
  }
  lc->src = std::shared_ptr<ByteSource>(fs.release());
  lc->size = lc->src->size();
  if (keep) {
    FileRec fr;
    fr.name = al.name;
    fr.rel_path = dst.size() > rc.run_dir.size() ? dst.substr(rc.run_dir.size() + 1) : dst;
    fr.bytes = lc->size;
    fr.lib = index;
    rc.ledger.add_file(fr);
  }
  rc.libs.push_back(std::move(lc));
  return true;
}

bool stage_select_extract(RunContext& rc) {
  const Config& cfg = rc.cfg;
  std::vector<size_t> chosen;
  if (!rc.req.selected_libs.empty()) {
    for (auto& name : rc.req.selected_libs) {
      bool found = false;
      for (size_t i = 0; i < rc.apk.libs.size(); i++)
        if (rc.apk.libs[i].entry == name) {
          chosen.push_back(i);
          found = true;
          break;
        }
      if (!found) {
        rc.warn("extract", "selected library " + name + " is not in the archive");
        rc.ledger.add_gap("unavailable", "library " + name, "selected library was not found in the archive");
      }
    }
  } else if (cfg.b("general.auto_select")) {
    for (size_t i = 0; i < rc.apk.libs.size(); i++)
      if (rc.apk.libs[i].selected_auto) chosen.push_back(i);
    std::sort(chosen.begin(), chosen.end(), [&](size_t a, size_t b) { return rc.apk.libs[a].rank < rc.apk.libs[b].rank; });
  } else if (!rc.apk.libs.empty()) {
    rc.log->log(LogLevel::Info, "extract", "automatic selection is off and no library was chosen: no library is analyzed");
    rc.ledger.add_gap("skipped", "library analysis", "automatic selection is off and no library was selected");
  }
  if (chosen.empty()) {
    if (!rc.apk.libs.empty() && rc.req.selected_libs.empty() && cfg.b("general.auto_select"))
      rc.ledger.add_gap("unavailable", "library analysis", "no library passed the selection rules (architecture, ELF validation)");
    return true;
  }
  size_t ok = 0;
  int index = 0;
  for (size_t i : chosen) {
    if (rc.cancel->cancelled()) return false;
    if (extract_one(rc, rc.apk.libs[i], index)) {
      index++;
      ok++;
    }
  }
  rc.ledger.add_counter("libs.extracted", ok);
  if (ok < chosen.size()) {
    stage_partial(strf("%zu of %zu libraries were not extracted", chosen.size() - ok, chosen.size()));
  }
  rc.log->log(ok ? LogLevel::Ok : LogLevel::Warning, "extract", strf("%zu of %zu libraries extracted", ok, chosen.size()));
  return ok > 0 || chosen.empty();
}

bool hash_source(const ByteSource& src, bool want_sha, bool want_crc, const CancelToken* cancel, std::string& sha_hex, std::string& crc_hex) {
  Sha256 sh;
  u32 crc = 0;
  std::vector<u8> buf(1u << 20);
  u64 off = 0;
  const u64 size = src.size();
  while (off < size) {
    if (cancel && cancel->cancelled()) return false;
    size_t n = src.read_at(off, buf.data(), (size_t)std::min<u64>(buf.size(), size - off));
    if (n == 0) return false;
    if (want_sha) sh.update(buf.data(), n);
    if (want_crc) crc = crc32_update(crc, buf.data(), n);
    off += n;
  }
  if (want_sha) sha_hex = sh.finish_hex();
  if (want_crc) crc_hex = strf("%08x", crc);
  return true;
}

bool stage_lib_input(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  if (!lc.src) {
    rc.error("input", "the library file is not open");
    return false;
  }
  lc.size = lc.src->size();
  if (lc.size == 0) rc.warn("input", "the library file is empty");
  if (cfg.b("general.verify_input") && lc.size) {
    const bool sha = cfg.flag("expert.input_hashes", "sha256"), crc = cfg.flag("expert.input_hashes", "crc32");
    if (sha || crc) {
      if (!hash_source(*lc.src, sha, crc, rc.cancel, lc.sha256, lc.crc32_hex)) {
        if (rc.cancel->cancelled()) return false;
        rc.warn("input", "checksums of " + lc.display + " could not be computed (read error)");
        stage_partial("checksums unavailable");
      }
    }
  }
  return true;
}

}  // namespace kratos
