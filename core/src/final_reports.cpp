// Run-level results: status, summary.json, dump.txt and completeness.txt.
#include <capstone/capstone.h>
#include <elfio/elfio_version.hpp>
#include <zlib.h>
#include <zstd.h>

#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

const char* stage_status_ru(StageStatus s) {
  switch (s) {
    case StageStatus::Ok: return "выполнен";
    case StageStatus::Partial: return "выполнен частично";
    case StageStatus::Failed: return "ошибка";
    case StageStatus::Skipped: return "пропущен";
    case StageStatus::Disabled: return "отключён";
    case StageStatus::Cancelled: return "отменён";
  }
  return "?";
}

const char* strength_ru(const std::string& s) {
  if (s == "strong") return "сильный";
  if (s == "moderate") return "умеренный";
  return "слабый";
}

const char* kind_ru(const std::string& k) {
  if (k == "unavailable") return "недоступно";
  if (k == "skipped") return "пропущено";
  if (k == "inferred") return "выведено по косвенным данным";
  if (k == "partial") return "получено частично";
  return k.c_str();
}

// Pads to a number of characters (not bytes), so Cyrillic text keeps its columns.
std::string pad_right(const std::string& s, size_t width) {
  size_t chars = 0;
  for (unsigned char c : s)
    if ((c & 0xC0) != 0x80) chars++;
  return chars >= width ? s : s + std::string(width - chars, ' ');
}

int detail_rank(const Config& c) {
  std::string d = c.s("general.detail_level");
  return d == "brief" ? 0 : d == "normal" ? 1 : d == "detailed" ? 2 : 3;
}

std::string lib_label(const RunContext& rc, int idx) {
  if (idx < 0) return "";
  if ((size_t)idx < rc.libs.size()) return rc.libs[(size_t)idx]->display;
  return "библиотека " + std::to_string(idx);
}

std::string mode_text(const RunContext& rc) { return rc.req.mode == "apk" ? "анализ APK" : "анализ отдельной библиотеки"; }

std::string profile_title(const std::string& id) {
  const ProfileDef* p = find_profile(id);
  return p ? p->title : id;
}

constexpr u32 kConfirmedMask = FS_SYMTAB | FS_DYNSYM | FS_INIT | FS_ENTRY | FS_UNWIND | FS_PLT;

struct FuncStats {
  u64 total = 0, high = 0, medium = 0, low = 0, generated = 0, size_estimated = 0, confirmed = 0, inferred = 0, thumb = 0;
  std::map<std::string, u64> by_source;
};

FuncStats func_stats(const FunctionsResult& fr) {
  FuncStats s;
  static const std::pair<u32, const char*> srcs[] = {{FS_SYMTAB, "symtab"}, {FS_DYNSYM, "dynsym"}, {FS_INIT, "init_fini"},   {FS_ENTRY, "entry"},
                                                     {FS_UNWIND, "unwind"}, {FS_PLT, "plt"},       {FS_CALL, "call_targets"}, {FS_PROLOGUE, "prologue"},
                                                     {FS_PTRTAB, "pointer_table"}};
  for (auto& f : fr.list) {
    s.total++;
    (f.conf >= 2 ? s.high : f.conf == 1 ? s.medium : s.low)++;
    if (f.generated) s.generated++;
    if (f.size_est) s.size_estimated++;
    if (f.thumb) s.thumb++;
    ((f.sources & kConfirmedMask) ? s.confirmed : s.inferred)++;
    for (auto& p : srcs)
      if (f.sources & p.first) s.by_source[p.second]++;
  }
  return s;
}

struct XrefStats {
  u64 total = 0, confirmed = 0, heuristic = 0;
  std::map<std::string, u64> by_type;
};

XrefStats xref_stats(const CodeScanResult& sr) {
  XrefStats x;
  for (auto& r : sr.xrefs) {
    x.total++;
    (r.confirmed ? x.confirmed : x.heuristic)++;
    x.by_type[xref_type_name(r.type)]++;
  }
  return x;
}

Json map_json(const std::map<std::string, u64>& m) {
  Json j = Json::object();
  for (auto& kv : m) j.set(kv.first, kv.second);
  return j;
}

Json lib_json(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  Json j = Json::object();
  j.set("index", lc.index);
  j.set("id", lc.id);
  j.set("entry", lc.entry_name);
  j.set("display", lc.display);
  j.set("abi_dir", lc.abi_dir);
  j.set("from_apk", lc.from_apk);
  j.set("size", lc.size);
  if (!lc.sha256.empty()) j.set("sha256", lc.sha256);
  if (!lc.crc32_hex.empty()) j.set("crc32", lc.crc32_hex);
  j.set("reports_dir", lc.rel_reports);
  j.set("large_file_mode", lc.large_file);
  const ElfModel& m = lc.elf;
  Json e = Json::object();
  e.set("parsed", lc.elf_ok);
  if (lc.elf_ok) {
    e.set("architecture", arch_name(lc.arch));
    e.set("machine", machine_name(m.machine));
    e.set("bits", m.is64 ? 64 : 32);
    e.set("little_endian", m.le);
    e.set("type", elf_type_name(m.type));
    e.set("entry", hex_prefixed(m.entry));
    e.set("soname", m.soname);
    Json need = Json::array();
    for (auto& n : m.needed) need.push(Json(n));
    e.set("needed", need);
    e.set("build_id", m.build_id);
    e.set("segments", (u64)m.segs.size());
    e.set("sections", (u64)m.secs.size());
    e.set("sections_reconstructed", m.secs_reconstructed);
    e.set("program_headers_assumed", m.phdr_assumed);
    e.set("dynamic_from_segment", m.dyn_from_segment);
    e.set("dynsym_parsed", (u64)m.dynsym.size());
    e.set("dynsym_declared", m.dynsym_declared);
    e.set("symtab_parsed", (u64)m.symtab.size());
    e.set("symtab_declared", m.symtab_declared);
    e.set("symbols_partial", m.symbols_partial);
    e.set("relocations", (u64)m.relocs.size());
    e.set("relocations_partial", m.relocs_partial);
    e.set("anomalies", (u64)m.anomalies.size());
    if (cfg.b("lib.diagnostics") || cfg.b("expert.diagnostics")) {
      Json an = Json::array();
      size_t n = 0;
      for (auto& a : m.anomalies) {
        if (n++ >= 500) break;
        Json o = Json::object();
        o.set("offset", a.offset);
        o.set("where", a.where);
        o.set("text", a.text);
        an.push(o);
      }
      e.set("anomaly_list", an);
    }
  }
  j.set("elf", e);
  Json pr = Json::object();
  pr.set("ran", lc.prot.ran);
  Json ind = Json::array();
  for (auto& i : lc.prot.indicators) {
    Json o = Json::object();
    o.set("id", i.id);
    o.set("title", i.title);
    o.set("detail", i.detail);
    o.set("strength", i.strength);
    ind.push(o);
  }
  pr.set("indicators", ind);
  pr.set("file_entropy", lc.prot.file_entropy);
  pr.set("trailing_bytes", lc.prot.trailing_bytes);
  Json rel = Json::array();
  for (auto& r : lc.prot.related) {
    Json o = Json::object();
    o.set("kind", r.kind);
    o.set("where", r.where);
    o.set("detail", r.detail);
    rel.push(o);
  }
  pr.set("related", rel);
  j.set("protection", pr);
  Json st = Json::object();
  st.set("ran", lc.strings.ran);
  st.set("found", lc.strings.total_found);
  st.set("written", lc.strings.written);
  st.set("filtered_out", lc.strings.filtered_out);
  st.set("truncated", lc.strings.truncated);
  st.set("by_encoding", [&] {
    Json o = Json::object();
    o.set("ascii", lc.strings.by_enc[0]);
    o.set("utf8", lc.strings.by_enc[1]);
    o.set("utf16le", lc.strings.by_enc[2]);
    o.set("utf16be", lc.strings.by_enc[3]);
    return o;
  }());
  j.set("strings", st);
  FuncStats fs = func_stats(lc.funcs);
  Json fn = Json::object();
  fn.set("ran", lc.funcs.ran);
  fn.set("total", fs.total);
  fn.set("confidence", [&] {
    Json o = Json::object();
    o.set("high", fs.high);
    o.set("medium", fs.medium);
    o.set("low", fs.low);
    return o;
  }());
  fn.set("confirmed_by_structure", fs.confirmed);
  fn.set("inferred_by_code_analysis", fs.inferred);
  fn.set("generated_names", fs.generated);
  fn.set("size_estimated", fs.size_estimated);
  fn.set("thumb", fs.thumb);
  fn.set("by_source", map_json(fs.by_source));
  fn.set("methods", (u64)lc.funcs.methods.size());
  fn.set("plt_stubs", (u64)lc.funcs.plt.size());
  fn.set("pointer_tables", (u64)lc.funcs.tables.size());
  j.set("functions", fn);
  XrefStats xs = xref_stats(lc.scan);
  Json cs = Json::object();
  cs.set("ran", lc.scan.ran);
  cs.set("instructions", lc.scan.insns);
  cs.set("bytes_total", lc.scan.bytes_total);
  cs.set("bytes_decoded", lc.scan.bytes_decoded);
  cs.set("bytes_data", lc.scan.bytes_data);
  cs.set("undecodable_runs", lc.scan.undecodable);
  cs.set("regions", lc.scan.regions);
  cs.set("note", lc.scan.arch_note);
  j.set("code_scan", cs);
  Json xr = Json::object();
  xr.set("total", xs.total);
  xr.set("confirmed", xs.confirmed);
  xr.set("heuristic", xs.heuristic);
  xr.set("by_type", map_json(xs.by_type));
  xr.set("partial", lc.scan.xref_partial);
  j.set("xrefs", xr);
  if (lc.elfio.ran) {
    Json o = Json::object();
    o.set("loaded", lc.elfio.loaded);
    o.set("sections", lc.elfio.sections);
    o.set("segments", lc.elfio.segments);
    o.set("symbols", lc.elfio.symbols);
    Json d = Json::array();
    for (auto& x : lc.elfio.diffs) d.push(Json(x));
    o.set("discrepancies", d);
    j.set("elfio_cross_check", o);
  }
  if (lc.dyn.ran) {
    Json o = Json::object();
    o.set("available", lc.dyn.available);
    o.set("reason", lc.dyn.reason);
    if (lc.dyn.available) {
      o.set("base", hex_prefixed(lc.dyn.base));
      o.set("bias", hex_prefixed(lc.dyn.bias));
    }
    j.set("dynamic", o);
  }
  Json comp = Json::array();
  for (auto& c : lc.companions) comp.push(Json(c));
  j.set("companions", comp);
  return j;
}

}  // namespace

// ------------------------------------------------------------------ status
StatusInfo compute_status(RunContext& rc) {
  StatusInfo st;
  bool cancelled = false;
  for (auto& s : rc.ledger.stages()) {
    if (s.status == StageStatus::Cancelled) cancelled = true;
    if (s.status != StageStatus::Failed) continue;
    std::string txt = s.title;
    std::string lib = lib_label(rc, s.lib);
    if (!lib.empty()) txt += " [" + lib + "]";
    if (!s.reason.empty()) txt += ": " + s.reason;
    (s.mandatory ? st.mandatory_failed : st.optional_failed).push_back(txt);
  }
  for (auto& f : rc.ledger.files()) {
    if (f.ok) continue;
    std::string txt = "файл " + f.name;
    std::string lib = lib_label(rc, f.lib);
    if (!lib.empty()) txt += " [" + lib + "]";
    if (!f.error.empty()) txt += ": " + f.error;
    (f.mandatory ? st.mandatory_failed : st.optional_failed).push_back(txt);
  }
  if (rc.cfg.b("meta.require") && !rc.meta.found && !cancelled) st.mandatory_failed.push_back("метаданные обязательны, но не найдены");
  if (cancelled) {
    st.id = "cancelled";
    st.text = "Отменено пользователем";
  } else if (!st.mandatory_failed.empty() || !st.optional_failed.empty()) {
    st.id = "error";
    st.text = "Завершено с ошибкой";
  } else {
    st.id = "success";
    st.text = "Успешно завершено";
  }
  return st;
}

// ------------------------------------------------------------------ summary.json
Json build_summary(RunContext& rc, const StatusInfo& st) {
  const Config& cfg = rc.cfg;
  const bool repro = rc.reproducible();
  Json j = Json::object();
  Json tool = Json::object();
  tool.set("name", "KRATOS DUMP");
  tool.set("version", KRATOS_VERSION);
  j.set("tool", tool);
  Json status = Json::object();
  status.set("id", st.id);
  status.set("text", st.text);
  Json mf = Json::array(), of = Json::array();
  for (auto& s : st.mandatory_failed) mf.push(Json(s));
  for (auto& s : st.optional_failed) of.push(Json(s));
  status.set("mandatory_failures", mf);
  status.set("optional_failures", of);
  j.set("status", status);

  Json run = Json::object();
  run.set("name", rc.run_name);
  run.set("mode", rc.req.mode);
  run.set("profile", rc.req.profile_id);
  run.set("profile_title", profile_title(rc.req.profile_id));
  if (!repro) {
    run.set("started", iso_time_utc(rc.started_ms));
    run.set("duration_ms", now_ms() - rc.started_ms);
    run.set("directory", rc.run_dir);
  }
  Json over = Json::array();
  for (auto& k : cfg.diff_from(rc.req.profile_id)) over.push(Json(k));
  run.set("settings_changed_from_profile", over);
  j.set("run", run);

  Json in = Json::object();
  in.set("name", rc.req.display_name);
  in.set("size", rc.input_size);
  if (!rc.input_sha256.empty()) in.set("sha256", rc.input_sha256);
  if (!rc.input_crc32.empty()) in.set("crc32", rc.input_crc32);
  j.set("input", in);

  if (rc.req.mode == "apk") {
    Json a = Json::object();
    a.set("readable", rc.apk.ok || rc.zip != nullptr);
    a.set("error", rc.apk.error);
    a.set("entries", rc.apk.entries);
    a.set("directories", rc.apk.dirs);
    a.set("uncompressed_bytes", rc.apk.total_uncompressed);
    a.set("compressed_bytes", rc.apk.total_compressed);
    a.set("central_directory_recovered", rc.apk.recovered);
    a.set("zip64", rc.apk.zip64);
    if (cfg.b("apk.report_structure")) {
      Json td = Json::object();
      for (auto& kv : rc.apk.top_dirs) {
        Json o = Json::object();
        o.set("entries", kv.second.first);
        o.set("bytes", kv.second.second);
        td.set(kv.first, o);
      }
      a.set("top_directories", td);
      a.set("compression_methods", map_json(rc.apk.methods));
      Json abis = Json::array();
      for (auto& x : rc.apk.abis) abis.push(Json(x));
      a.set("abis", abis);
    }
    Json cand = Json::array();
    for (auto& l : rc.apk.libs) {
      Json o = Json::object();
      o.set("entry", l.entry);
      o.set("abi", l.abi);
      o.set("size", l.size);
      o.set("is_elf", l.is_elf);
      o.set("architecture", arch_name(l.arch));
      o.set("selected_automatically", l.selected_auto);
      o.set("skipped_by_architecture_setting", l.skipped_by_arch);
      o.set("note", l.note);
      cand.push(o);
    }
    a.set("library_candidates", cand);
    Json na = Json::array();
    for (auto& n : rc.apk.nested_apks) na.push(Json(n));
    a.set("nested_archives", na);
    Json rel = Json::array();
    for (auto& r : rc.apk.related) {
      Json o = Json::object();
      o.set("kind", r.kind);
      o.set("where", r.where);
      o.set("detail", r.detail);
      rel.push(o);
    }
    a.set("related", rel);
    j.set("apk", a);
  }

  Json md = Json::object();
  md.set("probed", rc.meta.probed);
  md.set("found", rc.meta.found);
  md.set("handler", rc.meta.handler);
  md.set("name", rc.meta.name);
  md.set("source", rc.meta.source);
  md.set("status", rc.meta.status);
  md.set("size", rc.meta.size);
  md.set("file", rc.meta.rel_path);
  md.set("info", rc.meta.info);
  Json cands = Json::array();
  for (auto& c : rc.apk.metas) {
    Json o = Json::object();
    o.set("entry", c.entry);
    o.set("handler", c.handler);
    o.set("size", c.size);
    o.set("status", c.status);
    o.set("note", c.note);
    cands.push(o);
  }
  md.set("candidates", cands);
  Json notes = Json::array();
  for (auto& n : rc.meta.notes) notes.push(Json(n));
  md.set("notes", notes);
  j.set("metadata", md);

  Json libs = Json::array();
  for (auto& l : rc.libs) libs.push(lib_json(rc, *l));
  j.set("libraries", libs);

  // ---- stages ----
  auto stages = rc.ledger.stages();
  std::stable_sort(stages.begin(), stages.end(), [](const StageRec& a, const StageRec& b) { return a.order < b.order; });
  Json sj = Json::array();
  std::map<std::string, u64> stage_counts;
  for (auto& s : stages) {
    Json o = Json::object();
    o.set("id", s.id);
    o.set("title", s.title);
    o.set("library", s.lib >= 0 ? Json(lib_label(rc, s.lib)) : Json());
    o.set("status", to_string(s.status));
    o.set("mandatory", s.mandatory);
    if (!repro) o.set("ms", s.ms);
    o.set("reason", s.reason);
    Json nn = Json::array();
    for (auto& n : s.notes) nn.push(Json(n));
    o.set("notes", nn);
    sj.push(o);
    stage_counts[to_string(s.status)]++;
  }
  j.set("stages", sj);

  // ---- files ----
  auto files = rc.ledger.files();
  Json fj = Json::array();
  u64 created = 0, truncated = 0, failed = 0;
  for (auto& f : files) {
    Json o = Json::object();
    o.set("name", f.name);
    o.set("path", f.rel_path);
    o.set("library", f.lib >= 0 ? Json(lib_label(rc, f.lib)) : Json());
    o.set("ok", f.ok);
    o.set("bytes", f.bytes);
    o.set("lines", f.lines);
    o.set("objects", f.objects);
    o.set("truncated_by_limit", f.truncated);
    if (f.truncated) o.set("truncation_reason", f.trunc_reason);
    if (!f.ok) o.set("error", f.error);
    fj.push(o);
    if (f.ok) created++;
    else failed++;
    if (f.truncated) truncated++;
  }
  j.set("files", fj);

  // ---- completeness (counts only; no single percentage) ----
  Json comp = Json::object();
  comp.set("stages", map_json(stage_counts));
  Json fc = Json::object();
  fc.set("created", created);
  fc.set("cut_by_limit", truncated);
  fc.set("failed", failed);
  comp.set("files", fc);
  auto gaps = rc.ledger.gaps();
  std::map<std::string, u64> gap_counts;
  Json gj = Json::array();
  for (auto& g : gaps) {
    Json o = Json::object();
    o.set("kind", g.kind);
    o.set("what", g.what);
    o.set("why", g.why);
    o.set("library", g.lib >= 0 ? Json(lib_label(rc, g.lib)) : Json());
    gj.push(o);
    gap_counts[g.kind]++;
  }
  comp.set("gap_counts", map_json(gap_counts));
  comp.set("gaps", gj);
  comp.set("counters", map_json(rc.ledger.counters()));
  Json defs = Json::object();
  defs.set("confirmed", "read directly from the file structure: symbol tables, unwind tables, init/fini arrays, entry point, PLT/relocations");
  defs.set("inferred", "derived by code analysis: call targets, function prologues, pointer tables; marked with lower confidence");
  defs.set("generated_name", "a function without a symbol name receives a name like sub_001234; it is not a recovered original name");
  defs.set("estimated_size", "function size derived from the next function or unwind data, not from a symbol; marked with ~ in reports");
  comp.set("definitions", defs);
  j.set("completeness", comp);

  Json w = Json::array(), er = Json::array();
  {
    std::lock_guard<std::mutex> g(rc.mu);
    for (auto& s : rc.warnings) w.push(Json(s));
    for (auto& s : rc.errors) er.push(Json(s));
  }
  j.set("warnings", w);
  j.set("errors", er);

  if (cfg.b("expert.engine_info")) {
    Json d = Json::object();
    int maj = 0, min = 0;
    cs_version(&maj, &min);
    bool cap_used = false, elfio_used = false;
    for (auto& l : rc.libs) {
      if (l->scan.ran && l->scan.insns) cap_used = true;
      if (l->elfio.ran) elfio_used = true;
    }
    auto dep = [&](const char* name, const std::string& ver, bool used, const char* role) {
      Json o = Json::object();
      o.set("version", ver);
      o.set("used_in_this_run", used);
      o.set("role", role);
      d.set(name, o);
    };
    auto m = rc.apk.methods;
    dep("capstone", strf("%d.%d", maj, min), cap_used, "disassembly (ARM, ARM64, x86, x86-64)");
    dep("zlib", zlibVersion(), m.count("deflate") > 0, "deflate archive entries and zlib-compressed ELF sections");
    dep("zstd", ZSTD_versionString(), m.count("zstd") > 0, "Zstandard archive entries and compressed ELF sections");
    dep("elfio", ELFIO_VERSION, elfio_used, "independent ELF cross-check");
    j.set("dependencies", d);
  }
  return j;
}

// ------------------------------------------------------------------ dump.txt
bool stage_report_dump(RunContext& rc) {
  if (!report_wanted(rc, "out.dump")) return true;
  const Config& cfg = rc.cfg;
  const int det = detail_rank(cfg);
  const bool repro = rc.reproducible();
  ReportFile rf(rc, -1, "dump.txt", rc.reports_root, "reports", 0);
  if (!rf.ok()) {
    report_failed(rc, -1, "dump.txt", rf.create_error(), true);
    stage_partial("dump.txt could not be created");
    return false;
  }
  rf.header("общий отчёт", nullptr);
  OutFile& f = rf.f();
  StatusInfo st = compute_status(rc);
  auto H = [&](const std::string& t) {
    f.line("");
    f.line(t);
    f.line(std::string(t.size() > 70 ? 70 : t.size(), '-'));
  };

  f.line("Статус: " + st.text);
  f.line("Режим: " + mode_text(rc));
  f.line("Профиль: " + profile_title(rc.req.profile_id));
  if (!repro) {
    f.line("Начало: " + iso_time_utc(rc.started_ms));
    f.line(strf("Длительность: %.1f с", (double)(now_ms() - rc.started_ms) / 1000.0));
  }
  for (auto& s : st.mandatory_failed) f.line("ОШИБКА (обязательный этап): " + s);
  for (auto& s : st.optional_failed) f.line("Ошибка (необязательный этап): " + s);

  H("Входные данные");
  f.line("Имя: " + rc.req.display_name);
  f.line(strf("Размер: %llu байт (%s)", (unsigned long long)rc.input_size, human_size(rc.input_size).c_str()));
  if (!rc.input_sha256.empty()) f.line("SHA-256: " + rc.input_sha256);
  if (!rc.input_crc32.empty()) f.line("CRC32: " + rc.input_crc32);

  if (rc.req.mode == "apk") {
    H("Структура APK");
    if (!rc.zip) {
      f.line("Архив не удалось прочитать: " + rc.apk.error);
    } else {
      f.line(strf("Записей: %llu, каталогов: %llu", (unsigned long long)rc.apk.entries, (unsigned long long)rc.apk.dirs));
      f.line(strf("Размер данных: %s (распакованные), %s (в архиве)", human_size(rc.apk.total_uncompressed).c_str(), human_size(rc.apk.total_compressed).c_str()));
      if (rc.apk.zip64) f.line("Формат: ZIP64");
      if (rc.apk.recovered) f.line("ВНИМАНИЕ: центральный каталог повреждён; записи восстановлены по локальным заголовкам");
      for (auto& w : rc.apk.warnings) f.line("Предупреждение архива: " + w);
      if (cfg.b("apk.report_structure")) {
        f.line("Верхние каталоги:");
        for (auto& kv : rc.apk.top_dirs) f.line(strf("  %-20s записей: %-8llu размер: %s", kv.first.c_str(), (unsigned long long)kv.second.first, human_size(kv.second.second).c_str()));
        std::string ms;
        for (auto& kv : rc.apk.methods) ms += (ms.empty() ? "" : ", ") + kv.first + "=" + std::to_string(kv.second);
        f.line("Методы сжатия: " + ms);
        f.line("ABI в lib/: " + (rc.apk.abis.empty() ? std::string("нет") : join(rc.apk.abis, ", ")));
      }
      for (auto& r : rc.apk.related) f.line("Содержимое: " + r.where + " — " + r.detail);
      if (!rc.apk.nested_apks.empty()) f.line("Вложенные архивы: " + join(rc.apk.nested_apks, ", "));
      f.line("");
      f.line(strf("Кандидаты в библиотеки: %zu", rc.apk.libs.size()));
      for (auto& l : rc.apk.libs) {
        std::string tag = l.selected_auto ? "выбрана автоматически" : (l.skipped_by_arch ? "пропущена по настройке архитектур" : "");
        f.line(strf("  %-52s %-10s %s %s%s%s", l.entry.c_str(), human_size(l.size).c_str(), l.is_elf ? arch_name(l.arch) : "не ELF", tag.c_str(), l.note.empty() ? "" : "  // ",
                    l.note.c_str()));
      }
    }
  }

  H("Метаданные");
  if (!rc.meta.probed) f.line("Метаданные не анализировались: этап отключён или файл метаданных не указан (см. список этапов).");
  else if (!rc.meta.found) f.line("Метаданные не найдены и не выбраны.");
  else {
    f.line("Файл: " + rc.meta.name + (rc.meta.rel_path.empty() ? "" : "  (" + rc.meta.rel_path + ")"));
    f.line("Обработчик: " + rc.meta.handler + "; источник: " + rc.meta.source);
    f.line("Состояние: " + rc.meta.status);
    const Json* v = rc.meta.info.find("version");
    if (v) f.line(strf("Версия метаданных: %lld", (long long)v->as_int()));
    const Json* sl = rc.meta.info.find("string_literals");
    if (sl && sl->find("count")) f.line(strf("Строковых литералов: %lld", (long long)sl->find("count")->as_int()));
    const Json* idn = rc.meta.info.find("identifiers");
    if (idn && idn->find("count")) f.line(strf("Идентификаторов: %lld", (long long)idn->find("count")->as_int()));
    for (auto& n : rc.meta.notes) f.line("  - " + n);
    f.line("Подробности: reports/metadata_report.txt (если включён)");
  }

  for (auto& lp : rc.libs) {
    LibContext& lc = *lp;
    const ElfModel& m = lc.elf;
    H("Библиотека: " + lc.display);
    f.line("Идентификатор: " + lc.id);
    f.line(strf("Размер: %llu байт (%s)", (unsigned long long)lc.size, human_size(lc.size).c_str()));
    if (!lc.sha256.empty()) f.line("SHA-256: " + lc.sha256);
    if (!lc.crc32_hex.empty()) f.line("CRC32: " + lc.crc32_hex);
    if (lc.large_file) f.line("Режим большого файла: только потоковая обработка");
    if (!lc.elf_ok) {
      f.line("ELF не распознан: структура, символы и код недоступны.");
      if (!m.anomalies.empty()) f.line("Причина: " + m.anomalies[0].text);
    } else {
      f.line(strf("Архитектура: %s; %d бит; %s", arch_label(lc.arch), m.is64 ? 64 : 32, m.le ? "little-endian" : "big-endian"));
      f.line(strf("Тип ELF: %s; машина: %s; точка входа: 0x%llx", elf_type_name(m.type), machine_name(m.machine), (unsigned long long)m.entry));
      if (!m.soname.empty()) f.line("SONAME: " + m.soname);
      if (!m.build_id.empty()) f.line("Build-ID: " + m.build_id);
      if (!m.needed.empty()) f.line("Зависимости (DT_NEEDED): " + join(m.needed, ", "));
      if (!m.runpath.empty()) f.line("RUNPATH: " + m.runpath);
      f.line(strf("Сегменты: %zu%s", m.segs.size(), m.phdr_assumed ? " (таблица найдена по стандартному положению: заголовок повреждён)" : ""));
      f.line(strf("Секции: %zu%s", m.secs.size(), m.secs_reconstructed ? " (восстановлены по сегментам, имена и границы приблизительные)" : (m.secs_ok ? "" : " (таблица недоступна)")));
      f.line(strf("Динамическая таблица: %s", m.dyn_ok ? (m.dyn_from_segment ? "прочитана через PT_DYNAMIC" : "прочитана") : "недоступна"));
      f.line(strf("Символы .dynsym: разобрано %zu из заявленных %llu%s", m.dynsym.size(), (unsigned long long)m.dynsym_declared, m.symbols_partial ? " (неполно)" : ""));
      f.line(strf("Символы .symtab: разобрано %zu из заявленных %llu", m.symtab.size(), (unsigned long long)m.symtab_declared));
      if (m.reparsed_extra_symbols) f.line(strf("Дополнительно восстановлено символов по релокациям: %llu", (unsigned long long)m.reparsed_extra_symbols));
      f.line(strf("Релокации: %zu%s", m.relocs.size(), m.relocs_partial ? " (неполно)" : ""));
      f.line(strf("Отклонений от формата ELF: %zu", m.anomalies.size()));
      if (cfg.b("lib.diagnostics") || det >= 2) {
        size_t n = 0;
        for (auto& a : m.anomalies) {
          if (n++ >= 200) {
            f.line("  ... (остальные в summary.json и журнале)");
            break;
          }
          f.line(strf("  [0x%llx] %s: %s", (unsigned long long)a.offset, a.where.c_str(), a.text.c_str()));
        }
      }
    }
    if (lc.prot.ran) {
      f.line("");
      f.line("Признаки защиты и преобразования (это предположения по измерениям, не доказательства):");
      if (lc.prot.indicators.empty()) f.line("  явных признаков не найдено");
      for (auto& i : lc.prot.indicators) {
        f.line(strf("  [%s] %s", strength_ru(i.strength), i.title.c_str()));
        if (!i.detail.empty() && (cfg.s("prot.detail") == "detailed" || det >= 2)) f.line("      " + i.detail);
      }
      f.line(strf("  энтропия файла: %.3f; байт после конца ELF: %llu", lc.prot.file_entropy, (unsigned long long)lc.prot.trailing_bytes));
      for (auto& r : lc.prot.related) f.line("  связанные данные: " + r.kind + " @ " + r.where + (r.detail.empty() ? "" : " — " + r.detail));
    }
    if (lc.strings.ran) {
      f.line("");
      f.line(strf("Строки: найдено %llu, записано %llu, отфильтровано %llu%s", (unsigned long long)lc.strings.total_found, (unsigned long long)lc.strings.written,
                  (unsigned long long)lc.strings.filtered_out, lc.strings.truncated ? " (отчёт обрезан лимитом)" : ""));
      f.line(strf("  по кодировкам: ascii %llu, utf-8 %llu, utf-16le %llu, utf-16be %llu", (unsigned long long)lc.strings.by_enc[0], (unsigned long long)lc.strings.by_enc[1],
                  (unsigned long long)lc.strings.by_enc[2], (unsigned long long)lc.strings.by_enc[3]));
    }
    if (lc.funcs.ran) {
      FuncStats fs = func_stats(lc.funcs);
      f.line("");
      f.line(strf("Функции: %llu", (unsigned long long)fs.total));
      f.line(strf("  подтверждены структурой файла (символы, раскрутка, init/entry, PLT): %llu", (unsigned long long)fs.confirmed));
      f.line(strf("  найдены анализом кода (вызовы, прологи, таблицы указателей): %llu", (unsigned long long)fs.inferred));
      f.line(strf("  достоверность: высокая %llu, средняя %llu, низкая %llu", (unsigned long long)fs.high, (unsigned long long)fs.medium, (unsigned long long)fs.low));
      f.line(strf("  имена сгенерированы (sub_...): %llu; размер оценён (~): %llu", (unsigned long long)fs.generated, (unsigned long long)fs.size_estimated));
      if (det >= 2) {
        std::string s;
        for (auto& kv : fs.by_source) s += (s.empty() ? "" : ", ") + kv.first + "=" + std::to_string(kv.second);
        f.line("  по источникам: " + s);
      }
      f.line(strf("  методы (JNI/C++): %zu; PLT-заглушек: %zu; таблиц указателей: %zu", lc.funcs.methods.size(), lc.funcs.plt.size(), lc.funcs.tables.size()));
    }
    if (lc.scan.ran) {
      XrefStats xs = xref_stats(lc.scan);
      f.line("");
      f.line(strf("Просмотр кода: инструкций %llu; декодировано байт %llu из %llu; байт данных внутри кода %llu; участков, не поддающихся декодированию: %llu",
                  (unsigned long long)lc.scan.insns, (unsigned long long)lc.scan.bytes_decoded, (unsigned long long)lc.scan.bytes_total, (unsigned long long)lc.scan.bytes_data,
                  (unsigned long long)lc.scan.undecodable));
      if (!lc.scan.arch_note.empty()) f.line("  примечание: " + lc.scan.arch_note);
      if (xs.total) f.line(strf("Перекрёстные ссылки: %llu (подтверждённых %llu, предполагаемых %llu)", (unsigned long long)xs.total, (unsigned long long)xs.confirmed, (unsigned long long)xs.heuristic));
    }
    if (lc.elfio.ran) {
      f.line("");
      if (!lc.elfio.loaded) f.line("Проверка ELFIO: библиотека не загружена (" + lc.elfio.error + ")");
      else if (lc.elfio.diffs.empty()) f.line(strf("Проверка ELFIO: расхождений нет (секций %llu, сегментов %llu)", (unsigned long long)lc.elfio.sections, (unsigned long long)lc.elfio.segments));
      else {
        f.line("Проверка ELFIO: найдены расхождения:");
        for (auto& d : lc.elfio.diffs) f.line("  - " + d);
      }
    }
    if (lc.dyn.ran) {
      f.line("");
      if (!lc.dyn.available) f.line("Динамический модуль: недоступен — " + lc.dyn.reason);
      else {
        f.line("Динамический модуль (разрешение адресов по карте памяти; библиотека не загружалась):");
        for (auto& l : lc.dyn.lines) f.line("  " + l);
      }
    }
    f.line("");
    f.line("Файлы библиотеки:");
    for (auto& fl : rc.ledger.files())
      if (fl.lib == lc.index) f.line(strf("  %-44s %10llu байт%s%s", fl.rel_path.c_str(), (unsigned long long)fl.bytes, fl.truncated ? "  [обрезан лимитом: " : "", fl.truncated ? (fl.trunc_reason + "]").c_str() : ""));
  }
  if (rc.libs.empty()) {
    H("Библиотеки");
    f.line("Ни одна библиотека не была проанализирована.");
  }

  H("Этапы");
  auto stages = rc.ledger.stages();
  std::stable_sort(stages.begin(), stages.end(), [](const StageRec& a, const StageRec& b) { return a.order < b.order; });
  for (auto& s : stages) {
    std::string lib = lib_label(rc, s.lib);
    std::string line = "  " + pad_right(s.title + (lib.empty() ? "" : " [" + lib + "]"), 60) + " " + pad_right(stage_status_ru(s.status), 18);
    if (!repro) line += strf(" %6llu мс", (unsigned long long)s.ms);
    if (!s.reason.empty()) line += "  // " + s.reason;
    f.line(line);
    if (det >= 2)
      for (auto& n : s.notes) f.line("      " + n);
  }

  H("Результаты");
  f.line("  reports/dump.txt (этот файл)");
  f.line("  summary.json и logs/run.log записываются после этого отчёта; их размеры указаны в summary.json");
  for (auto& fl : rc.ledger.files()) {
    if (fl.lib >= 0) continue;
    f.line(strf("  %-44s %10llu байт%s%s", fl.rel_path.c_str(), (unsigned long long)fl.bytes, fl.ok ? "" : "  [ОШИБКА: ", fl.ok ? "" : (fl.error + "]").c_str()));
  }

  H("Полнота (подробности: summary.json, раздел completeness)");
  std::map<std::string, u64> gc;
  for (auto& g : rc.ledger.gaps()) gc[g.kind]++;
  f.line(strf("  недоступно: %llu; пропущено: %llu; выведено по косвенным данным: %llu; получено частично: %llu", (unsigned long long)gc["unavailable"], (unsigned long long)gc["skipped"],
              (unsigned long long)gc["inferred"], (unsigned long long)gc["partial"]));
  for (auto& g : rc.ledger.gaps()) {
    std::string lib = lib_label(rc, g.lib);
    f.line(strf("  - %s%s: %s — %s", lib.empty() ? "" : ("[" + lib + "] ").c_str(), g.what.c_str(), kind_ru(g.kind), g.why.c_str()));
  }
  f.line("  Этот отчёт не утверждает, что дамп «полный»: границы известны только там, где они перечислены выше.");

  {
    std::lock_guard<std::mutex> g(rc.mu);
    if (!rc.warnings.empty()) {
      H("Предупреждения");
      size_t n = 0;
      for (auto& w : rc.warnings) {
        if (n++ >= 300) {
          f.line("  ... (остальные в logs/run.log и summary.json)");
          break;
        }
        f.line("  " + w);
      }
    }
    if (!rc.errors.empty()) {
      H("Ошибки");
      for (auto& e : rc.errors) f.line("  " + e);
    }
  }

  if (cfg.b("expert.engine_info")) {
    H("Движки и зависимости");
    int maj = 0, min = 0;
    cs_version(&maj, &min);
    f.line(strf("  Capstone %d.%d — дизассемблирование", maj, min));
    f.line(strf("  zlib %s — deflate-записи архива и сжатые секции", zlibVersion()));
    f.line(strf("  Zstandard %s — записи метода 93 и сжатые секции", ZSTD_versionString()));
    f.line(std::string("  ELFIO ") + ELFIO_VERSION + " — независимая проверка структуры ELF");
  }
  return close_report(rc, rf, true);
}

// ------------------------------------------------------------------ completeness.txt
bool stage_report_completeness(RunContext& rc) {
  if (!report_wanted(rc, "out.completeness") || !rc.cfg.b("prot.completeness_report")) return true;
  ReportFile rf(rc, -1, "completeness.txt", rc.reports_root, "reports", 0);
  if (!rf.ok()) {
    report_failed(rc, -1, "completeness.txt", rf.create_error());
    stage_partial("completeness.txt could not be created");
    return true;
  }
  rf.header("полнота дампа", nullptr);
  OutFile& f = rf.f();
  StatusInfo st = compute_status(rc);
  f.line("Статус запуска: " + st.text);
  f.line("Что получено из файла, что выведено по косвенным данным и чего не хватает.");
  f.line("Единого процента нет: число «полноты» скрыло бы разницу между подтверждённым и предполагаемым.");
  f.line("");
  std::map<std::string, u64> sc;
  for (auto& s : rc.ledger.stages()) sc[to_string(s.status)]++;
  f.line(strf("Этапы: выполнено полностью %llu; частично %llu; с ошибкой %llu; пропущено %llu; отключено %llu; отменено %llu", (unsigned long long)sc["ok"], (unsigned long long)sc["partial"],
              (unsigned long long)sc["failed"], (unsigned long long)sc["skipped"], (unsigned long long)sc["disabled"], (unsigned long long)sc["cancelled"]));
  u64 created = 0, cut = 0, failed = 0;
  for (auto& fl : rc.ledger.files()) {
    if (fl.ok) created++;
    else failed++;
    if (fl.truncated) cut++;
  }
  f.line(strf("Файлы: создано %llu; из них обрезано лимитом %llu; не создано из-за ошибки %llu", (unsigned long long)created, (unsigned long long)cut, (unsigned long long)failed));

  auto gaps = rc.ledger.gaps();
  auto print_gaps = [&](int lib) {
    bool any = false;
    for (const char* kind : {"unavailable", "skipped", "partial", "inferred"}) {
      for (auto& g : gaps) {
        if (g.lib != lib || g.kind != kind) continue;
        f.line(strf("  %-30s %s — %s", g.what.c_str(), kind_ru(g.kind), g.why.c_str()));
        any = true;
      }
    }
    if (!any) f.line("  пробелов не зафиксировано");
  };
  f.line("");
  f.line("Общее");
  print_gaps(-1);
  for (auto& s : rc.ledger.stages()) {
    if (s.lib == -1 && (s.status == StageStatus::Failed || s.status == StageStatus::Partial || s.status == StageStatus::Skipped) && !s.reason.empty())
      f.line(strf("  этап «%s»: %s — %s", s.title.c_str(), stage_status_ru(s.status), s.reason.c_str()));
  }

  for (auto& lp : rc.libs) {
    LibContext& lc = *lp;
    const ElfModel& m = lc.elf;
    f.line("");
    f.line("Библиотека " + lc.display);
    f.line(" Подтверждено (прочитано из структуры файла):");
    if (!lc.elf_ok) {
      f.line("   ничего: файл не распознан как ELF");
    } else {
      f.line(strf("   сегменты: %zu%s", m.segs.size(), m.phdr_assumed ? " (положение таблицы предположено)" : ""));
      f.line(strf("   секции: %zu%s", m.secs.size(), m.secs_reconstructed ? " — НЕ из файла: восстановлены по сегментам" : ""));
      f.line(strf("   символы .dynsym: %zu из %llu; .symtab: %zu из %llu", m.dynsym.size(), (unsigned long long)m.dynsym_declared, m.symtab.size(), (unsigned long long)m.symtab_declared));
      f.line(strf("   релокации: %zu", m.relocs.size()));
      FuncStats fs = func_stats(lc.funcs);
      if (lc.funcs.ran) f.line(strf("   функции (символы, раскрутка, init/entry, PLT): %llu", (unsigned long long)fs.confirmed));
      XrefStats xs = xref_stats(lc.scan);
      if (lc.scan.ran) f.line(strf("   ссылки, найденные прямым декодированием: %llu", (unsigned long long)xs.confirmed));
      f.line(" Выведено по косвенным данным (предположения):");
      if (lc.funcs.ran) {
        f.line(strf("   функции по вызовам, прологам и таблицам указателей: %llu", (unsigned long long)fs.inferred));
        f.line(strf("   функции с достоверностью «низкая»: %llu", (unsigned long long)fs.low));
        f.line(strf("   сгенерированные имена (sub_...): %llu", (unsigned long long)fs.generated));
        f.line(strf("   размеры, оценённые по соседним функциям (~): %llu", (unsigned long long)fs.size_estimated));
      }
      if (lc.scan.ran) f.line(strf("   эвристические ссылки (таблицы указателей): %llu", (unsigned long long)xs.heuristic));
      if (lc.scan.ran && lc.scan.bytes_total)
        f.line(strf(" Код: декодировано %llu из %llu байт исполняемых областей; байт данных внутри кода: %llu", (unsigned long long)lc.scan.bytes_decoded, (unsigned long long)lc.scan.bytes_total,
                    (unsigned long long)lc.scan.bytes_data));
    }
    f.line(" Недоступно, пропущено или получено частично:");
    print_gaps(lc.index);
    for (auto& s : rc.ledger.stages())
      if (s.lib == lc.index && (s.status == StageStatus::Failed || s.status == StageStatus::Partial || s.status == StageStatus::Skipped) && !s.reason.empty())
        f.line(strf("  этап «%s»: %s — %s", s.title.c_str(), stage_status_ru(s.status), s.reason.c_str()));
  }
  f.line("");
  f.line("Определения");
  f.line("  подтверждено: прочитано напрямую (таблицы символов, раскрутки, init/fini, точка входа, PLT и релокации);");
  f.line("  выведено: получено анализом кода и помечается меньшей достоверностью;");
  f.line("  сгенерированное имя: функция без символа получает имя sub_<адрес>; это не восстановленное исходное имя;");
  f.line("  оценённый размер: определён по соседней функции или таблице раскрутки, а не по символу.");
  return close_report(rc, rf);
}

}  // namespace kratos
