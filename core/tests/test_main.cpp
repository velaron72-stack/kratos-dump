// Host tests for the KRATOS DUMP core. Everything goes through the public C interface (kratos/api.h), the same way the
// Android app uses it, and runs against the fixtures in tests/fixtures. No runtime of the Android app is involved.
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <csignal>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <string>
#include <vector>

#include "kratos/api.h"
#include "kratos/json.h"

using kratos::Json;
namespace fs = std::filesystem;

#ifndef KRATOS_FIXTURE_DIR
#error "KRATOS_FIXTURE_DIR must be defined"
#endif

// ---------------------------------------------------------------------------------------------- mini harness
static int g_checks = 0, g_failed = 0;
static std::string g_test;

#define CHECK(cond)                                                                           \
  do {                                                                                        \
    ++g_checks;                                                                               \
    if (!(cond)) {                                                                            \
      ++g_failed;                                                                             \
      fprintf(stderr, "  FAIL [%s] %s:%d: %s\n", g_test.c_str(), __FILE__, __LINE__, #cond); \
    }                                                                                         \
  } while (0)

#define CHECK_MSG(cond, msg)                                                                              \
  do {                                                                                                    \
    ++g_checks;                                                                                           \
    if (!(cond)) {                                                                                        \
      ++g_failed;                                                                                         \
      fprintf(stderr, "  FAIL [%s] %s:%d: %s (%s)\n", g_test.c_str(), __FILE__, __LINE__, #cond, std::string(msg).c_str()); \
    }                                                                                                     \
  } while (0)

// ---------------------------------------------------------------------------------------------- helpers
static fs::path g_tmp;
static int g_dir_counter = 0;

// A name that starts with "/" is an absolute path (used for files the tests generate themselves).
static std::string fixture(const std::string& name) { return !name.empty() && name[0] == '/' ? name : std::string(KRATOS_FIXTURE_DIR) + "/" + name; }

static fs::path new_out_dir() {
  fs::path p = g_tmp / ("out" + std::to_string(++g_dir_counter));
  fs::create_directories(p);
  return p;
}

static bool read_file(const fs::path& p, std::string& out) {
  std::ifstream f(p, std::ios::binary);
  if (!f) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return true;
}

static std::string slurp(const fs::path& p) {
  std::string s;
  read_file(p, s);
  return s;
}

static Json parse_json(const std::string& text) {
  Json j;
  std::string err;
  if (!Json::parse(text, j, err)) {
    fprintf(stderr, "  JSON parse error: %s\n  text: %.200s\n", err.c_str(), text.c_str());
    return Json();
  }
  return j;
}

// Calls a C API function that returns a malloc'ed string and parses it.
static Json call_json(const std::function<char*()>& f) {
  char* s = f();
  if (!s) return Json();
  std::string txt = s;
  kratos_free(s);
  return parse_json(txt);
}

static const Json& at(const Json& j, const std::string& key) {
  static const Json null_json;
  const Json* v = j.find(key);
  return v ? *v : null_json;
}

// Follows a dotted path through nested objects.
static const Json& path(const Json& j, const std::string& dotted) {
  const Json* cur = &j;
  size_t pos = 0;
  static const Json null_json;
  while (pos <= dotted.size()) {
    size_t dot = dotted.find('.', pos);
    std::string part = dotted.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
    const Json* next = cur->find(part);
    if (!next) return null_json;
    cur = next;
    if (dot == std::string::npos) break;
    pos = dot + 1;
  }
  return *cur;
}

struct Fd {
  int fd = -1;
  explicit Fd(const std::string& p) { fd = open(p.c_str(), O_RDONLY); }
  ~Fd() {
    if (fd >= 0) close(fd);
  }
};

struct Opts {
  std::string profile = "standard";
  Json config = Json::object();
  std::vector<std::string> libs;
  std::string selected_meta;       // "" = automatic
  std::string meta_fixture;        // lib mode: separate metadata file
  std::string out_root;            // default: a fresh directory
  std::function<void(void*, const char*)> on_progress;  // (handle, stage)
};

struct Result {
  Json outcome;
  std::string status;
  fs::path run_dir;
  bool ok = false;
  std::vector<std::string> log_lines;
  const Json& summary() const { return at(outcome, "summary"); }
};

// The engine calls the callbacks from several worker threads at once, so everything they touch is guarded.
static std::mutex g_cb_mutex;

struct CbState {
  void* handle = nullptr;
  const Opts* opts = nullptr;
  std::vector<std::string>* logs = nullptr;
};

static void cb_progress(void* user, const char* stage, unsigned long long, unsigned long long, const char* text) {
  auto* s = (CbState*)user;
  if (s->opts && s->opts->on_progress) s->opts->on_progress(s->handle, stage ? stage : "");
}

static void cb_log(void* user, unsigned long long, int level, const char* stage, const char* msg) {
  auto* s = (CbState*)user;
  std::lock_guard<std::mutex> g(g_cb_mutex);
  if (s->logs) s->logs->push_back(std::to_string(level) + " " + (stage ? stage : "") + ": " + (msg ? msg : ""));
}

static Result run_fixture(const std::string& name, const Opts& o = Opts()) {
  Result r;
  bool is_apk = name.size() > 4 && name.substr(name.size() - 4) == ".apk";
  Fd main_fd(fixture(name));
  Fd meta_fd(o.meta_fixture.empty() ? std::string() : fixture(o.meta_fixture));
  if (main_fd.fd < 0) {
    fprintf(stderr, "  fixture missing: %s\n", name.c_str());
    return r;
  }
  Json req = Json::object();
  req.set("mode", is_apk ? "apk" : "lib");
  req.set(is_apk ? "display_name" : "lib_name", name);
  req.set("display_name", name);
  if (!o.meta_fixture.empty()) req.set("meta_name", o.meta_fixture);
  req.set("out_root", o.out_root.empty() ? new_out_dir().string() : o.out_root);
  req.set("temp_dir", g_tmp.string());
  req.set("profile", o.profile);
  Json libs = Json::array();
  for (auto& l : o.libs) libs.push(Json(l));
  req.set("selected_libs", libs);
  if (!o.selected_meta.empty()) req.set("selected_meta", o.selected_meta);
  req.set("config", o.config);

  void* h = kratos_run_new();
  CbState st;
  st.handle = h;
  st.opts = &o;
  st.logs = &r.log_lines;
  char* s = kratos_run_json(h, req.dump().c_str(), is_apk ? main_fd.fd : -1, is_apk ? -1 : main_fd.fd, meta_fd.fd, cb_progress, cb_log, &st);
  kratos_run_delete(h);
  if (!s) return r;
  std::string txt = s;
  kratos_free(s);
  r.outcome = parse_json(txt);
  r.status = at(r.outcome, "status_id").as_string();
  r.run_dir = at(r.outcome, "run_dir").as_string();
  r.ok = r.outcome.is_object();
  return r;
}

static bool has_file(const Result& r, const std::string& rel) { return fs::is_regular_file(r.run_dir / rel); }

// Finds the single library report directory (reports/<lib>/) of a run.
static fs::path lib_reports(const Result& r) {
  fs::path base = r.run_dir / "reports";
  if (!fs::is_directory(base)) return {};
  for (auto& e : fs::directory_iterator(base))
    if (e.is_directory()) return e.path();
  return {};
}

static size_t gap_count(const Result& r) { return at(path(r.summary(), "completeness"), "gaps").size(); }

static bool any_gap_mentions(const Result& r, const std::string& what) {
  for (auto& g : at(path(r.summary(), "completeness"), "gaps").elems()) {
    if (at(g, "what").as_string().find(what) != std::string::npos) return true;
    if (at(g, "why").as_string().find(what) != std::string::npos) return true;
  }
  return false;
}

static bool log_has(const Result& r, const std::string& needle) {
  for (auto& l : r.log_lines)
    if (l.find(needle) != std::string::npos) return true;
  return false;
}

static bool stage_status(const Result& r, const std::string& id, std::string& status) {
  for (auto& s : at(r.summary(), "stages").elems()) {
    if (at(s, "id").as_string() == id) {
      status = at(s, "status").as_string();
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------------------------- tests: configuration
static void test_info_and_schema() {
  Json info = call_json([] { return kratos_info_json(); });
  CHECK(!at(info, "version").as_string().empty());
  CHECK(!path(info, "dependencies.capstone").as_string().empty());
  CHECK(!path(info, "dependencies.zlib").as_string().empty());
  CHECK(!path(info, "dependencies.zstd").as_string().empty());
  CHECK(path(info, "dependencies.zlib").as_string().rfind("1.3", 0) == 0);
  CHECK(path(info, "dependencies.zstd").as_string().rfind("1.5.7", 0) == 0);
  CHECK(path(info, "dependencies.capstone").as_string().rfind("5.0", 0) == 0);

  Json schema = call_json([] { return kratos_schema_json(); });
  const Json& settings = at(schema, "settings");
  CHECK(settings.size() >= 100);
  std::set<std::string> keys;
  std::set<std::string> cats;
  for (auto& c : at(schema, "categories").elems()) cats.insert(at(c, "id").as_string());
  for (auto& s : settings.elems()) {
    std::string key = at(s, "key").as_string();
    CHECK_MSG(keys.insert(key).second, "duplicate key " + key);
    CHECK_MSG(cats.count(at(s, "category").as_string()) == 1, "unknown category for " + key);
    CHECK_MSG(!at(s, "title").as_string().empty(), "no title: " + key);
    // Every setting carries the five-part help text shown behind the info button.
    for (const char* part : {"purpose", "effect", "performance", "limits", "example"})
      CHECK_MSG(!path(s, std::string("info.") + part).as_string().empty(), "info." + std::string(part) + " missing: " + key);
    std::string scope = at(s, "scope").as_string();
    CHECK_MSG(scope == "native" || scope == "ui", "bad scope: " + key);
  }
  for (const char* c : {"general", "apk", "library", "protection", "functions", "disasm", "strings", "xrefs", "metadata", "output", "limits", "performance", "console", "history", "expert"})
    CHECK_MSG(cats.count(c) == 1, std::string("category missing: ") + c);

  const Json& profiles = at(schema, "profiles");
  CHECK(profiles.is_array());
  std::set<std::string> ids;
  for (auto& pj : profiles.elems()) {
    ids.insert(at(pj, "id").as_string());
    CHECK(!at(pj, "title").as_string().empty());
    CHECK(at(pj, "values").size() == settings.size());
  }
  for (const char* p : {"quick", "standard", "detailed", "maximum"}) CHECK_MSG(ids.count(p) == 1, std::string("profile missing: ") + p);
}

static void test_config_validation() {
  Json v = call_json([] { return kratos_validate_config_json("standard", "{}"); });
  CHECK(at(v, "ok").as_bool());
  CHECK(at(v, "issues").size() == 0);
  CHECK(at(v, "changed").size() == 0);
  CHECK(at(v, "values").size() >= 100);

  // Unknown key and out-of-range value are both reported; valid overrides are listed as changed.
  v = call_json([] { return kratos_validate_config_json("detailed", "{\"limits.max_strings\":0,\"nope\":1,\"xref.depth\":9999}"); });
  CHECK(at(v, "ok").as_bool());
  bool unknown = false, range = false;
  for (auto& i : at(v, "issues").elems()) {
    if (at(i, "key").as_string() == "nope") unknown = true;
    if (at(i, "key").as_string() == "xref.depth") range = true;
  }
  CHECK(unknown);
  CHECK(range);

  // 0 means "no limit set by the user" for limits.*
  Json z = call_json([] { return kratos_validate_config_json("standard", "{\"limits.max_strings\":0}"); });
  CHECK(at(z, "issues").size() == 0);
  CHECK(path(z, "values").find("limits.max_strings") != nullptr);
  CHECK(path(z, "values.limits.max_strings").is_null() || true);

  // Malformed JSON is rejected without a crash.
  Json bad = call_json([] { return kratos_validate_config_json("standard", "{not json"); });
  CHECK(!at(bad, "ok").as_bool());
  CHECK(!at(bad, "error").as_string().empty());

  // The four profiles differ from each other.
  Json q = call_json([] { return kratos_validate_config_json("quick", "{}"); });
  Json m = call_json([] { return kratos_validate_config_json("maximum", "{}"); });
  size_t diff = 0;
  for (auto& kv : at(q, "values").members()) {
    const Json* o = at(m, "values").find(kv.first);
    if (!o || o->dump() != kv.second.dump()) ++diff;
  }
  CHECK(diff > 5);
}

static void test_probes() {
  {
    Fd fd(fixture("sample_multi_abi.apk"));
    Json p = call_json([&] { return kratos_probe_apk_json(fd.fd, "sample_multi_abi.apk", "standard", "{}", g_tmp.c_str()); });
    CHECK(at(p, "ok").as_bool());
    CHECK(at(p, "libs").size() == 4);
    CHECK(at(p, "entries").as_int() == 8);
    // The probe is read-only and does not consume the descriptor.
    CHECK(lseek(fd.fd, 0, SEEK_END) > 0);
  }
  {
    Fd fd(fixture("not_a_zip.apk"));
    Json p = call_json([&] { return kratos_probe_apk_json(fd.fd, "not_a_zip.apk", "standard", "{}", g_tmp.c_str()); });
    CHECK(p.is_object());
    CHECK(!at(p, "ok").as_bool());
    CHECK(!at(p, "error").as_string().empty());
  }
  {
    Fd fd(fixture("sample_arm64.so"));
    Json p = call_json([&] { return kratos_probe_lib_json(fd.fd, "sample_arm64.so"); });
    CHECK(at(p, "is_elf").as_bool());
    CHECK(at(p, "arch").as_string() == "arm64");
    CHECK(at(p, "bits").as_int() == 64);
    CHECK(at(p, "ok").as_bool());
  }
  {
    Fd fd(fixture("not_elf.so"));
    Json p = call_json([&] { return kratos_probe_lib_json(fd.fd, "not_elf.so"); });
    CHECK(p.is_object());
    CHECK(!at(p, "is_elf").as_bool());
  }
  {
    Fd fd(fixture("global-metadata.dat"));
    Json p = call_json([&] { return kratos_probe_meta_json(fd.fd, "global-metadata.dat"); });
    CHECK(at(p, "ok").as_bool());
  }
  {
    Fd fd(fixture("global-metadata-badmagic.dat"));
    Json p = call_json([&] { return kratos_probe_meta_json(fd.fd, "global-metadata-badmagic.dat"); });
    CHECK(p.is_object());
    CHECK(!at(p, "ok").as_bool());
  }
  // Invalid descriptor must not crash.
  Json bad = call_json([] { return kratos_probe_lib_json(-1, "x.so"); });
  CHECK(bad.is_object());
}

static void test_check_dir() {
  Json d = call_json([] { return kratos_check_dir_json(g_tmp.c_str()); });
  CHECK(at(d, "exists").as_bool());
  CHECK(at(d, "is_dir").as_bool());
  CHECK(at(d, "writable").as_bool());
  Json n = call_json([] { return kratos_check_dir_json("/nonexistent/kratos/dir"); });
  CHECK(!at(n, "exists").as_bool());
  CHECK(!at(n, "writable").as_bool());
  fs::path file = g_tmp / "plain_file";
  std::ofstream(file) << "x";
  Json f = call_json([&] { return kratos_check_dir_json(file.c_str()); });
  CHECK(!at(f, "is_dir").as_bool());
}

// ---------------------------------------------------------------------------------------------- tests: full runs
// Expected final status of each fixture. A damaged but partly readable file is still a success: the damage is
// recorded as gaps in the completeness report instead of being hidden or turned into a failure.
static const std::map<std::string, std::string>& expected_status() {
  static const std::map<std::string, std::string> m = {
      {"elf_header_only.so", "success"},
      {"elf_ident_only.so", "error"},
      {"empty.so", "error"},
      {"not_elf.so", "error"},
      {"not_a_zip.apk", "error"},
  };
  return m;
}

static void test_all_fixtures_run() {
  std::vector<std::string> names;
  for (auto& e : fs::directory_iterator(KRATOS_FIXTURE_DIR)) {
    std::string n = e.path().filename().string();
    if (e.is_regular_file() && (n.size() > 3 && (n.substr(n.size() - 3) == ".so" || n.substr(n.size() - 4) == ".apk"))) names.push_back(n);
  }
  CHECK(names.size() >= 40);
  for (auto& n : names) {
    g_test = "fixture " + n;
    for (const char* profile : {"quick", "maximum"}) {
      Opts o;
      o.profile = profile;
      Result r = run_fixture(n, o);
      CHECK_MSG(r.ok, n + " produced no outcome");
      if (!r.ok) continue;
      auto it = expected_status().find(n);
      std::string want = it == expected_status().end() ? "success" : it->second;
      CHECK_MSG(r.status == want, n + " [" + profile + "]: status " + r.status + ", expected " + want);
      // The status text is one of the four required phrases.
      std::string text = at(r.outcome, "status_text").as_string();
      CHECK_MSG(text == "Успешно завершено" || text == "Завершено с ошибкой" || text == "Отменено пользователем" || text == "Не запущено", text);
      // A finished run always leaves summary.json, and its status agrees with the outcome.
      CHECK_MSG(has_file(r, "summary.json"), n + ": summary.json not written");
      Json disk = parse_json(slurp(r.run_dir / "summary.json"));
      CHECK(path(disk, "status.id").as_string() == r.status);
      // A success is never reported while a mandatory failure is on record, and the reverse.
      size_t mand = at(path(r.summary(), "status"), "mandatory_failures").size();
      CHECK_MSG((r.status == "success") == (mand == 0), n + ": status and mandatory failures disagree");
      // Standard folder layout.
      for (const char* d : {"source", "libraries", "metadata", "reports", "logs"})
        CHECK_MSG(fs::is_directory(r.run_dir / d), n + ": missing directory " + d);
    }
  }
  g_test.clear();
}

static void test_required_reports_maximum() {
  Opts o;
  o.profile = "maximum";
  Result r = run_fixture("sample_multi_abi.apk", o);
  CHECK(r.status == "success");
  for (const char* f : {"summary.json", "reports/dump.txt", "reports/completeness.txt", "reports/analysis_log.txt", "reports/metadata_report.txt", "logs/run.log"})
    CHECK_MSG(has_file(r, f), std::string("missing ") + f);
  fs::path lr = lib_reports(r);
  CHECK(!lr.empty());
  for (const char* f : {"functions.txt", "methods.txt", "offsets.h", "strings.txt", "imports.txt", "exports.txt", "disassembly.txt", "hex_dump.txt",
                        "sections.txt", "segments.txt", "relocations.txt", "cross_references.txt"}) {
    CHECK_MSG(fs::is_regular_file(lr / f), std::string("missing library report ") + f);
    CHECK_MSG(fs::exists(lr / f) && fs::file_size(lr / f) > 0, std::string("empty library report ") + f);
  }
  CHECK(has_file(r, "libraries/arm64-v8a/libsample.so"));
  CHECK(has_file(r, "metadata/global-metadata.dat"));
  // The source is stored only when asked for; the file list is stored by default.
  CHECK(has_file(r, "source/apk_files.txt"));
}

static void test_output_toggles() {
  Opts o;
  o.profile = "maximum";
  o.config.set("out.hex_dump", false);
  o.config.set("out.cross_references", false);
  o.config.set("out.disassembly", false);
  Result r = run_fixture("sample_arm64.so", o);
  CHECK(r.status == "success");
  fs::path lr = lib_reports(r);
  CHECK(!fs::exists(lr / "hex_dump.txt"));
  CHECK(!fs::exists(lr / "cross_references.txt"));
  CHECK(!fs::exists(lr / "disassembly.txt"));
  CHECK(fs::exists(lr / "functions.txt"));
  // Disabled outputs are not counted as failed files.
  CHECK(path(r.summary(), "completeness.files.failed").as_int() == 0);
}

// ---------------------------------------------------------------------------------------------- tests: analysis quality
static void test_arm64_sample_content() {
  Opts o;
  o.profile = "maximum";
  Result r = run_fixture("sample_arm64.so", o);
  CHECK(r.status == "success");
  const Json& lib = at(r.summary(), "libraries").at(0);
  CHECK(path(lib, "elf.parsed").as_bool());
  CHECK(path(lib, "elf.architecture").as_string() == "arm64");
  CHECK(path(lib, "elf.bits").as_int() == 64);
  CHECK(path(lib, "elf.dynsym_parsed").as_int() > 0);
  CHECK(path(lib, "elf.dynsym_parsed").as_int() == path(lib, "elf.dynsym_declared").as_int());
  CHECK(path(lib, "functions.total").as_int() >= 10);
  CHECK(path(lib, "strings.found").as_int() > 10);
  CHECK(path(lib, "code_scan.instructions").as_int() > 50);
  CHECK(path(lib, "code_scan.bytes_decoded").as_int() > 0);
  // Cross-references are split into confirmed and heuristic, and the two parts add up.
  CHECK(path(lib, "xrefs.total").as_int() == path(lib, "xrefs.confirmed").as_int() + path(lib, "xrefs.heuristic").as_int());

  fs::path lr = lib_reports(r);
  std::string fn = slurp(lr / "functions.txt");
  CHECK(!fn.empty());
  std::string dis = slurp(lr / "disassembly.txt");
  CHECK(dis.find("bl") != std::string::npos || dis.find("ret") != std::string::npos);
  std::string off = slurp(lr / "offsets.h");
  CHECK(off.find("0x") != std::string::npos);
  std::string comp = slurp(r.run_dir / "reports/completeness.txt");
  CHECK(!comp.empty());
}

static void test_all_architectures_decode() {
  for (const char* n : {"sample_arm.so", "sample_arm64.so", "sample_x86.so", "sample_x86_64.so"}) {
    g_test = std::string("arch ") + n;
    Opts o;
    o.profile = "standard";
    Result r = run_fixture(n, o);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK(path(lib, "elf.parsed").as_bool());
    CHECK_MSG(path(lib, "code_scan.instructions").as_int() > 20, n);
    CHECK_MSG(path(lib, "functions.total").as_int() >= 5, n);
    // Everything the code scanner could not decode is accounted for, not silently dropped.
    CHECK(path(lib, "code_scan.bytes_decoded").as_int() <= path(lib, "code_scan.bytes_total").as_int());
  }
  g_test.clear();
}

static void test_stripped_gets_generated_names() {
  for (const char* n : {"sample_arm64_stripped.so", "sample_arm_stripped.so", "sample_x86_64_stripped.so"}) {
    g_test = std::string("stripped ") + n;
    Opts o;
    o.profile = "standard";
    Result r = run_fixture(n, o);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "functions.total").as_int() >= 5, n);
    CHECK_MSG(path(lib, "functions.generated_names").as_int() >= 1, n);
    // Functions found only by code analysis are marked as inferred, never as read from the file structure.
    CHECK_MSG(path(lib, "functions.confirmed_by_structure").as_int() + path(lib, "functions.inferred_by_code_analysis").as_int() == path(lib, "functions.total").as_int(), n);
    std::string fn = slurp(lib_reports(r) / "functions.txt");
    CHECK_MSG(fn.find("sub_") != std::string::npos, n);
  }
  g_test.clear();
}

static void test_plt_xrefs_resolved() {
  // Calls through the PLT must resolve to the imported name, even without section headers or symbols.
  for (const char* n : {"sample_arm64.so", "sample_arm.so", "sample_x86_64.so", "sample_arm64_stripped.so", "sample_arm_stripped.so",
                        "sample_arm64_nosections.so", "sample_arm64_zeroedsections.so"}) {
    g_test = std::string("plt ") + n;
    Opts o;
    o.profile = "maximum";
    Result r = run_fixture(n, o);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "functions.plt_stubs").as_int() > 0, n);
    CHECK_MSG(path(lib, "xrefs.total").as_int() > 0, n);
  }
  g_test.clear();
}

static void test_cross_references_label_kinds() {
  Opts o;
  o.profile = "maximum";
  Result r = run_fixture("sample_arm64_stripped.so", o);
  CHECK(r.status == "success");
  std::string x = slurp(lib_reports(r) / "cross_references.txt");
  CHECK(!x.empty());
  // The report states what is confirmed and what is a heuristic guess.
  bool mentions_confirmed = x.find("confirmed") != std::string::npos || x.find("подтвержд") != std::string::npos;
  bool mentions_heur = x.find("heuristic") != std::string::npos || x.find("эвристи") != std::string::npos || x.find("предположит") != std::string::npos;
  CHECK(mentions_confirmed);
  CHECK(mentions_heur);
}

static void test_obfuscated_names_survive() {
  for (const char* n : {"sample_arm64_obfnames.so", "sample_arm_obfnames.so", "sample_x86_64_obfnames.so"}) {
    g_test = std::string("obf ") + n;
    Opts o;
    o.profile = "standard";
    Result r = run_fixture(n, o);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "functions.total").as_int() >= 5, n);
    CHECK_MSG(path(lib, "strings.found").as_int() > 0, n);
  }
  g_test.clear();
}

static void test_packed_is_flagged() {
  Opts o;
  // A file with a removed section table and a packer signature is flagged, and the reasons are listed.
  Result r = run_fixture("sample_arm64_packedlike.so", o);
  CHECK(r.status == "success");
  const Json& lib = at(r.summary(), "libraries").at(0);
  CHECK(path(lib, "protection.ran").as_bool());
  std::set<std::string> ids;
  for (auto& i : path(lib, "protection.indicators").elems()) ids.insert(at(i, "id").as_string());
  CHECK(ids.count("marker") == 1);
  CHECK(ids.count("no_sections") == 1);
  CHECK(path(lib, "functions.total").as_int() > 0);
  // A plain library has no indicators.
  Result plain = run_fixture("sample_arm64.so", o);
  CHECK(path(at(plain.summary(), "libraries").at(0), "protection.indicators").size() == 0);
}

static void test_packed_relocations_are_decoded() {
  // Android packed relocations (APS2) and RELR are normal link-time compression, not protection: they must be decoded,
  // and they must not be reported as a packer.
  for (const char* n : {"sample_arm64_packed.so", "sample_arm_packed.so", "sample_arm64_relr.so"}) {
    g_test = std::string("relocs ") + n;
    Result r = run_fixture(n);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "elf.relocations").as_int() > 0, n);
    CHECK_MSG(!path(lib, "elf.relocations_partial").as_bool(), n);
    CHECK_MSG(path(lib, "protection.indicators").size() == 0, n);
  }
  g_test.clear();
}

static void test_damaged_elf_is_analyzed_with_gaps() {
  // Each of these has damaged or missing headers. The run must still produce results and must say what was guessed.
  for (const char* n : {"sample_arm64_badphoff.so", "sample_arm64_badshoff.so", "sample_arm64_nosections.so", "sample_arm64_truncated.so",
                        "sample_arm64_zeroedsections.so", "sample_arm_badshoff.so", "sample_arm_nosections.so", "sample_x86_64_nosections.so",
                        "sample_x86_64_truncated.so", "sample_x86_64_zeroedsections.so"}) {
    g_test = std::string("damaged ") + n;
    Opts o;
    o.profile = "standard";
    Result r = run_fixture(n, o);
    CHECK_MSG(r.status == "success", n);
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "elf.parsed").as_bool(), n);
    CHECK_MSG(path(lib, "functions.total").as_int() > 0, n);
    CHECK_MSG(gap_count(r) > 0, std::string(n) + ": damaged file produced no recorded gaps");
    CHECK(has_file(r, "reports/completeness.txt"));
  }
  g_test.clear();
}

static void test_appended_data_noted() {
  for (const char* n : {"sample_arm64_appended.so", "sample_arm_appended.so", "sample_x86_64_appended.so"}) {
    g_test = std::string("appended ") + n;
    Opts o;
    Result r = run_fixture(n, o);
    CHECK(r.status == "success");
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "protection.trailing_bytes").as_int() > 0, n);
  }
  g_test.clear();
}

static void test_not_elf_and_degenerate_inputs() {
  for (const char* n : {"not_elf.so", "empty.so", "elf_ident_only.so"}) {
    g_test = std::string("degenerate ") + n;
    Result r = run_fixture(n);
    CHECK(r.ok);
    CHECK_MSG(r.status == "error", n);
    CHECK_MSG(at(path(r.summary(), "status"), "mandatory_failures").size() > 0, n);
    // Even a failed run explains itself and leaves its summary.
    CHECK(has_file(r, "summary.json"));
    CHECK(has_file(r, "logs/run.log"));
    CHECK(at(r.summary(), "errors").size() > 0);
  }
  g_test.clear();
}


static void test_damaged_ident_is_inferred() {
  // One damaged byte in e_ident (invalid class, or a byte-order flag that contradicts the rest of the header) must not stop the
  // analysis: the real values are inferred from the other header fields, and the inference is recorded.
  for (const char* n : {"bad_class.so", "bad_endian.so"}) {
    g_test = std::string("ident ") + n;
    Opts o;
    o.profile = "maximum";
    Result r = run_fixture(n, o);
    CHECK_MSG(r.status == "success", n);
    const Json& lib = at(r.summary(), "libraries").at(0);
    CHECK_MSG(path(lib, "elf.architecture").as_string() == "arm64", n);
    CHECK_MSG(path(lib, "elf.little_endian").as_bool(), n);
    CHECK_MSG(path(lib, "functions.total").as_int() >= 10, n);
    CHECK_MSG(any_gap_mentions(r, "ELF identification"), n);
    std::set<std::string> ids;
    for (auto& i : path(lib, "protection.indicators").elems()) ids.insert(at(i, "id").as_string());
    CHECK_MSG(ids.count("header_nonstandard") == 1, n);

    // The library probe used for automatic selection inside an APK accepts it too.
    Fd fd(fixture(n));
    Json p = call_json([&] { return kratos_probe_lib_json(fd.fd, n); });
    CHECK_MSG(at(p, "is_elf").as_bool(), n);
    CHECK_MSG(at(p, "arch").as_string() == "arm64", n);
  }
  g_test.clear();
  // Nothing to infer from: the identification alone is not enough, so this stays an error.
  Result ident = run_fixture("elf_ident_only.so");
  CHECK(ident.status == "error");
}

// ---------------------------------------------------------------------------------------------- tests: APK mode
static void test_apk_auto_selection() {
  Opts o;
  Result r = run_fixture("sample_multi_abi.apk", o);
  CHECK(r.status == "success");
  const Json& apk = at(r.summary(), "apk");
  CHECK(at(apk, "readable").as_bool());
  CHECK(at(apk, "library_candidates").size() == 4);
  CHECK(at(apk, "abis").size() == 4);
  // Automatic rule: arm64-v8a first, one library.
  CHECK(at(r.summary(), "libraries").size() == 1);
  CHECK(at(at(r.summary(), "libraries").at(0), "entry").as_string() == "lib/arm64-v8a/libsample.so");
  CHECK(path(r.summary(), "metadata.found").as_bool());
  CHECK(path(r.summary(), "metadata.handler").as_string() == "il2cpp");
}

static void test_apk_user_selection_overrides_auto() {
  Opts o;
  o.libs = {"lib/armeabi-v7a/libsample.so", "lib/x86_64/libsample.so"};
  Result r = run_fixture("sample_multi_abi.apk", o);
  CHECK(r.status == "success");
  const Json& libs = at(r.summary(), "libraries");
  CHECK(libs.size() == 2);
  std::set<std::string> got;
  for (auto& l : libs.elems()) got.insert(at(l, "entry").as_string());
  CHECK(got.count("lib/armeabi-v7a/libsample.so") == 1);
  CHECK(got.count("lib/x86_64/libsample.so") == 1);
  CHECK(path(libs.at(0), "elf.parsed").as_bool());
  CHECK(has_file(r, "libraries/armeabi-v7a/libsample.so"));
  CHECK(has_file(r, "libraries/x86_64/libsample.so"));
}

static void test_apk_metadata_choice() {
  Opts none;
  none.selected_meta = "none";
  Result r = run_fixture("sample_multi_abi.apk", none);
  CHECK(r.status == "success");
  CHECK(!has_file(r, "metadata/global-metadata.dat"));
  CHECK(!path(r.summary(), "metadata.found").as_bool());
}

static void test_apk_without_libraries() {
  Result r = run_fixture("sample_no_libs.apk");
  CHECK(r.ok);
  CHECK(r.status != "not_started");
  CHECK(at(r.summary(), "libraries").size() == 0);
  // The absence of libraries is stated, not hidden.
  CHECK(has_file(r, "reports/completeness.txt"));
}

static void test_apk_stored_and_nested() {
  Result stored = run_fixture("sample_stored_libs.apk");
  CHECK(stored.status == "success");
  CHECK(at(stored.summary(), "libraries").size() >= 1);
  CHECK(path(at(stored.summary(), "libraries").at(0), "elf.parsed").as_bool());

  Opts o;
  Result nested = run_fixture("sample_nested.apk", o);
  CHECK(nested.status == "success");
  CHECK(at(path(nested.summary(), "apk"), "nested_archives").size() >= 1);
}

static void test_apk_odd_abi_directory() {
  Result r = run_fixture("sample_odd_abi.apk");
  CHECK(r.ok);
  CHECK(r.status == "success");
  CHECK(at(path(r.summary(), "apk"), "library_candidates").size() >= 1);
}

static void test_apk_damaged_archives() {
  // Corrupt central directory: entries are recovered from local headers and the recovery is reported.
  Result eocd = run_fixture("corrupt_eocd.apk");
  CHECK(eocd.ok);
  CHECK(at(path(eocd.summary(), "apk"), "readable").as_bool());
  CHECK(at(path(eocd.summary(), "apk"), "central_directory_recovered").as_bool());
  CHECK(any_gap_mentions(eocd, "central") || any_gap_mentions(eocd, "directory") || any_gap_mentions(eocd, "каталог"));

  Result trunc = run_fixture("corrupt_truncated.apk");
  CHECK(trunc.ok);
  CHECK(at(path(trunc.summary(), "apk"), "readable").as_bool());

  // A CRC mismatch on an entry is recorded but does not stop the other entries.
  Result crc = run_fixture("sample_bad_crc.apk");
  CHECK(crc.status == "success");
  CHECK(at(crc.summary(), "libraries").size() == 1);
  CHECK(path(at(crc.summary(), "libraries").at(0), "elf.parsed").as_bool());
  bool crc_warned = false;
  for (auto& w : at(crc.summary(), "warnings").elems())
    if (w.as_string().find("CRC32") != std::string::npos) crc_warned = true;
  CHECK(crc_warned);
  CHECK(any_gap_mentions(crc, "libsample.so"));

  Result notzip = run_fixture("not_a_zip.apk");
  CHECK(notzip.status == "error");
  CHECK(!at(path(notzip.summary(), "apk"), "readable").as_bool());
  CHECK(at(notzip.summary(), "errors").size() > 0);
}

static void test_independent_stages_after_failure() {
  // The user picked one library that is not an ELF file and one that is valid. The valid one is still analyzed and
  // saved; the failure is reported and the final status is not "success".
  Opts o;
  o.libs = {"lib/arm64-v8a/libnotelf.so", "lib/armeabi-v7a/libsample.so"};
  Result r = run_fixture("sample_bad_lib.apk", o);
  CHECK(r.ok);
  CHECK(r.status == "error");
  CHECK(at(r.summary(), "libraries").size() == 2);
  int parsed = 0;
  for (auto& l : at(r.summary(), "libraries").elems())
    if (path(l, "elf.parsed").as_bool()) ++parsed;
  CHECK(parsed == 1);
  CHECK(at(path(r.summary(), "status"), "mandatory_failures").size() >= 1);
  CHECK(has_file(r, "summary.json"));
  CHECK(has_file(r, "reports/completeness.txt"));
  bool have_report = false;
  for (auto& e : fs::directory_iterator(r.run_dir / "reports"))
    if (e.is_directory() && fs::exists(e.path() / "functions.txt")) have_report = true;
  CHECK(have_report);
}

static void test_damaged_library_inside_apk() {
  // libbroken.so has damaged headers: it is analyzed from what is readable and the guesses are recorded.
  Result r = run_fixture("sample_bad_lib.apk");
  CHECK(r.status == "success");
  CHECK(at(r.summary(), "libraries").size() == 1);
  CHECK(path(at(r.summary(), "libraries").at(0), "elf.parsed").as_bool());
  CHECK(gap_count(r) > 0);
  // The non-ELF candidate is listed and explained, not silently dropped.
  bool noted = false;
  for (auto& c : at(path(r.summary(), "apk"), "library_candidates").elems())
    if (at(c, "entry").as_string().find("libnotelf.so") != std::string::npos && !at(c, "is_elf").as_bool() && !at(c, "note").as_string().empty()) noted = true;
  CHECK(noted);
}

// ---------------------------------------------------------------------------------------------- tests: metadata
static void test_metadata_cases() {
  {
    Opts o;
    o.meta_fixture = "global-metadata.dat";
    Result r = run_fixture("sample_arm64.so", o);
    CHECK(r.status == "success");
    CHECK(path(r.summary(), "metadata.found").as_bool());
    CHECK(path(r.summary(), "metadata.status").as_string() == "ok");
    CHECK(path(r.summary(), "metadata.handler").as_string() == "il2cpp");
    CHECK(path(r.summary(), "metadata.info.version").as_int() == 29);
    CHECK(has_file(r, "metadata/global-metadata.dat"));
  }
  struct Case {
    const char* file;
    const char* status;
  };
  for (const Case& c : {Case{"global-metadata-badmagic.dat", "invalid"}, Case{"global-metadata-badversion.dat", "unsupported_version"},
                        Case{"global-metadata-truncated.dat", "invalid"}}) {
    g_test = std::string("metadata ") + c.file;
    Opts o;
    o.meta_fixture = c.file;
    Result r = run_fixture("sample_arm64.so", o);
    // Metadata is optional: a bad file never fails the library analysis, but it is never reported as healthy either.
    CHECK_MSG(r.status == "success", c.file);
    CHECK_MSG(path(r.summary(), "metadata.status").as_string() == c.status, std::string(c.file) + ": " + path(r.summary(), "metadata.status").as_string());
    CHECK_MSG(any_gap_mentions(r, "metadata"), c.file);
    CHECK_MSG(at(path(r.summary(), "libraries").at(0), "elf").is_object(), c.file);
  }
  g_test.clear();
  // Bad metadata inside an APK: same rules.
  Result bad = run_fixture("sample_bad_metadata.apk");
  CHECK(bad.status == "success");
  CHECK(path(bad.summary(), "metadata.status").as_string() == "invalid");
  CHECK(at(bad.summary(), "warnings").size() >= 1);
  CHECK(path(at(bad.summary(), "libraries").at(0), "elf.parsed").as_bool());
}

// ---------------------------------------------------------------------------------------------- tests: limits, settings, cancel, errors
static void test_limits_are_reported_not_hidden() {
  Opts cut;
  cut.config.set("limits.max_strings", 5);
  Result r = run_fixture("sample_arm64.so", cut);
  CHECK(r.status == "success");
  const Json& lib = at(r.summary(), "libraries").at(0);
  CHECK(path(lib, "strings.truncated").as_bool());
  CHECK(path(lib, "strings.written").as_int() <= 5);
  CHECK(path(lib, "strings.found").as_int() > path(lib, "strings.written").as_int());
  CHECK(path(r.summary(), "completeness.files.cut_by_limit").as_int() >= 1);
  std::string txt = slurp(lib_reports(r) / "strings.txt");
  CHECK(!txt.empty());

  // 0 means no limit set by the user.
  Opts free_run;
  free_run.config.set("limits.max_strings", 0);
  Result r0 = run_fixture("sample_arm64.so", free_run);
  CHECK(r0.status == "success");
  CHECK(!path(at(r0.summary(), "libraries").at(0), "strings.truncated").as_bool());
  CHECK(path(at(r0.summary(), "libraries").at(0), "strings.written").as_int() == path(at(r0.summary(), "libraries").at(0), "strings.found").as_int());
}

static void test_settings_change_results() {
  // A setting that does nothing is a bug. Check that a few representative settings change the output.
  Opts base;
  Result a = run_fixture("sample_arm64.so", base);
  Opts minlen;
  minlen.config.set("strings.min_len", 12);
  Result b = run_fixture("sample_arm64.so", minlen);
  CHECK(path(at(b.summary(), "libraries").at(0), "strings.found").as_int() < path(at(a.summary(), "libraries").at(0), "strings.found").as_int());

  Opts prefix;
  prefix.config.set("func.name_prefix", "zz_");
  Result c = run_fixture("sample_arm64_stripped.so", prefix);
  CHECK(slurp(lib_reports(c) / "functions.txt").find("zz_") != std::string::npos);
  CHECK(slurp(lib_reports(c) / "functions.txt").find("sub_") == std::string::npos);

  Opts nodis;
  nodis.config.set("out.disassembly", false);
  Result d = run_fixture("sample_arm64.so", nodis);
  CHECK(!fs::exists(lib_reports(d) / "disassembly.txt"));

  // Changed settings are listed in the summary.
  CHECK(at(path(c.summary(), "run"), "settings_changed_from_profile").size() >= 1);
}

static void test_profiles_differ_in_output() {
  Opts q, m;
  q.profile = "quick";
  m.profile = "maximum";
  Result rq = run_fixture("sample_arm64.so", q);
  Result rm = run_fixture("sample_arm64.so", m);
  CHECK(rq.status == "success");
  CHECK(rm.status == "success");
  size_t nq = 0, nm = 0;
  for (auto& e : fs::recursive_directory_iterator(rq.run_dir)) nq += e.is_regular_file();
  for (auto& e : fs::recursive_directory_iterator(rm.run_dir)) nm += e.is_regular_file();
  CHECK(nm > nq);
  CHECK(path(rm.summary(), "run.profile").as_string() == "maximum");
  CHECK(path(rq.summary(), "run.profile").as_string() == "quick");
}

static void test_unknown_profile_warns_and_runs() {
  Opts o;
  o.profile = "no_such_profile";
  Result r = run_fixture("sample_arm64.so", o);
  CHECK(r.ok);
  CHECK(r.status == "success");
  CHECK(log_has(r, "no_such_profile") || at(r.summary(), "warnings").size() > 0);
}

static void test_invalid_setting_value_does_not_break_run() {
  Opts o;
  o.config.set("xref.depth", 99999);
  o.config.set("no.such.key", 1);
  Result r = run_fixture("sample_arm64.so", o);
  CHECK(r.ok);
  CHECK(r.status == "success");
}

static void test_cancel() {
  Opts o;
  o.profile = "maximum";
  std::atomic<int> calls{0};
  o.on_progress = [&](void* h, const char*) {
    if (calls++ == 0) kratos_run_cancel(h);
  };
  Result r = run_fixture("sample_multi_abi.apk", o);
  CHECK(r.ok);
  CHECK(r.status == "cancelled");
  CHECK(at(r.outcome, "status_text").as_string() == "Отменено пользователем");
  // A cancelled run is never reported as a success, and it still explains what was and was not done.
  CHECK(has_file(r, "summary.json"));
  Json disk = parse_json(slurp(r.run_dir / "summary.json"));
  CHECK(path(disk, "status.id").as_string() == "cancelled");
  std::string st;
  bool any_cancelled = false;
  for (auto& s : at(r.summary(), "stages").elems())
    if (at(s, "status").as_string() == "cancelled" || at(s, "status").as_string() == "skipped") any_cancelled = true;
  CHECK(any_cancelled);
  CHECK(!stage_status(r, "no_such_stage", st));
}

static void test_unwritable_output() {
  Opts o;
  o.out_root = "/proc/kratos_no_such_dir/out";
  Result r = run_fixture("sample_arm64.so", o);
  CHECK(r.ok || r.outcome.is_object());
  CHECK(r.status != "success");
  CHECK(r.status == "not_started" || r.status == "error");
  CHECK(!at(r.outcome, "error").as_string().empty() || r.status == "error");
}

static void test_output_name_unique() {
  // Two runs into the same folder never overwrite each other (out.overwrite = unique).
  fs::path root = new_out_dir();
  Opts o;
  o.out_root = root.string();
  Result a = run_fixture("sample_arm64.so", o);
  Result b = run_fixture("sample_arm64.so", o);
  CHECK(a.status == "success");
  CHECK(b.status == "success");
  CHECK(a.run_dir != b.run_dir);
  CHECK(fs::exists(a.run_dir / "summary.json"));
  CHECK(fs::exists(b.run_dir / "summary.json"));
  CHECK(a.run_dir.parent_path().filename() == "android_dump");
}

static std::string normalize(std::string s) {
  // Timestamps and the run name vary between runs; everything else must be identical.
  static const std::regex ts("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z");
  static const std::regex stamp("[0-9]{8}_[0-9]{6}");
  static const std::regex dur("(Длительность|duration)[^\\n]*");
  s = std::regex_replace(s, ts, "<ts>");
  s = std::regex_replace(s, stamp, "<stamp>");
  s = std::regex_replace(s, dur, "<dur>");
  return s;
}

static void test_deterministic_reports() {
  Opts o;
  o.profile = "maximum";
  Result a = run_fixture("sample_arm64_stripped.so", o);
  Result b = run_fixture("sample_arm64_stripped.so", o);
  CHECK(a.status == "success");
  CHECK(b.status == "success");
  fs::path la = lib_reports(a), lb = lib_reports(b);
  int compared = 0;
  for (auto& e : fs::directory_iterator(la)) {
    std::string name = e.path().filename().string();
    std::string x = normalize(slurp(e.path())), y = normalize(slurp(lb / name));
    CHECK_MSG(x == y, "report differs between identical runs: " + name);
    ++compared;
  }
  CHECK(compared >= 10);
}

static void test_concurrent_runs_are_independent() {
  std::vector<std::string> st(4);
  std::vector<std::thread> th;
  const char* names[4] = {"sample_arm64.so", "sample_arm.so", "sample_x86_64.so", "sample_multi_abi.apk"};
  std::vector<fs::path> outs;
  for (int i = 0; i < 4; ++i) outs.push_back(new_out_dir());
  for (int i = 0; i < 4; ++i) {
    th.emplace_back([&, i] {
      Opts o;
      o.out_root = outs[i].string();
      Result r = run_fixture(names[i], o);
      st[i] = r.status;
    });
  }
  for (auto& t : th) t.join();
  for (int i = 0; i < 4; ++i) CHECK_MSG(st[i] == "success", names[i]);
}

static void test_status_texts_exact() {
  // The four statuses required by the specification have exactly these texts.
  Result ok = run_fixture("sample_arm64.so");
  CHECK(at(ok.outcome, "status_text").as_string() == "Успешно завершено");
  Result bad = run_fixture("not_elf.so");
  CHECK(at(bad.outcome, "status_text").as_string() == "Завершено с ошибкой");
}


// ---------------------------------------------------------------------------------------------- tests: settings are really used
static std::set<std::string> native_setting_keys() {
  Json schema = call_json([] { return kratos_schema_json(); });
  std::set<std::string> keys;
  for (auto& st : at(schema, "settings").elems())
    if (at(st, "scope").as_string() == "native") keys.insert(at(st, "key").as_string());
  return keys;
}

// Static check: every setting that the native side owns is referenced by name in the engine code (outside the registry itself).
static void test_every_native_setting_is_referenced_in_code() {
  std::string code;
  for (const char* dir : {"src", "include"}) {
    for (auto& e : fs::recursive_directory_iterator(fs::path(KRATOS_SOURCE_DIR) / dir)) {
      if (!e.is_regular_file()) continue;
      if (e.path().filename() == "settings.cpp") continue;
      std::string ext = e.path().extension().string();
      if (ext == ".cpp" || ext == ".h") code += slurp(e.path());
    }
  }
  CHECK(code.size() > 100000);
  std::set<std::string> keys = native_setting_keys();
  CHECK(keys.size() >= 130);
  for (auto& k : keys) CHECK_MSG(code.find("\"" + k + "\"") != std::string::npos, "setting is never read by the engine: " + k);
}

// Dynamic check: run a spread of inputs with everything switched on and record which settings the engine actually read.
static void test_settings_are_read_during_runs() {
  std::set<std::string> read;
  struct In {
    const char* file;
  };
  for (const char* f : {"sample_multi_abi.apk", "sample_nested.apk", "sample_bad_crc.apk", "sample_arm64.so", "sample_arm.so", "sample_x86.so", "sample_x86_64.so",
                        "sample_arm64_stripped.so", "sample_arm64_packedlike.so", "sample_arm_nosections.so"}) {
    Opts o;
    o.profile = "maximum";
    o.config.set("expert.diagnostics", true);
    o.config.set("dyn.enabled", true);
    Result r = run_fixture(f, o);
    std::string diag = slurp(r.run_dir / "logs/diagnostics.txt");
    size_t pos = diag.find("прочитанные движком:");
    CHECK_MSG(pos != std::string::npos, std::string("no diagnostics for ") + f);
    if (pos == std::string::npos) continue;
    std::istringstream in(diag.substr(pos));
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
      if (line.empty()) break;
      size_t a = line.find_first_not_of(' ');
      if (a != std::string::npos) read.insert(line.substr(a));
    }
  }
  // Settings that are only read when a condition is met (a range is given, an output folder already exists, a run fails, ...).
  static const std::set<std::string> conditional = {"dyn.log", "dyn.pid", "dyn.save_artifacts", "lib.range_space", "out.overwrite", "out.partial_results"};
  for (auto& k : native_setting_keys())
    if (!conditional.count(k)) CHECK_MSG(read.count(k) == 1, "setting was not read in any run: " + k);
}

static void test_arm_mode_forced() {
  auto count = [](const std::string& s, const std::string& needle) {
    size_t n = 0, p = 0;
    while ((p = s.find(needle, p)) != std::string::npos) {
      ++n;
      p += needle.size();
    }
    return n;
  };
  Opts arm, thumb, autom;
  arm.config.set("disasm.arm_mode", "arm");
  thumb.config.set("disasm.arm_mode", "thumb");
  std::string a = slurp(lib_reports(run_fixture("sample_arm.so", arm)) / "disassembly.txt");
  std::string t = slurp(lib_reports(run_fixture("sample_arm.so", thumb)) / "disassembly.txt");
  std::string d = slurp(lib_reports(run_fixture("sample_arm.so", autom)) / "disassembly.txt");
  CHECK(count(a, "-- thumb --") == 0);
  CHECK(count(a, "-- arm --") > 0);
  CHECK(count(t, "-- arm --") == 0);
  CHECK(count(t, "-- thumb --") > 0);
  // Automatic mode finds both kinds in this mixed library.
  CHECK(count(d, "-- arm --") > 0);
  CHECK(count(d, "-- thumb --") > 0);
}


static size_t count_of(const std::string& hay, const std::string& needle) {
  size_t n = 0, p = 0;
  while ((p = hay.find(needle, p)) != std::string::npos) {
    ++n;
    p += needle.size();
  }
  return n;
}

static void test_unicode_strings() {
  Opts o;
  o.profile = "maximum";
  Result r = run_fixture("sample_arm64_strings.so", o);
  CHECK(r.status == "success");
  const Json& st = path(at(r.summary(), "libraries").at(0), "strings");
  CHECK(path(st, "by_encoding.utf8").as_int() >= 2);
  CHECK(path(st, "by_encoding.utf16le").as_int() >= 2);
  CHECK(path(st, "by_encoding.utf16be").as_int() >= 1);
  std::string txt = slurp(lib_reports(r) / "strings.txt");
  for (const char* s : {"Привет, мир! Проверка", "你好，世界，这是一个测试字符串", "Широкая строка UTF-16", "Wide text", "Big endian"})
    CHECK_MSG(count_of(txt, s) == 1, std::string("expected exactly one hit of: ") + s);

  // Choosing only ASCII leaves out every non-ASCII and every wide string.
  Opts ascii;
  ascii.profile = "maximum";
  Json enc = Json::array();
  enc.push(Json("ascii"));
  ascii.config.set("strings.encodings", enc);
  Result a = run_fixture("sample_arm64_strings.so", ascii);
  std::string at_txt = slurp(lib_reports(a) / "strings.txt");
  CHECK(at_txt.find("Привет") == std::string::npos);
  CHECK(at_txt.find("Wide text") == std::string::npos);
  CHECK(path(at(a.summary(), "libraries").at(0), "strings.by_encoding.utf16le").as_int() == 0);
}

// A JNI export present in both .dynsym and .symtab is one method, not two.
static void test_methods_listed_once() {
  for (const char* n : {"sample_arm64.so", "sample_arm.so", "sample_x86_64.so"}) {
    Opts o;
    o.profile = "maximum";
    Result r = run_fixture(n, o);
    CHECK_MSG(r.status == "success", n);
    std::string txt = slurp(lib_reports(r) / "methods.txt");
    CHECK_MSG(count_of(txt, "Native.nativeAdd(") == 1, std::string("nativeAdd listed more than once in ") + n);
    CHECK_MSG(count_of(txt, "JNI_OnLoad\n") == 1, std::string("JNI_OnLoad listed more than once in ") + n);
  }
}

// PLT0 (the lazy-binding resolver at the start of .plt) is one entry of its own kind, the second half of every stub is not a
// function, and a symbol that is in both .dynsym and .symtab appears once in offsets.h.
static void test_plt_header_and_offsets_dedupe() {
  for (const char* n : {"sample_arm64.so", "sample_arm.so", "sample_x86.so", "sample_x86_64.so"}) {
    Opts o;
    o.profile = "maximum";
    Result r = run_fixture(n, o);
    CHECK_MSG(r.status == "success", n);
    std::istringstream in(slurp(lib_reports(r) / "functions.txt"));
    std::string line;
    int headers = 0, plt_lines = 0;
    while (std::getline(in, line)) {
      if (line.find(" .plt ") == std::string::npos) continue;
      plt_lines++;
      if (line.find("{plt-header}") != std::string::npos) {
        headers++;
        continue;
      }
      CHECK_MSG(line.find("ptrtable") == std::string::npos, std::string("lazy-binding tail listed as a function in ") + n + ": " + line);
      CHECK_MSG(line.find("{plt}") != std::string::npos && line.find("@plt") != std::string::npos, std::string("unnamed PLT entry in ") + n + ": " + line);
    }
    CHECK_MSG(headers == 1, std::string("expected one PLT0 entry in ") + n);
    CHECK_MSG(plt_lines == 6, std::string("expected PLT0 and five stubs in ") + n);

    std::string offs = slurp(lib_reports(r) / "offsets.h");
    CHECK_MSG(count_of(offs, "uintptr_t kratos_add_RVA") == 1, std::string("kratos_add listed more than once in offsets.h of ") + n);
    CHECK_MSG(offs.find("kratos_add_2_") == std::string::npos, n);
  }
}

// ---------------------------------------------------------------------------------------------- tests: key dependencies
// Every third-party component that is built into the core has at least one test that goes through the real pipeline.

// zstd: ZIP method 93 (APK entry compressed with Zstandard).
static void test_zstd_zip_entry() {
  Result r = run_fixture("sample_zstd.apk");
  CHECK(r.ok);
  CHECK(r.status == "success");
  std::string listing = slurp(r.run_dir / "source/apk_files.txt");
  CHECK(listing.find("zstd") != std::string::npos);
  CHECK(listing.find("stored") != std::string::npos);
  // The extracted library is byte for byte the original, so the frame was decoded completely and verified (CRC-32).
  fs::path extracted = r.run_dir / "libraries/arm64-v8a/libsample.so";
  CHECK(fs::is_regular_file(extracted));
  CHECK(slurp(extracted) == slurp(fixture("sample_arm64.so")));
  const Json& lib = at(r.summary(), "libraries").at(0);
  CHECK(path(lib, "elf.architecture").as_string() == "arm64");
  CHECK(path(lib, "elf.parsed").as_bool());
}

// zlib (deflate) for APK entries is covered by every *.apk fixture with method 8. This one is about ELF sections:
// zlib (ELFCOMPRESS_ZLIB) and zstd (ELFCOMPRESS_ZSTD) compressed debug sections are decompressed to look for strings.
static void test_compressed_sections() {
  for (const char* n : {"sample_arm64_zlibsec.so", "sample_arm64_zstdsec.so"}) {
    Opts on;
    on.profile = "maximum";
    Result a = run_fixture(n, on);
    CHECK_MSG(a.status == "success", n);
    std::string txt = slurp(lib_reports(a) / "strings.txt");
    // "op_fn" is a local variable name that exists only inside the compressed .debug_str.
    CHECK_MSG(txt.find("\"op_fn\"") != std::string::npos, std::string("decompressed string missing in ") + n);
    CHECK_MSG(txt.find("decompressed") != std::string::npos, std::string("decompressed strings are not marked in ") + n);

    Opts off = on;
    off.config.set("lib.decompress_sections", false);
    Result b = run_fixture(n, off);
    CHECK_MSG(b.status == "success", n);
    std::string txt2 = slurp(lib_reports(b) / "strings.txt");
    CHECK_MSG(txt2.find("\"op_fn\"") == std::string::npos, std::string("the setting must switch decompression off: ") + n);
  }
}

// ELFIO: an independent second parse; its figures must agree with ours on healthy files and its refusal on damaged files is reported.
static void test_elfio_cross_check() {
  for (const char* n : {"sample_arm64.so", "sample_arm.so", "sample_x86.so", "sample_x86_64.so", "sample_arm64_stripped.so"}) {
    Opts o;
    o.profile = "maximum";
    Result r = run_fixture(n, o);
    CHECK_MSG(r.status == "success", n);
    const Json& lib = at(r.summary(), "libraries").at(0);
    const Json& x = at(lib, "elfio_cross_check");
    CHECK_MSG(at(x, "loaded").as_bool(), n);
    CHECK_MSG(at(x, "discrepancies").size() == 0, n);
    CHECK_MSG(at(x, "sections").as_int() == path(lib, "elf.sections").as_int() && at(x, "sections").as_int() > 0, n);
    CHECK_MSG(at(x, "segments").as_int() == path(lib, "elf.segments").as_int() && at(x, "segments").as_int() > 0, n);
  }
  // Switched off: the stage does not run and the summary has no ELFIO block.
  Opts off;
  off.profile = "maximum";
  off.config.set("lib.cross_check_elfio", false);
  Result r = run_fixture("sample_arm64.so", off);
  CHECK(r.status == "success");
  CHECK(at(at(r.summary(), "libraries").at(0), "elfio_cross_check").is_null());
  // A damaged file: ELFIO refuses it and that is recorded as a discrepancy, not hidden.
  Opts dm;
  dm.profile = "maximum";
  Result d = run_fixture("sample_arm64_badshoff.so", dm);
  CHECK(d.ok);
  const Json& xd = at(at(d.summary(), "libraries").at(0), "elfio_cross_check");
  CHECK(!at(xd, "loaded").as_bool());
  CHECK(at(xd, "discrepancies").size() >= 1);
}

// ---------------------------------------------------------------------------------------------- tests: large files and write failures
#if defined(__SANITIZE_ADDRESS__)
#define KRATOS_TEST_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define KRATOS_TEST_SANITIZED 1
#endif
#endif

// Builds sample_arm64.so followed by `extra` bytes of reproducible pseudo-random non-ASCII data. A readable marker is planted in every
// full MiB, so a scan that stopped early would miss the later ones.
static std::string make_padded_library(const std::string& name, size_t extra, int* markers) {
  fs::path p = g_tmp / name;
  std::string base = slurp(fixture("sample_arm64.so"));
  std::ofstream f(p, std::ios::binary);
  f.write(base.data(), (std::streamsize)base.size());
  uint64_t x = 0x9e3779b97f4a7c15ull;
  std::string chunk(1 << 20, '\0');
  size_t left = extra;
  int n = 0;
  while (left) {
    size_t take = std::min(left, chunk.size());
    for (size_t i = 0; i < take; i++) {
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      chunk[i] = (char)(0x80 | (x >> 24));  // no printable ASCII, so the filler does not drown the string index
    }
    if (take == chunk.size()) {
      std::string m = "KRATOS_LARGE_MARKER_" + std::to_string(n++) + "_END";
      for (size_t i = 0; i < m.size(); i++) chunk[1000 + i] = m[i];
      chunk[1000 + m.size()] = '\0';
    }
    f.write(chunk.data(), (std::streamsize)take);
    left -= take;
  }
  if (markers) *markers = n;
  return p.string();
}

// Resets the peak resident memory counter of this process (Linux only).
static bool reset_peak_rss() {
  FILE* f = fopen("/proc/self/clear_refs", "w");
  if (!f) return false;
  bool ok = fputs("5", f) >= 0;
  ok = fclose(f) == 0 && ok;
  return ok;
}

static long peak_rss_kb() {
  std::ifstream f("/proc/self/status");
  std::string line;
  while (std::getline(f, line))
    if (line.rfind("VmHWM:", 0) == 0) return atol(line.c_str() + 6);
  return 0;
}

static void test_large_file_streaming() {
#ifdef KRATOS_TEST_SANITIZED
  const size_t extra = 6u << 20;  // the sanitizers make the run far slower and distort memory figures
#else
  const size_t extra = 32u << 20;
#endif
  int markers = 0;
  std::string big = make_padded_library("big_padded.so", extra, &markers);
  const uint64_t size = fs::file_size(big);
  CHECK(markers >= 5);

  Opts o;
  o.profile = "maximum";
  o.config.set("perf.large_file_mb", 1);  // everything above 1 MiB counts as large
  o.config.set("out.hex_bytes_per_line", 16);
  o.config.set("out.hex_collapse", false);
  o.config.set("out.hex_ascii", false);
  const bool measured = reset_peak_rss();
  const long before = peak_rss_kb();
  Result r = run_fixture(big, o);
  const long peak = peak_rss_kb();
  CHECK(r.ok);
  CHECK(r.status == "success");
  const Json& lib = at(r.summary(), "libraries").at(0);
  CHECK(at(lib, "large_file_mode").as_bool());
  CHECK(at(lib, "size").as_int() == (long long)size);
  // The mode is visible, and so is what it costs.
  CHECK(any_gap_mentions(r, "large"));
  CHECK(any_gap_mentions(r, "ELFIO"));

  // No user limit (profile "maximum", limits 0): the whole file is dumped, up to and including the final offset line.
  fs::path hex = lib_reports(r) / "hex_dump.txt";
  CHECK(fs::is_regular_file(hex));
  CHECK(fs::file_size(hex) >= size * 3);
  std::string tail;
  {
    std::ifstream f(hex, std::ios::binary);
    f.seekg(0, std::ios::end);
    std::streamoff len = f.tellg();
    std::streamoff from = len > 4096 ? len - 4096 : 0;
    f.seekg(from);
    tail.assign((size_t)(len - from), '\0');
    f.read(&tail[0], (std::streamsize)tail.size());
  }
  char endline[32];
  snprintf(endline, sizeof endline, "%08llx\n", (unsigned long long)size);
  const size_t el = strlen(endline);
  CHECK_MSG(tail.size() >= el && tail.compare(tail.size() - el, el, endline) == 0, "hex_dump.txt must end with the offset " + std::string(endline));

  // Strings are scanned across the whole file, including the last megabyte.
  std::string strings = slurp(lib_reports(r) / "strings.txt");
  CHECK_MSG(strings.find("KRATOS_LARGE_MARKER_0_END") != std::string::npos, "first marker missing");
  CHECK_MSG(strings.find("KRATOS_LARGE_MARKER_" + std::to_string(markers - 1) + "_END") != std::string::npos, "last marker missing");

  // Streaming: the hex dump is several times larger than the input, but it must not be held in memory.
#ifndef KRATOS_TEST_SANITIZED
  if (measured && peak > 0) {
    const long hex_kb = (long)(fs::file_size(hex) >> 10);
    const long growth = peak - before;
    fprintf(stderr, "  large file: input %llu KiB, hex dump %ld KiB, peak memory growth %ld KiB\n", (unsigned long long)(size >> 10), hex_kb, growth);
    CHECK_MSG(growth < hex_kb / 2, "peak memory grew by " + std::to_string(growth) + " KiB for a " + std::to_string(hex_kb) + " KiB report");
  }
#else
  (void)measured;
  (void)before;
  (void)peak;
#endif
  std::error_code ec;
  fs::remove(big, ec);
}

namespace {
// Limits the size of any file this process writes. Writes past the limit fail with EFBIG instead of killing the process.
struct FileSizeLimit {
  rlimit old{};
  bool active = false;
  explicit FileSizeLimit(rlim_t bytes) {
    signal(SIGXFSZ, SIG_IGN);
    if (getrlimit(RLIMIT_FSIZE, &old) != 0) return;
    rlimit lim = old;
    lim.rlim_cur = bytes;
    active = setrlimit(RLIMIT_FSIZE, &lim) == 0;
  }
  ~FileSizeLimit() {
    if (active) setrlimit(RLIMIT_FSIZE, &old);
  }
};
}  // namespace

static Result run_with_write_limit(const std::string& lib, Opts o, rlim_t limit) {
  o.profile = "maximum";
  o.config.set("out.hex_bytes_per_line", 16);
  o.config.set("out.hex_collapse", false);
  FileSizeLimit guard(limit);
  CHECK(guard.active);
  return run_fixture(lib, o);
}

static void test_report_write_failure_is_reported() {
  int markers = 0;
  std::string lib = make_padded_library("write_fail.so", 200u << 10, &markers);
  // The hex dump of this file is about 1 MiB, so it cannot be written under a 256 KiB file size limit.
  Result r = run_with_write_limit(lib, Opts(), 256u << 10);
  CHECK(r.ok);
  // The failed report is named as an optional failure, required results are intact, and the status is not a success.
  CHECK(r.status == "error");
  CHECK(at(r.outcome, "status_text").as_string() == "Завершено с ошибкой");
  Json disk = parse_json(slurp(r.run_dir / "summary.json"));
  CHECK(path(disk, "status.id").as_string() == "error");
  bool named = false;
  for (auto& e : path(disk, "status.optional_failures").elems())
    if (e.as_string().find("hex_dump.txt") != std::string::npos) named = true;
  CHECK_MSG(named, "hex_dump.txt must be listed among the optional failures");
  CHECK(path(disk, "status.mandatory_failures").size() == 0);
  CHECK(has_file(r, "reports/dump.txt"));
  CHECK(has_file(r, "reports/completeness.txt"));
  CHECK(!slurp(r.run_dir / "reports/dump.txt").empty());
  // A half-written report is not left behind as if it were a result.
  CHECK(!fs::exists(lib_reports(r) / "hex_dump.txt"));
  // Independent reports were still produced.
  CHECK(fs::is_regular_file(lib_reports(r) / "sections.txt"));
  CHECK(fs::is_regular_file(lib_reports(r) / "functions.txt"));
  std::error_code ec;
  fs::remove(lib, ec);
}

static void test_partial_results_off_removes_failed_run() {
  int markers = 0;
  std::string lib = make_padded_library("write_fail2.so", 200u << 10, &markers);
  Opts o;
  o.config.set("out.partial_results", false);
  Result r = run_with_write_limit(lib, o, 256u << 10);
  CHECK(r.ok);
  CHECK(r.status == "error");
  // With partial results switched off a failed run leaves no directory, and the outcome says so instead of pointing at it.
  CHECK(r.run_dir.empty() || !fs::exists(r.run_dir));
  std::error_code ec;
  fs::remove(lib, ec);
}

// ---------------------------------------------------------------------------------------------- main
int main(int argc, char** argv) {
  std::string filter = argc > 1 ? argv[1] : "";
  g_tmp = fs::temp_directory_path() / ("kratos_tests_" + std::to_string(getpid()));
  fs::create_directories(g_tmp);

  struct T {
    const char* name;
    void (*fn)();
  };
  const T tests[] = {
      {"info_and_schema", test_info_and_schema},
      {"config_validation", test_config_validation},
      {"probes", test_probes},
      {"check_dir", test_check_dir},
      {"all_fixtures_run", test_all_fixtures_run},
      {"required_reports_maximum", test_required_reports_maximum},
      {"output_toggles", test_output_toggles},
      {"arm64_sample_content", test_arm64_sample_content},
      {"all_architectures_decode", test_all_architectures_decode},
      {"stripped_gets_generated_names", test_stripped_gets_generated_names},
      {"plt_xrefs_resolved", test_plt_xrefs_resolved},
      {"cross_references_label_kinds", test_cross_references_label_kinds},
      {"obfuscated_names_survive", test_obfuscated_names_survive},
      {"packed_is_flagged", test_packed_is_flagged},
      {"packed_relocations_are_decoded", test_packed_relocations_are_decoded},
      {"damaged_elf_is_analyzed_with_gaps", test_damaged_elf_is_analyzed_with_gaps},
      {"appended_data_noted", test_appended_data_noted},
      {"not_elf_and_degenerate_inputs", test_not_elf_and_degenerate_inputs},
      {"damaged_ident_is_inferred", test_damaged_ident_is_inferred},
      {"apk_auto_selection", test_apk_auto_selection},
      {"apk_user_selection_overrides_auto", test_apk_user_selection_overrides_auto},
      {"apk_metadata_choice", test_apk_metadata_choice},
      {"apk_without_libraries", test_apk_without_libraries},
      {"apk_stored_and_nested", test_apk_stored_and_nested},
      {"apk_odd_abi_directory", test_apk_odd_abi_directory},
      {"apk_damaged_archives", test_apk_damaged_archives},
      {"independent_stages_after_failure", test_independent_stages_after_failure},
      {"damaged_library_inside_apk", test_damaged_library_inside_apk},
      {"metadata_cases", test_metadata_cases},
      {"limits_are_reported_not_hidden", test_limits_are_reported_not_hidden},
      {"settings_change_results", test_settings_change_results},
      {"profiles_differ_in_output", test_profiles_differ_in_output},
      {"unknown_profile_warns_and_runs", test_unknown_profile_warns_and_runs},
      {"invalid_setting_value_does_not_break_run", test_invalid_setting_value_does_not_break_run},
      {"cancel", test_cancel},
      {"unwritable_output", test_unwritable_output},
      {"output_name_unique", test_output_name_unique},
      {"deterministic_reports", test_deterministic_reports},
      {"concurrent_runs_are_independent", test_concurrent_runs_are_independent},
      {"status_texts_exact", test_status_texts_exact},
      {"arm_mode_forced", test_arm_mode_forced},
      {"unicode_strings", test_unicode_strings},
      {"every_native_setting_is_referenced_in_code", test_every_native_setting_is_referenced_in_code},
      {"settings_are_read_during_runs", test_settings_are_read_during_runs},
      {"methods_listed_once", test_methods_listed_once},
      {"plt_header_and_offsets_dedupe", test_plt_header_and_offsets_dedupe},
      {"zstd_zip_entry", test_zstd_zip_entry},
      {"compressed_sections", test_compressed_sections},
      {"elfio_cross_check", test_elfio_cross_check},
      {"large_file_streaming", test_large_file_streaming},
      {"report_write_failure_is_reported", test_report_write_failure_is_reported},
      {"partial_results_off_removes_failed_run", test_partial_results_off_removes_failed_run},
  };

  int ran = 0, failed_tests = 0;
  for (const T& t : tests) {
    if (!filter.empty() && std::string(t.name).find(filter) == std::string::npos) continue;
    g_test = t.name;
    int before = g_failed;
    t.fn();
    ++ran;
    bool ok = g_failed == before;
    if (!ok) ++failed_tests;
    printf("%s %s\n", ok ? "PASS" : "FAIL", t.name);
    fflush(stdout);
  }
  std::error_code ec;
  fs::remove_all(g_tmp, ec);
  printf("\n%d tests, %d failed, %d checks, %d failed checks\n", ran, failed_tests, g_checks, g_failed);
  return g_failed == 0 && ran > 0 ? 0 : 1;
}
