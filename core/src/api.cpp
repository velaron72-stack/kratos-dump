// Flat C interface over the engine (see api.h).
#include "kratos/api.h"

#include <capstone/capstone.h>
#include <zlib.h>
#include <zstd.h>

#include <unistd.h>

#include "kratos/engine.h"
#include "kratos/io.h"
#include "kratos/stages.h"

using namespace kratos;

namespace {

char* dup_string(const std::string& s) {
  char* p = (char*)malloc(s.size() + 1);
  if (!p) return nullptr;
  memcpy(p, s.data(), s.size());
  p[s.size()] = 0;
  return p;
}

char* fail_json(const std::string& msg) {
  Json j = Json::object();
  j.set("ok", false);
  j.set("error", msg);
  return dup_string(j.dump());
}

Json parse_object(const char* text, std::string& err) {
  Json j = Json::object();
  if (!text || !*text) return j;
  Json parsed;
  if (!Json::parse(text, parsed, err)) return j;
  if (!parsed.is_object()) {
    err = "a JSON object was expected";
    return j;
  }
  return parsed;
}

// Profile values with the given overrides applied on top.
Json merged_values(const std::string& profile, const Json& overrides) {
  Json v = profile_values(find_profile(profile) ? profile : "standard");
  for (auto& kv : overrides.members()) v.set(kv.first, kv.second);
  return v;
}

template <class F>
char* guarded(F&& f) {
  try {
    return f();
  } catch (const std::exception& e) {
    return fail_json(std::string("internal error: ") + e.what());
  } catch (...) {
    return fail_json("internal error");
  }
}

struct Handle {
  CancelToken cancel;
  std::atomic<bool> running{false};
};

Json lib_json(const ApkLib& l) {
  Json o = Json::object();
  o.set("entry", l.entry);
  o.set("name", l.name);
  o.set("abi", l.abi);
  o.set("size", l.size);
  o.set("is_elf", l.is_elf);
  o.set("validated", l.validated);
  o.set("arch", arch_name(l.arch));
  o.set("arch_label", arch_label(l.arch));
  o.set("bits", l.bits);
  o.set("little_endian", l.le);
  o.set("skipped_by_arch", l.skipped_by_arch);
  o.set("note", l.note);
  o.set("nested", l.nested);
  o.set("rank", l.rank);
  o.set("selected_auto", l.selected_auto);
  return o;
}

}  // namespace

extern "C" {

char* kratos_info_json(void) {
  return guarded([&]() -> char* {
    Json j = Json::object();
    j.set("version", KRATOS_VERSION);
    Json d = Json::object();
    int maj = 0, mn = 0;
    cs_version(&maj, &mn);
    d.set("capstone", strf("%d.%d", maj, mn));
    d.set("zlib", zlibVersion());
    d.set("zstd", ZSTD_versionString());
    j.set("dependencies", d);
    Json a = Json::array();
    for (const char* n : {"arm64", "arm", "x86_64", "x86"}) a.push(Json(n));
    j.set("architectures", a);
    return dup_string(j.dump());
  });
}

char* kratos_schema_json(void) {
  return guarded([&]() -> char* { return dup_string(schema_json().dump()); });
}

char* kratos_validate_config_json(const char* profile_id, const char* overrides_json) {
  return guarded([&]() -> char* {
    std::string err;
    Json ov = parse_object(overrides_json, err);
    if (!err.empty()) return fail_json("overrides: " + err);
    std::string profile = profile_id && *profile_id ? profile_id : "standard";
    std::vector<ConfigIssue> issues;
    Config cfg = Config::from_json(merged_values(profile, ov), &issues);
    Json out = Json::object();
    out.set("ok", true);
    out.set("profile", profile);
    Json is = Json::array();
    for (auto& i : issues) {
      Json o = Json::object();
      o.set("key", i.key);
      o.set("message", i.message);
      is.push(o);
    }
    out.set("issues", is);
    out.set("values", cfg.to_json());
    Json ch = Json::array();
    for (auto& k : cfg.diff_from(find_profile(profile) ? profile : "standard")) ch.push(Json(k));
    out.set("changed", ch);
    return dup_string(out.dump());
  });
}

char* kratos_probe_apk_json(int fd, const char* name, const char* profile_id, const char* overrides_json, const char* temp_dir) {
  return guarded([&]() -> char* {
    std::string err;
    Json ov = parse_object(overrides_json, err);
    if (!err.empty()) return fail_json("overrides: " + err);
    Config cfg = Config::from_json(merged_values(profile_id && *profile_id ? profile_id : "standard", ov), nullptr);
    Logger log;
    std::string e2;
    ApkScan s = inspect_apk_only(fd, name ? name : "", cfg, log, nullptr, e2, temp_dir ? temp_dir : "");
    Json out = Json::object();
    out.set("ok", s.ok);
    out.set("error", s.ok ? "" : (s.error.empty() ? e2 : s.error));
    out.set("entries", s.entries);
    out.set("dirs", s.dirs);
    out.set("total_uncompressed", s.total_uncompressed);
    out.set("total_compressed", s.total_compressed);
    out.set("recovered", s.recovered);
    out.set("zip64", s.zip64);
    out.set("has_lib_dir", s.has_lib_dir);
    Json w = Json::array();
    for (auto& x : s.warnings) w.push(Json(x));
    out.set("warnings", w);
    Json abis = Json::array();
    for (auto& x : s.abis) abis.push(Json(x));
    out.set("abis", abis);
    Json libs = Json::array();
    for (auto& l : s.libs) libs.push(lib_json(l));
    out.set("libs", libs);
    Json metas = Json::array();
    for (auto& m : s.metas) {
      Json o = Json::object();
      o.set("entry", m.entry);
      o.set("name", m.name);
      o.set("handler", m.handler);
      o.set("size", m.size);
      o.set("status", m.status);
      o.set("note", m.note);
      metas.push(o);
    }
    out.set("metas", metas);
    Json nested = Json::array();
    for (auto& x : s.nested_apks) nested.push(Json(x));
    out.set("nested_apks", nested);
    Json rel = Json::array();
    for (auto& r : s.related) {
      Json o = Json::object();
      o.set("kind", r.kind);
      o.set("where", r.where);
      o.set("detail", r.detail);
      rel.push(o);
    }
    out.set("related", rel);
    return dup_string(out.dump());
  });
}

char* kratos_probe_lib_json(int fd, const char* name) {
  return guarded([&]() -> char* {
    if (fd < 0) return fail_json("no file");
    FdSource src(::dup(fd), true);
    ApkLib l = probe_library_source(src, name ? name : "");
    Json out = lib_json(l);
    out.set("ok", l.is_elf);
    return dup_string(out.dump());
  });
}

char* kratos_probe_meta_json(int fd, const char* name) {
  return guarded([&]() -> char* {
    if (fd < 0) return fail_json("no file");
    FdSource src(::dup(fd), true);
    Json out = probe_metadata_source(src, name ? name : "");
    out.set("ok", out.has("recognized") && out.find("recognized")->as_bool());
    return dup_string(out.dump());
  });
}

char* kratos_check_dir_json(const char* path) {
  return guarded([&]() -> char* {
    std::string p = path ? path : "";
    Json out = Json::object();
    out.set("exists", path_exists(p));
    out.set("is_dir", is_directory(p));
    std::string err;
    bool w = !p.empty() && dir_writable(p, err);
    out.set("writable", w);
    out.set("error", w ? "" : err);
    u64 avail = 0;
    bool known = !p.empty() && free_space_of(p, avail);
    out.set("free_known", known);
    out.set("free_bytes", known ? avail : (u64)0);
    return dup_string(out.dump());
  });
}

void* kratos_run_new(void) { return new (std::nothrow) Handle(); }

void kratos_run_cancel(void* handle) {
  if (handle) static_cast<Handle*>(handle)->cancel.cancel();
}

void kratos_run_delete(void* handle) { delete static_cast<Handle*>(handle); }

char* kratos_run_json(void* handle, const char* request_json, int apk_fd, int lib_fd, int meta_fd, kratos_progress_fn progress, kratos_log_fn log, void* user) {
  return guarded([&]() -> char* {
    Handle* h = static_cast<Handle*>(handle);
    if (!h) return fail_json("invalid handle");
    bool expected = false;
    if (!h->running.compare_exchange_strong(expected, true)) return fail_json("a run is already in progress on this handle");
    struct Release {
      Handle* h;
      ~Release() { h->running = false; }
    } release{h};
    h->cancel.reset();

    std::string err;
    Json j = parse_object(request_json, err);
    if (!err.empty()) return fail_json("request: " + err);
    auto str = [&](const char* k) {
      const Json* v = j.find(k);
      return v && v->is_string() ? v->as_string() : std::string();
    };
    RunRequest req;
    req.mode = str("mode").empty() ? "apk" : str("mode");
    req.display_name = str("display_name");
    req.lib_name = str("lib_name");
    req.meta_name = str("meta_name");
    req.out_root = str("out_root");
    req.temp_dir = str("temp_dir");
    if (!str("profile").empty()) req.profile_id = str("profile");
    req.selected_meta = str("selected_meta");
    req.apk_fd = apk_fd;
    req.lib_fd = lib_fd;
    req.meta_fd = meta_fd;
    if (const Json* sl = j.find("selected_libs"))
      if (sl->is_array())
        for (auto& e : sl->elems())
          if (e.is_string()) req.selected_libs.push_back(e.as_string());
    if (const Json* c = j.find("config"))
      if (c->is_object()) req.config = *c;

    ProgressFn pf = [&](const std::string& stage, u64 done, u64 total, const std::string& text) {
      if (progress) progress(user, stage.c_str(), done, total, text.c_str());
    };
    Logger::Callback lf = [&](const LogEntry& e) {
      if (log) log(user, e.ts_ms, (int)e.level, e.stage.c_str(), e.msg.c_str());
    };
    RunOutcome o = run_analysis(req, h->cancel, pf, lf);
    Json out = Json::object();
    out.set("ok", o.status_id != "not_started");
    out.set("status_id", o.status_id);
    out.set("status_text", o.status_text);
    out.set("run_dir", o.run_dir);
    out.set("summary_path", o.summary_path);
    out.set("error", o.error);
    out.set("summary", o.summary);
    return dup_string(out.dump());
  });
}

void kratos_free(char* p) { free(p); }

}  // extern "C"
