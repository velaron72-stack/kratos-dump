// Host command-line front end for the KRATOS DUMP core: runs the same engine the Android app uses.
#include <fcntl.h>
#include <unistd.h>

#include <csignal>
#include <iostream>

#include "kratos/engine.h"
#include "kratos/stages.h"

using namespace kratos;

namespace {

CancelToken g_cancel;
void on_sigint(int) { g_cancel.cancel(); }

void usage() {
  fprintf(stderr,
          "usage:\n"
          "  kratos_cli apk <file.apk> -o <dir> [options]\n"
          "  kratos_cli lib <file.so> -o <dir> [--meta <file>] [options]\n"
          "  kratos_cli schema            print the settings schema as JSON\n"
          "options:\n"
          "  --profile quick|standard|detailed|maximum\n"
          "  --set key=value                            override one setting (repeatable)\n"
          "  --config file.json                         JSON object with setting overrides\n"
          "  --lib <entry>                              APK entry to analyze (repeatable); default: automatic selection\n"
          "  --meta <entry|none|path>                   metadata: APK entry, 'none', or a file path in lib mode\n"
          "  --temp <dir>                               scratch directory\n"
          "  --quiet                                    only the final result line\n");
}

Json parse_value(const SettingDef* def, const std::string& v) {
  if (def) {
    switch (def->kind) {
      case SettingKind::Bool: return Json(v == "1" || v == "true" || v == "yes" || v == "on");
      case SettingKind::Int: return Json((long long)strtoll(v.c_str(), nullptr, 0));
      case SettingKind::Number: return Json(strtod(v.c_str(), nullptr));
      case SettingKind::Flags: {
        Json a = Json::array();
        for (auto& p : split(v, ',')) a.push(Json(trim(p)));
        return a;
      }
      default: break;
    }
  }
  return Json(v);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  std::string cmd = argv[1];
  if (cmd == "schema") {
    printf("%s\n", schema_json().dump(2).c_str());
    return 0;
  }
  if ((cmd != "apk" && cmd != "lib") || argc < 3) {
    usage();
    return 2;
  }
  RunRequest req;
  req.mode = cmd;
  std::string input = argv[2];
  std::string out_dir, meta_arg, temp;
  bool quiet = false;
  std::vector<std::pair<std::string, std::string>> sets;
  std::string config_file;
  for (int i = 3; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "-o") out_dir = next();
    else if (a == "--profile") req.profile_id = next();
    else if (a == "--set") {
      std::string kv = next();
      size_t eq = kv.find('=');
      if (eq == std::string::npos) {
        fprintf(stderr, "--set needs key=value\n");
        return 2;
      }
      sets.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
    } else if (a == "--config") config_file = next();
    else if (a == "--lib") req.selected_libs.push_back(next());
    else if (a == "--meta") meta_arg = next();
    else if (a == "--temp") temp = next();
    else if (a == "--quiet") quiet = true;
    else {
      fprintf(stderr, "unknown option %s\n", a.c_str());
      usage();
      return 2;
    }
  }
  if (out_dir.empty()) {
    fprintf(stderr, "-o <dir> is required\n");
    return 2;
  }
  int fd = open(input.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "cannot open %s\n", input.c_str());
    return 2;
  }
  req.display_name = base_name(input);
  if (cmd == "apk") req.apk_fd = fd;
  else {
    req.lib_fd = fd;
    req.lib_name = base_name(input);
  }
  int mfd = -1;
  if (!meta_arg.empty()) {
    if (cmd == "apk") req.selected_meta = meta_arg;
    else {
      mfd = open(meta_arg.c_str(), O_RDONLY | O_CLOEXEC);
      if (mfd < 0) {
        fprintf(stderr, "cannot open %s\n", meta_arg.c_str());
        return 2;
      }
      req.meta_fd = mfd;
      req.meta_name = base_name(meta_arg);
    }
  }
  req.out_root = out_dir;
  req.temp_dir = temp;
  req.config = Json::object();
  if (!config_file.empty()) {
    std::string txt, err;
    Json j;
    if (!read_text_file(config_file, txt) || !Json::parse(txt, j, err) || !j.is_object()) {
      fprintf(stderr, "cannot read config %s%s\n", config_file.c_str(), err.empty() ? "" : (": " + err).c_str());
      return 2;
    }
    for (auto& kv : j.members()) req.config.set(kv.first, kv.second);
  }
  for (auto& kv : sets) req.config.set(kv.first, parse_value(find_setting(kv.first), kv.second));

  signal(SIGINT, on_sigint);
  RunOutcome o = run_analysis(
      req, g_cancel, [&](const std::string&, u64, u64, const std::string&) {},
      [&](const LogEntry& e) {
        if (quiet) return;
        fprintf(stderr, "[%s] %-7s %-14s %s\n", clock_hms(e.ts_ms).c_str(), level_name(e.level), e.stage.c_str(), e.msg.c_str());
      });
  close(fd);
  if (mfd >= 0) close(mfd);
  printf("%s\n", o.status_text.c_str());
  if (o.status_id == "not_started") {
    printf("причина: %s\n", o.error.c_str());
    return 3;
  }
  printf("результаты: %s\n", o.run_dir.c_str());
  return o.status_id == "success" ? 0 : (o.status_id == "cancelled" ? 130 : 1);
}
