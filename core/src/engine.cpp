// Run executor: preflight, result directory, stage graph (dependencies, threads, cancel, error mode), final files.
#include "kratos/engine.h"

#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <capstone/capstone.h>
#include <condition_variable>
#include <thread>
#include <zlib.h>
#include <zstd.h>

#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

struct Gate {
  StageStatus st = StageStatus::Ok;  // Ok = run the stage
  std::string reason;
};
Gate run_it() { return Gate(); }
Gate disabled(const std::string& why) { return {StageStatus::Disabled, why}; }
Gate skipped(const std::string& why) { return {StageStatus::Skipped, why}; }

struct Node {
  std::string id, title;
  int lib = -1;
  bool mandatory = false;
  bool always = false;     // runs even after cancellation or an error in "stop" mode (final reports)
  bool is_report = false;  // writes a report (delayed in "deferred" report mode)
  int cost = 1;            // 1 cheap .. 3 expensive (order in "cheap_first" mode)
  std::vector<int> hard;   // outputs are required: the node is skipped when one of these did not complete
  std::vector<int> soft;   // order only
  std::function<Gate()> gate;
  std::function<bool()> fn;
  int order = 0;
  // runtime
  int state = 0;  // 0 waiting, 1 running, 2 done
  StageStatus result = StageStatus::Skipped;
  std::string reason;  // why it did not complete (shown in chained skip messages)
};

class Graph {
 public:
  Graph(RunContext& rc, int threads, bool cheap_first, bool stop_on_error, std::atomic<int>& done, std::atomic<int>& total)
      : rc_(rc), threads_(std::max(1, threads)), cheap_first_(cheap_first), stop_on_error_(stop_on_error), done_(done), total_(total) {}

  int add(Node n) {
    n.order = next_order_++;
    nodes_.push_back(std::move(n));
    total_++;
    return (int)nodes_.size() - 1;
  }
  Node& node(int i) { return nodes_[(size_t)i]; }
  size_t size() const { return nodes_.size(); }
  void set_order_base(int b) { next_order_ = b; }
  int next_order() const { return next_order_; }

  void run() {
    order_.clear();
    for (size_t i = 0; i < nodes_.size(); i++) order_.push_back((int)i);
    if (cheap_first_) std::stable_sort(order_.begin(), order_.end(), [&](int a, int b) { return nodes_[(size_t)a].cost < nodes_[(size_t)b].cost; });
    std::vector<std::thread> pool;
    for (int i = 1; i < threads_; i++) pool.emplace_back([this]() {
      if (rc_.cfg.b("perf.low_priority")) setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), 10);
      loop();
    });
    loop();
    for (auto& t : pool) t.join();
  }

 private:
  bool deps_done(const Node& n) const {
    for (int d : n.hard)
      if (nodes_[(size_t)d].state != 2) return false;
    for (int d : n.soft)
      if (nodes_[(size_t)d].state != 2) return false;
    return true;
  }

  // Decides whether a ready node is resolved without running. Lock held.
  bool resolve_without_running(Node& n, StageStatus& st, std::string& why) {
    if (!n.always) {
      if (rc_.cancel->cancelled()) {
        st = StageStatus::Cancelled;
        why = "отменено пользователем";
        return true;
      }
      if (stopped_) {
        st = StageStatus::Skipped;
        why = "остановлено после ошибки этапа «" + stop_stage_ + "» (режим «остановиться»)";
        return true;
      }
      for (int d : n.hard) {
        const Node& dn = nodes_[(size_t)d];
        if (dn.result == StageStatus::Failed || dn.result == StageStatus::Skipped || dn.result == StageStatus::Cancelled) {
          st = StageStatus::Skipped;
          if (starts_with(dn.reason, "нужен результат этапа")) why = dn.reason;  // keep the root cause, not a chain of prefixes
          else why = "нужен результат этапа «" + dn.title + "», он не выполнен" + (dn.reason.empty() ? std::string() : ": " + dn.reason);
          return true;
        }
      }
    }
    return false;
  }

  void finish_locked(Node& n, StageStatus st, const std::string& why) {
    StageRec rec;
    rec.id = n.id;
    rec.title = n.title;
    rec.mandatory = n.mandatory;
    rec.lib = n.lib;
    rec.order = n.order;
    rec.status = st;
    rec.reason = why;
    rc_.ledger.add_stage(rec);
    n.result = st;
    n.reason = why;
    n.state = 2;
    int d = ++done_;
    rc_.prog("run", (u64)d, (u64)total_.load(), n.title + ": " + to_string(st));
  }

  int pick_locked() {
    bool changed;
    do {
      changed = false;
      for (int idx : order_) {
        Node& n = nodes_[(size_t)idx];
        if (n.state != 0 || !deps_done(n)) continue;
        StageStatus st;
        std::string why;
        if (resolve_without_running(n, st, why)) {
          finish_locked(n, st, why);
          changed = true;
          continue;
        }
        return idx;
      }
    } while (changed);
    return -1;
  }

  bool all_done_locked() const {
    for (auto& n : nodes_)
      if (n.state != 2) return false;
    return true;
  }

  void loop() {
    for (;;) {
      int idx;
      {
        std::unique_lock<std::mutex> lk(mu_);
        for (;;) {
          idx = pick_locked();
          if (idx >= 0) break;
          if (all_done_locked()) {
            cv_.notify_all();
            return;
          }
          if (running_ == 0) {  // nothing can run and nothing is running: dependency cycle (a programming error)
            for (auto& n : nodes_)
              if (n.state == 0) finish_locked(n, StageStatus::Skipped, "внутренняя ошибка: цикл зависимостей этапов");
            cv_.notify_all();
            return;
          }
          cv_.wait(lk);
        }
        nodes_[(size_t)idx].state = 1;
        running_++;
      }
      execute(idx);
      {
        std::lock_guard<std::mutex> lk(mu_);
        running_--;
        Node& n = nodes_[(size_t)idx];
        n.state = 2;
        if (n.result == StageStatus::Failed && stop_on_error_ && !stopped_) {
          stopped_ = true;
          stop_stage_ = n.title;
        }
        int d = ++done_;
        rc_.prog("run", (u64)d, (u64)total_.load(), n.title + ": " + to_string(n.result));
        cv_.notify_all();
      }
    }
  }

  void execute(int idx) {
    Node& n = nodes_[(size_t)idx];
    StageRec rec;
    rec.id = n.id;
    rec.title = n.title;
    rec.mandatory = n.mandatory;
    rec.lib = n.lib;
    rec.order = n.order;
    Gate g = n.gate ? n.gate() : run_it();
    if (g.st != StageStatus::Ok) {
      rec.status = g.st;
      rec.reason = g.reason;
      rc_.ledger.add_stage(rec);
      n.result = g.st;
      n.reason = g.reason;
      rc_.log->log(LogLevel::Info, n.id, n.title + ": " + std::string(g.st == StageStatus::Disabled ? "отключён" : "пропущен") + " — " + g.reason);
      return;
    }
    rec.status = StageStatus::Ok;
    size_t errs_before;
    {
      std::lock_guard<std::mutex> lk(rc_.mu);
      errs_before = rc_.errors.size();
    }
    rc_.log->log(LogLevel::Info, n.id, n.title);
    rc_.prog(n.id, 0, 0, n.title);
    const u64 t0 = now_ms();
    bool ok = false;
    std::string exc;
    {
      StageScope scope(&rec);
      try {
        ok = n.fn();
      } catch (const std::bad_alloc&) {
        exc = "недостаточно памяти";
      } catch (const std::exception& e) {
        exc = e.what();
      } catch (...) {
        exc = "неизвестное исключение";
      }
    }
    rec.ms = now_ms() - t0;
    if (!exc.empty()) {
      ok = false;
      rc_.error(n.id, "исключение в этапе: " + exc);
      rec.reason = exc;
    }
    if (!ok) {
      if (rc_.cancel->cancelled() && exc.empty()) {
        rec.status = StageStatus::Cancelled;
        if (rec.reason.empty()) rec.reason = "отменено пользователем";
      } else {
        rec.status = StageStatus::Failed;
        if (rec.reason.empty()) {
          std::lock_guard<std::mutex> lk(rc_.mu);
          if (rc_.errors.size() > errs_before) rec.reason = rc_.errors.back();
          else rec.reason = "см. журнал";
        }
      }
    }
    LogLevel lv = rec.status == StageStatus::Ok ? LogLevel::Ok : (rec.status == StageStatus::Partial ? LogLevel::Warning : (rec.status == StageStatus::Failed ? LogLevel::Error : LogLevel::Warning));
    rc_.log->log(lv, n.id, strf("%s: %s (%llu мс)%s%s", n.title.c_str(), to_string(rec.status), (unsigned long long)rec.ms, rec.reason.empty() ? "" : " — ", rec.reason.c_str()));
    rc_.ledger.add_stage(rec);
    n.result = rec.status;
    n.reason = rec.reason;
  }

  RunContext& rc_;
  int threads_;
  bool cheap_first_, stop_on_error_;
  std::atomic<int>& done_;
  std::atomic<int>& total_;
  std::vector<Node> nodes_;
  std::vector<int> order_;
  std::mutex mu_;
  std::condition_variable cv_;
  int running_ = 0;
  bool stopped_ = false;
  std::string stop_stage_;
  int next_order_ = 0;
};

// ---------------------------------------------------------------- helpers
std::string strip_ext(const std::string& n) {
  size_t d = n.rfind('.');
  if (d == std::string::npos || d == 0 || n.size() - d > 6) return n;
  return n.substr(0, d);
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
  size_t p = 0;
  while ((p = s.find(from, p)) != std::string::npos) {
    s.replace(p, from.size(), to);
    p += to.size();
  }
  return s;
}

std::string make_run_name(const Config& cfg, const RunRequest& req) {
  std::string tpl = cfg.s("out.name_template");
  if (trim(tpl).empty()) tpl = "{name}_{date}_{time}";
  std::string stamp = local_stamp_for_dir();  // YYYYMMDD_HHMMSS
  std::string date = stamp.substr(0, 8), tm = stamp.size() >= 15 ? stamp.substr(9, 6) : "000000";
  std::string base = strip_ext(base_name(req.display_name.empty() ? "run" : req.display_name));
  std::string s = replace_all(tpl, "{name}", sanitize_filename(base));
  s = replace_all(s, "{date}", date);
  s = replace_all(s, "{time}", tm);
  s = replace_all(s, "{profile}", sanitize_filename(req.profile_id));
  s = sanitize_filename(s);
  if (s.empty()) s = "run";
  if (s.size() > 120) s.resize(120);
  return s;
}

RunOutcome not_started(const std::string& why) {
  RunOutcome o;
  o.status_id = "not_started";
  o.status_text = "Не запущено";
  o.error = why;
  return o;
}

// Restores the thread priority on exit.
struct PriorityGuard {
  bool active = false;
  int old = 0;
  explicit PriorityGuard(bool low) {
    if (!low) return;
    id_t tid = (id_t)syscall(SYS_gettid);
    errno = 0;
    old = getpriority(PRIO_PROCESS, tid);
    if (errno == 0 && setpriority(PRIO_PROCESS, tid, 10) == 0) active = true;
  }
  ~PriorityGuard() {
    if (active) setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), old);
  }
};

bool arch_allowed(const Config& cfg, Arch a) {
  std::string n = arch_name(a);
  if (n != "arm64" && n != "arm" && n != "x86_64" && n != "x86") n = "other";
  return cfg.flag("lib.architectures", n);
}

}  // namespace

RunOutcome run_analysis(const RunRequest& req_in, CancelToken& cancel, ProgressFn progress, Logger::Callback log_cb) {
  RunOutcome outcome;
  try {
    // ------------------------------------------------------------ configuration
    RunRequest req = req_in;
    const std::string requested_profile = req.profile_id;
    if (!find_profile(req.profile_id)) req.profile_id = "standard";
    Json eff = profile_values(req.profile_id);
    if (req.config.is_object())
      for (auto& kv : req.config.members()) eff.set(kv.first, kv.second);
    std::vector<ConfigIssue> issues;
    Config cfg = Config::from_json(eff, &issues);
    cfg.clear_touched();

    // ------------------------------------------------------------ preflight
    if (req.mode != "apk" && req.mode != "lib") return not_started("неизвестный режим запуска: " + req.mode);
    if (req.mode == "apk" && req.apk_fd < 0) return not_started("не выбран файл APK");
    if (req.mode == "lib" && req.lib_fd < 0) return not_started("не выбран файл библиотеки");
    if (req.out_root.empty()) return not_started("не выбрана папка для результатов");
    const std::string root = path_join(req.out_root, "android_dump");
    if (!mkdirs(root)) return not_started("не удаётся создать папку результатов: " + root);
    {
      std::string werr;
      if (!dir_writable(root, werr)) return not_started("в папку результатов нельзя писать: " + werr);
    }
    u64 in_size = 0;
    {
      int fd = req.mode == "apk" ? req.apk_fd : req.lib_fd;
      FdSource probe(fd, false);
      in_size = probe.size();
    }
    {
      u64 avail = 0;
      u64 need = 16ull << 20;
      if (req.mode == "apk" && cfg.b("apk.copy_source")) need += in_size;
      if (free_space_of(root, avail) && avail < need)
        return not_started(strf("недостаточно свободного места: доступно %s, нужно не менее %s", human_size(avail).c_str(), human_size(need).c_str()));
    }

    // ------------------------------------------------------------ run directory
    const std::string run_name = make_run_name(cfg, req);
    std::string run_dir = path_join(root, run_name);
    if (path_exists(run_dir)) {
      if (cfg.s("out.overwrite") == "overwrite") {
        if (!remove_tree(run_dir)) return not_started("не удаётся заменить существующий каталог результатов: " + run_dir);
      } else {
        run_dir = unique_path(run_dir);
      }
    }
    for (const char* d : {"", "source", "libraries", "metadata", "reports", "logs"})
      if (!mkdirs(path_join(run_dir, d))) {
        remove_tree(run_dir);
        return not_started(std::string("не удаётся создать каталог ") + path_join(run_dir, d));
      }

    // ------------------------------------------------------------ context
    Logger log;
    log.set_verbosity(cfg.s("console.verbosity") == "short" ? 0 : (cfg.s("console.verbosity") == "detailed" ? 2 : 1));
    const bool want_debug = cfg.b("console.debug");
    const bool want_alog = cfg.b("out.analysis_log");
    log.set_debug_enabled(want_debug || want_alog);

    RunContext rc;
    rc.req = req;
    rc.cfg = cfg;
    rc.log = &log;
    rc.cancel = &cancel;
    rc.progress = progress;
    rc.run_name = run_name;
    rc.run_dir = run_dir;
    rc.src_dir = path_join(run_dir, "source");
    rc.libs_dir = path_join(run_dir, "libraries");
    rc.meta_dir = path_join(run_dir, "metadata");
    rc.reports_root = path_join(run_dir, "reports");
    rc.logs_dir = path_join(run_dir, "logs");
    rc.started_ms = now_ms();
    rc.input_size = in_size;
    const u64 mem_mb = cfg.limit("perf.memory_limit_mb");
    rc.mem.reset(new MemBudget((mem_mb ? mem_mb : syscap::kDefaultMemoryMb) * 1048576ull));
    bool own_temp = false;
    std::string temp_err;
    if (rc.req.temp_dir.empty() || !dir_writable(rc.req.temp_dir, temp_err)) {
      rc.req.temp_dir = path_join(run_dir, ".tmp");
      mkdirs(rc.req.temp_dir);
      own_temp = true;
    }
    PriorityGuard prio(cfg.b("perf.low_priority"));

    // Log sinks: UI callback, run.log, analysis_log.txt.
    std::unique_ptr<ReportFile> alog;
    std::mutex alog_mu;
    if (want_alog) {
      alog.reset(new ReportFile(rc, -1, "analysis_log.txt", rc.reports_root, "reports", 0));
      if (alog->ok()) alog->header("журнал анализа", nullptr);
      else {
        report_failed(rc, -1, "analysis_log.txt", alog->create_error());
        alog.reset();
      }
    }
    log.set_callback([&](const LogEntry& e) {
      if (log_cb && (e.level != LogLevel::Debug || want_debug)) log_cb(e);
      if (alog) {
        std::lock_guard<std::mutex> g(alog_mu);
        alog->f().line(strf("[%s] %-7s %-14s %s", clock_hms(e.ts_ms).c_str(), level_name(e.level), e.stage.c_str(), e.msg.c_str()));
      }
    });
    if (cfg.b("console.save_full_log")) log.open_file(path_join(rc.logs_dir, "run.log"), want_debug || want_alog ? LogLevel::Debug : LogLevel::Info);

    log.log(LogLevel::Info, "run", strf("KRATOS DUMP %s: %s, профиль «%s»", KRATOS_VERSION, req.mode == "apk" ? "анализ APK" : "анализ библиотеки", req.profile_id.c_str()));
    log.log(LogLevel::Info, "run", "результаты: " + run_dir);
    for (auto& is : issues) rc.warn("config", is.key + ": " + is.message);
    if (requested_profile != req.profile_id) rc.warn("config", "профиль «" + requested_profile + "» неизвестен: использован «standard»");
    {
      u64 avail = 0;
      if (free_space_of(root, avail) && avail < in_size + (16ull << 20)) rc.warn("run", strf("свободного места мало (%s): результаты могут не поместиться", human_size(avail).c_str()));
    }

    // ------------------------------------------------------------ graph
    int threads = (int)cfg.i("perf.threads");
    if (threads <= 0) threads = (int)std::max(1u, std::min(4u, std::thread::hardware_concurrency()));
    const bool cheap_first = cfg.s("general.stage_order") == "cheap_first";
    const bool stop_mode = cfg.s("general.error_mode") == "stop";
    const bool deferred = cfg.s("general.report_mode") == "deferred";
    const int depth = (int)cfg.i("general.depth");
    std::atomic<int> done{0}, total{0};
    int order_counter = 0;
    const bool apk_mode = req.mode == "apk";
    auto depth_gate = [depth](int need) { return depth >= need ? run_it() : skipped(strf("глубина анализа %d меньше требуемой %d", depth, need)); };

    // ---- phase 1: input, archive, metadata, extraction ----
    {
      Graph g(rc, threads, cheap_first, stop_mode, done, total);
      g.set_order_base(order_counter);
      Node in;
      in.id = "input";
      in.title = apk_mode ? "Открытие APK" : "Открытие библиотеки";
      in.mandatory = true;
      in.fn = [&]() -> bool {
        mkdirs(rc.meta_dir);
        std::string err;
        if (apk_mode) {
          rc.apk_src = std::make_shared<FdSource>(::dup(req.apk_fd), true);
          rc.input_size = rc.apk_src->size();
          if (rc.input_size == 0) {
            rc.error("input", "файл APK пуст или недоступен для чтения");
            return false;
          }
          if (cfg.b("general.verify_input")) {
            const bool sha = cfg.flag("expert.input_hashes", "sha256"), crc = cfg.flag("expert.input_hashes", "crc32");
            if ((sha || crc) && !hash_source(*rc.apk_src, sha, crc, &cancel, rc.input_sha256, rc.input_crc32)) {
              if (cancel.cancelled()) return false;
              rc.warn("input", "контрольные суммы APK не посчитаны (ошибка чтения)");
              stage_partial("контрольные суммы недоступны");
            }
          }
          if (cfg.b("apk.copy_source")) {
            std::string fn = sanitize_filename(base_name(req.display_name.empty() ? "source.apk" : req.display_name));
            std::string dst = unique_path(path_join(rc.src_dir, fn));
            u64 copied = 0;
            rc.prog("input", 0, rc.input_size, "копирование исходного APK");
            if (!copy_fd_to_file(req.apk_fd, dst, &cancel, &copied, err)) {
              if (cancel.cancelled()) return false;
              rc.error("input", "не удалось скопировать исходный APK: " + err);
              report_failed(rc, -1, fn, err);
              stage_partial("копия APK не создана");
            } else {
              FileRec fr;
              fr.name = fn;
              fr.rel_path = "source/" + base_name(dst);
              fr.bytes = copied;
              rc.ledger.add_file(fr);
            }
          }
          return true;
        }
        // standalone library
        auto lc = std::make_unique<LibContext>();
        lc->index = 0;
        lc->from_apk = false;
        lc->entry_name = req.lib_name.empty() ? "library.so" : base_name(req.lib_name);
        lc->display = lc->entry_name;
        lc->id = sanitize_filename(lc->entry_name);
        lc->ledger = &rc.ledger;
        lc->reports_dir = path_join(rc.reports_root, lc->id);
        lc->rel_reports = path_join("reports", lc->id);
        if (cfg.b("apk.extract_libraries")) {
          std::string dst = unique_path(path_join(rc.libs_dir, sanitize_filename(lc->entry_name)));
          u64 copied = 0;
          if (!copy_fd_to_file(req.lib_fd, dst, &cancel, &copied, err)) {
            if (cancel.cancelled()) return false;
            rc.error("input", "не удалось прочитать библиотеку: " + err);
            return false;
          }
          auto fs = FdSource::open_path(dst, err);
          if (!fs) {
            rc.error("input", err);
            return false;
          }
          lc->local_path = dst;
          lc->src = std::shared_ptr<ByteSource>(fs.release());
          FileRec fr;
          fr.name = base_name(dst);
          fr.rel_path = "libraries/" + base_name(dst);
          fr.bytes = copied;
          rc.ledger.add_file(fr);
        } else {
          lc->src = std::make_shared<FdSource>(::dup(req.lib_fd), true);
        }
        lc->size = lc->src->size();
        lc->extracted_ok = true;
        rc.input_size = lc->size;
        rc.libs.push_back(std::move(lc));
        return true;
      };
      int n_in = g.add(std::move(in));

      int n_scan = -1;
      if (apk_mode) {
        Node sc;
        sc.id = "apk_scan";
        sc.title = "Структура APK";
        sc.mandatory = true;
        sc.hard = {n_in};
        sc.cost = 2;
        sc.fn = [&]() { return stage_apk_scan(rc); };
        n_scan = g.add(std::move(sc));

        Node fl;
        fl.id = "apk_files";
        fl.title = "Список файлов APK";
        fl.hard = {n_scan};
        fl.is_report = true;
        fl.gate = [&]() { return cfg.b("apk.save_file_list") ? run_it() : disabled("список файлов отключён в настройках"); };
        fl.fn = [&]() -> bool {
          if (!rc.zip) return true;
          ReportFile rf(rc, -1, "apk_files.txt", rc.src_dir, "source", 0);
          if (!rf.ok()) {
            report_failed(rc, -1, "apk_files.txt", rf.create_error());
            stage_partial("apk_files.txt не создан");
            return true;
          }
          rf.header("список записей архива", nullptr);
          OutFile& f = rf.f();
          f.line(strf("%-10s %-12s %-12s %-9s %-8s %s", "метод", "размер", "в архиве", "CRC32", "флаги", "имя"));
          for (auto& e : rc.zip->entries()) {
            if (!f.object()) break;
            std::string flags;
            if (e.recovered) flags += "R";
            if (e.duplicate) flags += "D";
            if (e.encrypted) flags += "E";
            if (!e.data_ok) flags += "!";
            f.line(strf("%-10s %-12llu %-12llu %08x  %-8s %s", zip_method_name(e.method), (unsigned long long)e.uncomp_size, (unsigned long long)e.comp_size, e.crc, flags.c_str(),
                        e.name.c_str()));
          }
          f.line("");
          f.line("# флаги: R — запись восстановлена по локальному заголовку, D — повтор имени, E — зашифрована, ! — данные за пределами архива");
          if (!rc.apk.nested_apks.empty()) f.line("# вложенные APK (не перечислены): " + join(rc.apk.nested_apks, ", "));
          close_report(rc, rf);
          return true;
        };
        g.add(std::move(fl));
      }

      Node md;
      md.id = "metadata";
      md.title = "Метаданные";
      md.mandatory = cfg.b("meta.require");
      md.cost = 2;
      if (apk_mode && req.meta_fd < 0) md.hard = {n_scan};
      else if (apk_mode) md.soft = {n_scan};
      else md.soft = {n_in};
      md.gate = [&]() -> Gate {
        if (req.meta_fd >= 0) return run_it();  // a file picked by hand always wins
        if (!apk_mode) return disabled("файл метаданных не указан");
        if (req.selected_meta == "none") return disabled("выбрано: анализ без метаданных");
        if (req.selected_meta.empty() && !cfg.b("meta.auto_find")) return disabled("автоматический поиск метаданных выключен");
        return run_it();
      };
      md.fn = [&]() {
          return stage_metadata(rc);
      };
      int n_meta = g.add(std::move(md));
      (void)n_meta;

      if (apk_mode) {
        Node ex;
        ex.id = "extract";
        ex.title = "Выбор и извлечение библиотек";
        ex.mandatory = true;
        ex.hard = {n_scan};
        ex.cost = 2;
        ex.fn = [&]() { return stage_select_extract(rc); };
        g.add(std::move(ex));
      }
      g.run();
      order_counter = g.next_order();
    }

    // ---- phase 2: libraries and final reports ----
    {
      Graph g(rc, threads, cheap_first, stop_mode, done, total);
      g.set_order_base(order_counter);
      std::vector<int> analysis_nodes, elf_nodes;
      std::vector<int> report_nodes;
      for (auto& lp : rc.libs) {
        LibContext* lc = lp.get();
        auto add = [&](const std::string& id, const std::string& title, int cost, bool mandatory, bool is_report, std::vector<int> hard, std::vector<int> soft,
                       std::function<Gate()> gate, std::function<bool()> fn) {
          Node n;
          n.id = id;
          n.title = title;
          n.lib = lc->index;
          n.cost = cost;
          n.mandatory = mandatory;
          n.is_report = is_report;
          n.hard = std::move(hard);
          n.soft = std::move(soft);
          n.gate = std::move(gate);
          n.fn = std::move(fn);
          int i = g.add(std::move(n));
          (is_report ? report_nodes : analysis_nodes).push_back(i);
          return i;
        };
        const bool lib_input_is_apk = lc->from_apk;
        int n_input = add("lib_input", "Проверка файла библиотеки", 1, true, false, {}, {}, nullptr, [&, lc, lib_input_is_apk]() -> bool {
          if (!mkdirs(lc->reports_dir)) {
            rc.error("input", "не удаётся создать каталог отчётов " + lc->reports_dir);
            return false;
          }
          bool ok = stage_lib_input(rc, *lc);
          if (!lib_input_is_apk) {
            rc.input_sha256 = lc->sha256;
            rc.input_crc32 = lc->crc32_hex;
          }
          return ok;
        });
        int n_elf = add("elf", "Разбор ELF", 1, true, false, {n_input}, {}, nullptr, [&, lc]() { return stage_elf(rc, *lc); });
        elf_nodes.push_back(n_elf);
        auto code_gate = [&, lc](int need) -> Gate {
          Gate d = depth_gate(need);
          if (d.st != StageStatus::Ok) return d;
          if (!lc->elf_ok) return skipped("библиотека не разобрана как ELF");
          if (!arch_allowed(rc.cfg, lc->elf.arch)) return skipped(std::string("архитектура ") + arch_name(lc->elf.arch) + " исключена настройкой «Поддерживаемые архитектуры»");
          return run_it();
        };
        int n_elfio = add("elfio", "Перекрёстная проверка ELFIO", 2, false, false, {n_elf}, {},
                          [&, lc]() -> Gate {
                            if (!cfg.b("lib.cross_check_elfio")) return disabled("проверка отключена в настройках");
                            if (!lc->elf_ok) return skipped("библиотека не разобрана как ELF");
                            return run_it();
                          },
                          [&, lc]() { return stage_elfio_check(rc, *lc); });
        (void)n_elfio;
        int n_prot = add("protection", "Признаки защиты и упаковки", 2, false, false, {}, {n_elf},
                         [&]() -> Gate { return cfg.b("prot.detect") ? run_it() : disabled("выявление защиты отключено в настройках"); }, [&, lc]() { return stage_protection(rc, *lc); });
        (void)n_prot;
        int n_str = add("strings", "Строки", 2, false, false, {}, {n_elf},
                        [&, lc]() -> Gate {
                          Gate d = depth_gate(2);
                          if (d.st != StageStatus::Ok) return d;
                          const bool idx = cfg.flag("xref.types", "string") && depth >= 4;
                          if (!cfg.b("out.strings") && !idx) return disabled("отчёт strings.txt выключен и ссылки на строки не нужны");
                          return run_it();
                        },
                        [&, lc]() { return stage_strings(rc, *lc); });
        int n_fs = add("functions_static", "Функции: символы и таблицы", 2, false, false, {n_elf}, {}, [&, lc, code_gate]() { return code_gate(3); },
                       [&, lc]() { return stage_functions_static(rc, *lc); });
        int n_unk = add("unknown_structures", "Неизвестные структуры", 3, false, false, {n_fs}, {},
                        [&, lc, code_gate]() -> Gate {
                          if (!cfg.b("lib.unknown_structures")) return disabled("поиск неизвестных структур отключён в настройках");
                          return code_gate(4);
                        },
                        [&, lc]() { return stage_unknown_structures(rc, *lc); });
        int n_cs = add("codescan", "Просмотр кода", 3, false, false, {n_fs}, {n_str, n_unk}, [&, lc, code_gate]() { return code_gate(3); }, [&, lc]() { return stage_codescan(rc, *lc); });
        int n_ff = add("functions_final", "Функции: итог", 2, false, false, {n_fs}, {n_cs, n_unk}, [&, lc, code_gate]() { return code_gate(3); },
                       [&, lc]() { return stage_functions_final(rc, *lc); });

        // imports.txt shows the PLT stub of each import, which the code scan finds: wait for it so the report does not depend on timing.
        add("rep_structure", "Отчёты: секции, сегменты, релокации, импорт, экспорт", 1, false, true, {n_elf}, {n_cs}, nullptr, [&, lc]() { return stage_report_structure(rc, *lc); });
        add("rep_functions", "Отчёты: functions, methods, offsets", 1, false, true, {n_ff}, {},
            [&, lc, code_gate]() -> Gate {
              if (!cfg.b("out.functions") && !cfg.b("out.methods") && !cfg.b("out.offsets")) return disabled("все три отчёта выключены");
              return code_gate(3);
            },
            [&, lc]() { return stage_report_functions(rc, *lc); });
        add("rep_disasm", "Дизассемблирование", 3, false, true, {n_ff}, {},
            [&, lc, code_gate]() -> Gate {
              if (!cfg.b("out.disassembly")) return disabled("отчёт disassembly.txt выключен");
              return code_gate(3);
            },
            [&, lc]() { return stage_report_disasm(rc, *lc); });
        add("rep_xrefs", "Перекрёстные ссылки", 2, false, true, {n_ff}, {},
            [&, lc, code_gate]() -> Gate {
              if (!cfg.b("out.cross_references")) return disabled("отчёт cross_references.txt выключен");
              return code_gate(4);
            },
            [&, lc]() { return stage_report_xrefs(rc, *lc); });
        add("rep_hex", "Hex-дамп", 2, false, true, {}, {n_elf},
            [&]() -> Gate { return cfg.b("out.hex_dump") ? run_it() : disabled("отчёт hex_dump.txt выключен"); }, [&, lc]() { return stage_report_hex(rc, *lc); });
        add("dynamic", "Динамический модуль (карта памяти)", 1, false, false, {}, {n_ff},
            [&, lc]() -> Gate {
              if (!cfg.b("dyn.enabled")) return disabled("динамический модуль отключён в настройках");
              if (!lc->elf_ok) return skipped("библиотека не разобрана как ELF");
              return run_it();
            },
            [&, lc]() { return stage_dynamic(rc, *lc); });
      }

      // run-level reports
      {
        Node n;
        n.id = "metadata_report";
        n.title = "Отчёт о метаданных";
        n.is_report = true;
        n.soft = elf_nodes;
        n.cost = 2;
        n.gate = [&]() -> Gate {
          if (!cfg.b("out.metadata_report")) return disabled("отчёт metadata_report.txt выключен");
          if (!rc.meta.found) return skipped(rc.meta.probed ? "метаданные не найдены" : "метаданные не анализировались: этап отключён или файл не указан");
          return run_it();
        };
        n.fn = [&]() { return stage_metadata_report(rc); };
        report_nodes.push_back(g.add(std::move(n)));
      }
      std::vector<int> all_before;
      for (size_t i = 0; i < g.size(); i++) all_before.push_back((int)i);
      if (deferred) {
        // Reports are written after every analysis stage of every library.
        for (int r : report_nodes) {
          Node& rn = g.node(r);
          for (int a : analysis_nodes) rn.soft.push_back(a);
        }
      }
      {
        Node n;
        n.id = "dump";
        n.title = "Общий отчёт dump.txt";
        n.mandatory = true;
        n.always = true;
        n.is_report = true;
        n.soft = all_before;
        n.gate = [&]() -> Gate { return cfg.b("out.dump") ? run_it() : disabled("отчёт dump.txt выключен"); };
        n.fn = [&]() { return stage_report_dump(rc); };
        g.add(std::move(n));
      }
      {
        Node n;
        n.id = "completeness";
        n.title = "Отчёт о полноте";
        n.always = true;
        n.is_report = true;
        n.soft = all_before;
        n.gate = [&]() -> Gate {
          if (!cfg.b("out.completeness") || !cfg.b("prot.completeness_report")) return disabled("отдельный отчёт о полноте выключен");
          return run_it();
        };
        n.fn = [&]() { return stage_report_completeness(rc); };
        g.add(std::move(n));
      }
      g.run();
      order_counter = g.next_order();
    }

    // ------------------------------------------------------------ finalize
    StatusInfo st = compute_status(rc);
    log.log(st.id == "success" ? LogLevel::Ok : (st.id == "cancelled" ? LogLevel::Warning : LogLevel::Error), "run", "итог: " + st.text);
    if (alog) {
      std::lock_guard<std::mutex> g(alog_mu);
      close_report(rc, *alog);
      alog.reset();
    }
    // Scratch files.
    for (auto& t : rc.temp_files) remove_file(t);
    rc.nested_zips.clear();
    if (own_temp) remove_tree(rc.req.temp_dir);

    if (cfg.b("expert.diagnostics")) {
      std::string txt = "KRATOS DUMP " KRATOS_VERSION " — диагностика запуска\n";
      txt += strf("потоков: %d; память: пик учтённых структур %s из %s\n", threads, human_size(rc.mem->peak()).c_str(), human_size(rc.mem->limit()).c_str());
      auto stages = rc.ledger.stages();
      std::stable_sort(stages.begin(), stages.end(), [](const StageRec& a, const StageRec& b) { return a.order < b.order; });
      txt += "\nэтапы:\n";
      for (auto& s : stages) txt += strf("  %-44s %-9s %7llu мс  lib=%d\n", s.title.c_str(), to_string(s.status), (unsigned long long)s.ms, s.lib);
      txt += "\nпараметры, изменённые относительно профиля:\n";
      for (auto& k : cfg.diff_from(rc.req.profile_id)) txt += "  " + k + "\n";
      txt += "\nпараметры, прочитанные движком:\n";
      // The stage graph reads the local copy and the stages read the one in the run context: report both.
      std::set<std::string> read_keys = cfg.touched();
      for (auto& k : rc.cfg.touched()) read_keys.insert(k);
      for (auto& k : read_keys) txt += "  " + k + "\n";
      int maj = 0, mn = 0;
      cs_version(&maj, &mn);
      txt += strf("\nCapstone %d.%d; zlib %s; zstd %s\n", maj, mn, zlibVersion(), ZSTD_versionString());
      std::string err;
      if (write_text_retry(rc, path_join(rc.logs_dir, "diagnostics.txt"), txt, err)) {
        FileRec fr;
        fr.name = "diagnostics.txt";
        fr.rel_path = "logs/diagnostics.txt";
        fr.bytes = txt.size();
        rc.ledger.add_file(fr);
      } else {
        report_failed(rc, -1, "diagnostics.txt", err);
        st = compute_status(rc);
      }
    }
    if (cfg.b("console.save_full_log") && log.file_open()) {
      FileRec fr;
      fr.name = "run.log";
      fr.rel_path = "logs/run.log";
      fr.bytes = log.file_bytes();
      rc.ledger.add_file(fr);
    }

    const std::string summary_path = path_join(run_dir, "summary.json");
    Json summary = build_summary(rc, st);
    std::string werr;
    bool wrote = write_text_retry(rc, summary_path, summary.dump(2), werr);
    if (!wrote) {
      rc.error("summary", "summary.json не записан: " + werr);
      FileRec fr;
      fr.name = "summary.json";
      fr.ok = false;
      fr.error = werr;
      fr.mandatory = true;
      rc.ledger.add_file(fr);
      st = compute_status(rc);
      summary = build_summary(rc, st);
    }
    log.close_file();

    outcome.status_id = st.id;
    outcome.status_text = st.text;
    outcome.run_dir = run_dir;
    outcome.summary_path = wrote ? summary_path : "";
    outcome.summary = summary;
    if (st.id != "success" && !cfg.b("out.partial_results")) {
      remove_tree(run_dir);
      outcome.run_dir.clear();
      outcome.summary_path.clear();
    }
    return outcome;
  } catch (const std::exception& e) {
    RunOutcome o = not_started(std::string("внутренняя ошибка: ") + e.what());
    return o;
  } catch (...) {
    return not_started("внутренняя ошибка");
  }
}

}  // namespace kratos
