// Thread-safe logger with UI callback and streaming file sink.
#pragma once

#include "kratos/common.h"

namespace kratos {

enum class LogLevel { Debug = 0, Info = 1, Ok = 2, Warning = 3, Error = 4 };
const char* level_name(LogLevel l);
bool parse_level(const std::string& s, LogLevel& out);

struct LogEntry {
  u64 ts_ms = 0;
  LogLevel level = LogLevel::Info;
  std::string stage;
  std::string msg;
};

class Logger {
 public:
  using Callback = std::function<void(const LogEntry&)>;

  Logger() = default;
  ~Logger();
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  void set_callback(Callback cb);
  // Opens (truncates) a log file. Entries below min_level are not written to it.
  bool open_file(const std::string& path, LogLevel min_level);
  void close_file();
  bool file_open() const;
  u64 file_bytes() const;

  void set_debug_enabled(bool v) { debug_enabled_ = v; }
  void set_verbosity(int v) { verbosity_ = v; }  // 0 short, 1 normal, 2 detailed
  int verbosity() const { return verbosity_; }
  bool debug_enabled() const { return debug_enabled_; }

  void log(LogLevel lv, const std::string& stage, const std::string& msg);
  void logf(LogLevel lv, const char* stage, const char* fmt, ...) __attribute__((format(printf, 4, 5)));

  size_t count(LogLevel lv) const;
  std::vector<LogEntry> problems(size_t max_each = 200) const;  // warnings and errors, in order

 private:
  mutable std::mutex mu_;
  Callback cb_;
  FILE* file_ = nullptr;
  LogLevel file_min_ = LogLevel::Info;
  u64 file_bytes_ = 0;
  bool debug_enabled_ = false;
  int verbosity_ = 1;
  size_t counts_[5] = {0, 0, 0, 0, 0};
  std::vector<LogEntry> warn_;
  std::vector<LogEntry> err_;
};

}  // namespace kratos
