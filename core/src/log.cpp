#include "kratos/log.h"

namespace kratos {

const char* level_name(LogLevel l) {
  switch (l) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info: return "INFO";
    case LogLevel::Ok: return "OK";
    case LogLevel::Warning: return "WARNING";
    case LogLevel::Error: return "ERROR";
  }
  return "INFO";
}

bool parse_level(const std::string& s, LogLevel& out) {
  std::string t = to_lower(s);
  if (t == "debug") out = LogLevel::Debug;
  else if (t == "info") out = LogLevel::Info;
  else if (t == "ok") out = LogLevel::Ok;
  else if (t == "warning" || t == "warn") out = LogLevel::Warning;
  else if (t == "error") out = LogLevel::Error;
  else return false;
  return true;
}

Logger::~Logger() { close_file(); }

void Logger::set_callback(Callback cb) {
  std::lock_guard<std::mutex> g(mu_);
  cb_ = std::move(cb);
}

bool Logger::open_file(const std::string& path, LogLevel min_level) {
  std::lock_guard<std::mutex> g(mu_);
  if (file_) {
    fclose(file_);
    file_ = nullptr;
  }
  file_ = fopen(path.c_str(), "wb");
  file_min_ = min_level;
  file_bytes_ = 0;
  return file_ != nullptr;
}

void Logger::close_file() {
  std::lock_guard<std::mutex> g(mu_);
  if (file_) {
    fclose(file_);
    file_ = nullptr;
  }
}

bool Logger::file_open() const {
  std::lock_guard<std::mutex> g(mu_);
  return file_ != nullptr;
}

u64 Logger::file_bytes() const {
  std::lock_guard<std::mutex> g(mu_);
  return file_bytes_;
}

void Logger::log(LogLevel lv, const std::string& stage, const std::string& msg) {
  if (lv == LogLevel::Debug && !debug_enabled_) return;
  LogEntry e;
  e.ts_ms = now_ms();
  e.level = lv;
  e.stage = stage;
  e.msg = msg;
  Callback cb;
  {
    std::lock_guard<std::mutex> g(mu_);
    counts_[(int)lv]++;
    if (lv == LogLevel::Warning && warn_.size() < 1000) warn_.push_back(e);
    if (lv == LogLevel::Error && err_.size() < 1000) err_.push_back(e);
    if (file_ && lv >= file_min_) {
      std::string line = strf("[%s] %-7s %-14s %s\n", clock_hms(e.ts_ms).c_str(), level_name(lv), stage.c_str(), msg.c_str());
      fwrite(line.data(), 1, line.size(), file_);
      file_bytes_ += line.size();
    }
    cb = cb_;
  }
  if (cb) cb(e);
}

void Logger::logf(LogLevel lv, const char* stage, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::string m = vstrf(fmt, ap);
  va_end(ap);
  log(lv, stage, m);
}

size_t Logger::count(LogLevel lv) const {
  std::lock_guard<std::mutex> g(mu_);
  return counts_[(int)lv];
}

std::vector<LogEntry> Logger::problems(size_t max_each) const {
  std::lock_guard<std::mutex> g(mu_);
  std::vector<LogEntry> out;
  for (size_t i = 0; i < warn_.size() && i < max_each; i++) out.push_back(warn_[i]);
  for (size_t i = 0; i < err_.size() && i < max_each; i++) out.push_back(err_[i]);
  std::sort(out.begin(), out.end(), [](const LogEntry& a, const LogEntry& b) { return a.ts_ms < b.ts_ms; });
  return out;
}

}  // namespace kratos
