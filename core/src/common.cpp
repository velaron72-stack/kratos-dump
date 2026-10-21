#include "kratos/common.h"

#include <chrono>
#include <ctime>

namespace kratos {

std::string vstrf(const char* fmt, va_list ap) {
  va_list ap2;
  va_copy(ap2, ap);
  char small[256];
  int n = vsnprintf(small, sizeof small, fmt, ap);
  std::string out;
  if (n < 0) {
    out = "";
  } else if ((size_t)n < sizeof small) {
    out.assign(small, (size_t)n);
  } else {
    out.resize((size_t)n + 1);
    vsnprintf(&out[0], out.size(), fmt, ap2);
    out.resize((size_t)n);
  }
  va_end(ap2);
  return out;
}

std::string strf(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::string s = vstrf(fmt, ap);
  va_end(ap);
  return s;
}

std::string hex(u64 v, int width) { return strf("%0*llx", width, (unsigned long long)v); }
std::string hex_prefixed(u64 v, int width) { return "0x" + hex(v, width); }

std::string bytes_hex(const u8* p, size_t n, char sep) {
  std::string s;
  s.reserve(n * 3);
  static const char* d = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    if (i && sep) s.push_back(sep);
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}

std::string human_size(u64 b) {
  const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  double v = (double)b;
  int i = 0;
  while (v >= 1024.0 && i < 4) {
    v /= 1024.0;
    i++;
  }
  return i == 0 ? strf("%llu B", (unsigned long long)b) : strf("%.2f %s", v, u[i]);
}

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && isspace((unsigned char)s[a])) a++;
  while (b > a && isspace((unsigned char)s[b - 1])) b--;
  return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& s, char sep, bool keep_empty) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i <= s.size()) {
    size_t j = s.find(sep, i);
    if (j == std::string::npos) j = s.size();
    std::string part = trim(s.substr(i, j - i));
    if (keep_empty || !part.empty()) out.push_back(part);
    i = j + 1;
  }
  return out;
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
  std::string o;
  for (size_t i = 0; i < v.size(); i++) {
    if (i) o += sep;
    o += v[i];
  }
  return o;
}

std::string to_lower(std::string s) {
  for (auto& c : s) c = (char)tolower((unsigned char)c);
  return s;
}
bool starts_with(const std::string& s, const std::string& p) { return s.size() >= p.size() && s.compare(0, p.size(), p) == 0; }
bool ends_with(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}
bool contains_ci(const std::string& hay, const std::string& needle) {
  if (needle.empty()) return true;
  return to_lower(hay).find(to_lower(needle)) != std::string::npos;
}

std::string base_name(const std::string& path) {
  size_t p = path.find_last_of("/\\");
  return p == std::string::npos ? path : path.substr(p + 1);
}

std::string sanitize_filename(const std::string& s) {
  std::string o;
  for (unsigned char c : s) {
    if (isalnum(c) || c == '.' || c == '-' || c == '_') o.push_back((char)c);
    else o.push_back('_');
  }
  if (o.empty() || o == "." || o == "..") o = "unnamed";
  if (o.size() > 120) o.resize(120);
  return o;
}

std::string sanitize_ident(const std::string& s) {
  std::string o;
  for (unsigned char c : s) o.push_back((isalnum(c) || c == '_') ? (char)c : '_');
  if (o.empty()) o = "_";
  if (isdigit((unsigned char)o[0])) o.insert(o.begin(), '_');
  if (o.size() > 100) o.resize(100);
  return o;
}

bool parse_u64(const std::string& in, u64& out) {
  std::string s = trim(in);
  if (s.empty()) return false;
  char* end = nullptr;
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
  errno = 0;
  unsigned long long v = strtoull(s.c_str(), &end, base);
  if (errno != 0 || end == s.c_str() || *end != '\0') return false;
  out = v;
  return true;
}

u64 now_ms() {
  return (u64)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string iso_time_utc(u64 ms) {
  time_t t = (time_t)(ms / 1000);
  struct tm tmv;
  gmtime_r(&t, &tmv);
  return strf("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min,
              tmv.tm_sec, (int)(ms % 1000));
}

std::string local_stamp_for_dir() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  return strf("%04d%02d%02d_%02d%02d%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

std::string clock_hms(u64 ms) {
  time_t t = (time_t)(ms / 1000);
  struct tm tmv;
  localtime_r(&t, &tmv);
  return strf("%02d:%02d:%02d.%03d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(ms % 1000));
}

const char* to_string(StageStatus s) {
  switch (s) {
    case StageStatus::Ok: return "ok";
    case StageStatus::Partial: return "partial";
    case StageStatus::Failed: return "failed";
    case StageStatus::Skipped: return "skipped";
    case StageStatus::Disabled: return "disabled";
    case StageStatus::Cancelled: return "cancelled";
  }
  return "?";
}

}  // namespace kratos
