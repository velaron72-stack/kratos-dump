// KRATOS DUMP core: common types and helpers.
#pragma once

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace kratos {

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

#define KRATOS_VERSION "1.0.0"

// System safety caps. These stay in force even when a user limit is 0 (= no user limit).
namespace syscap {
constexpr u64 kMaxStringLen = 1u << 20;            // 1 MiB per extracted string
constexpr u64 kMaxEntrySize = 8ull << 30;           // 8 GiB per extracted archive entry
constexpr u64 kMaxZipEntries = 5'000'000;           // central directory entries
constexpr u64 kMaxElfTables = 1u << 24;             // phdr/shdr/dyn entries
constexpr u64 kMaxTableBytes = 1ull << 30;          // single metadata table read into memory
constexpr u64 kMaxObjects = 50'000'000;             // functions / xrefs / strings in memory
constexpr u64 kDefaultMemoryMb = 1024;              // used when perf.memory_limit_mb == 0
constexpr double kMaxInflateRatio = 20000.0;        // zip-bomb guard
}  // namespace syscap

std::string strf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
std::string vstrf(const char* fmt, va_list ap);

std::string hex(u64 v, int width = 0);
std::string hex_prefixed(u64 v, int width = 0);
std::string bytes_hex(const u8* p, size_t n, char sep = ' ');
std::string human_size(u64 bytes);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep, bool keep_empty = false);
std::string join(const std::vector<std::string>& v, const std::string& sep);
std::string to_lower(std::string s);
bool starts_with(const std::string& s, const std::string& p);
bool ends_with(const std::string& s, const std::string& p);
bool contains_ci(const std::string& hay, const std::string& needle);
std::string base_name(const std::string& path);
std::string sanitize_filename(const std::string& s);
// Valid C identifier from arbitrary text (used by offsets.h).
std::string sanitize_ident(const std::string& s);
bool parse_u64(const std::string& s, u64& out);  // decimal or 0x hex; empty -> false

u64 now_ms();
std::string iso_time_utc(u64 ms);
std::string local_stamp_for_dir();  // YYYYMMDD_HHMMSS (local time)
std::string clock_hms(u64 ms);      // HH:MM:SS.mmm (local time)

// Cooperative cancellation shared by all stages.
class CancelToken {
 public:
  void cancel() { flag_.store(true, std::memory_order_relaxed); }
  bool cancelled() const { return flag_.load(std::memory_order_relaxed); }
  void reset() { flag_.store(false); }

 private:
  std::atomic<bool> flag_{false};
};

enum class StageStatus { Ok, Partial, Failed, Skipped, Disabled, Cancelled };
const char* to_string(StageStatus s);

// Tracks bytes reserved by in-memory structures against a soft budget.
class MemBudget {
 public:
  explicit MemBudget(u64 limit_bytes) : limit_(limit_bytes) {}
  bool try_reserve(u64 n) {
    u64 cur = used_.load();
    for (;;) {
      if (cur + n > limit_) return false;
      if (used_.compare_exchange_weak(cur, cur + n)) {
        u64 p = peak_.load();
        while (cur + n > p && !peak_.compare_exchange_weak(p, cur + n)) {}
        return true;
      }
    }
  }
  void release(u64 n) { used_.fetch_sub(std::min<u64>(n, used_.load())); }
  u64 used() const { return used_.load(); }
  u64 peak() const { return peak_.load(); }
  u64 limit() const { return limit_; }

 private:
  u64 limit_;
  std::atomic<u64> used_{0}, peak_{0};
};

// Little/big endian readers.
inline u16 rd16(const u8* p, bool le) { return le ? (u16)(p[0] | (p[1] << 8)) : (u16)((p[0] << 8) | p[1]); }
inline u32 rd32(const u8* p, bool le) {
  return le ? ((u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24))
            : (((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3]);
}
inline u64 rd64(const u8* p, bool le) {
  u64 a = rd32(p, le), b = rd32(p + 4, le);
  return le ? (a | (b << 32)) : ((a << 32) | b);
}

}  // namespace kratos
