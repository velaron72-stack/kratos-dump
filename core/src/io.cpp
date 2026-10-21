#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "kratos/io.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>

#include <zlib.h>

namespace kratos {

// ---------------- SHA-256 ----------------
static const u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline u32 ror(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

Sha256::Sha256() {
  static const u32 init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(h_, init, sizeof h_);
}

void Sha256::block(const u8* p) {
  u32 w[64];
  for (int i = 0; i < 16; i++) w[i] = ((u32)p[i * 4] << 24) | ((u32)p[i * 4 + 1] << 16) | ((u32)p[i * 4 + 2] << 8) | p[i * 4 + 3];
  for (int i = 16; i < 64; i++) {
    u32 s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
    u32 s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; i++) {
    u32 S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    u32 ch = (e & f) ^ (~e & g);
    u32 t1 = h + S1 + ch + K256[i] + w[i];
    u32 S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    u32 mj = (a & b) ^ (a & c) ^ (b & c);
    u32 t2 = S0 + mj;
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const void* data, size_t n) {
  const u8* p = (const u8*)data;
  total_ += n;
  if (buf_len_) {
    size_t take = std::min(n, 64 - buf_len_);
    memcpy(buf_ + buf_len_, p, take);
    buf_len_ += take;
    p += take;
    n -= take;
    if (buf_len_ == 64) {
      block(buf_);
      buf_len_ = 0;
    }
  }
  while (n >= 64) {
    block(p);
    p += 64;
    n -= 64;
  }
  if (n) {
    memcpy(buf_, p, n);
    buf_len_ = n;
  }
}

std::string Sha256::finish_hex() {
  u64 bits = total_ * 8;
  u8 pad = 0x80;
  update(&pad, 1);
  u8 z = 0;
  while (buf_len_ != 56) update(&z, 1);
  u8 len[8];
  for (int i = 0; i < 8; i++) len[i] = (u8)(bits >> (56 - 8 * i));
  update(len, 8);
  std::string out;
  for (int i = 0; i < 8; i++) out += strf("%08x", h_[i]);
  return out;
}

u32 crc32_update(u32 crc, const void* data, size_t n) {
  const u8* p = (const u8*)data;
  while (n) {
    uInt chunk = (uInt)std::min<size_t>(n, 1u << 30);
    crc = (u32)::crc32(crc, p, chunk);
    p += chunk;
    n -= chunk;
  }
  return crc;
}

// ---------------- ByteSource ----------------
bool ByteSource::read_exact(u64 off, void* dst, size_t len) const {
  if (len == 0) return true;
  if (off > size() || len > size() - off) return false;
  return read_at(off, dst, len) == len;
}

bool ByteSource::read_vec(u64 off, u64 len, std::vector<u8>& out, u64 cap) const {
  if (len > cap || off > size() || len > size() - off) return false;
  out.assign((size_t)len, 0);
  return read_exact(off, out.data(), (size_t)len);
}

void FdSource::init() {
  struct stat st;
  if (fd_ >= 0 && fstat(fd_, &st) == 0) {
    if (S_ISREG(st.st_mode)) size_ = (u64)st.st_size;
    else {
      off_t e = lseek(fd_, 0, SEEK_END);
      size_ = e > 0 ? (u64)e : 0;
    }
  }
}

FdSource::~FdSource() {
  if (own_ && fd_ >= 0) close(fd_);
}

std::unique_ptr<FdSource> FdSource::open_path(const std::string& path, std::string& err) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    err = strf("cannot open %s: %s", path.c_str(), strerror(errno));
    return nullptr;
  }
  return std::unique_ptr<FdSource>(new FdSource(fd, true));
}

size_t FdSource::read_at(u64 off, void* dst, size_t len) const {
  size_t got = 0;
  u8* p = (u8*)dst;
  while (got < len) {
    ssize_t r = pread(fd_, p + got, len - got, (off_t)(off + got));
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (r == 0) break;
    got += (size_t)r;
  }
  return got;
}

size_t MemSource::read_at(u64 off, void* dst, size_t len) const {
  if (off >= d_.size()) return 0;
  size_t n = (size_t)std::min<u64>(len, d_.size() - off);
  memcpy(dst, d_.data() + off, n);
  return n;
}

// ---------------- filesystem ----------------
std::string path_join(const std::string& a, const std::string& b) {
  if (a.empty()) return b;
  if (b.empty()) return a;
  if (a.back() == '/') return a + b;
  return a + "/" + b;
}

bool mkdirs(const std::string& path) {
  if (path.empty()) return false;
  if (is_directory(path)) return true;
  size_t i = 1;
  while (i <= path.size()) {
    size_t j = path.find('/', i);
    std::string part = path.substr(0, j == std::string::npos ? path.size() : j);
    if (!part.empty() && !is_directory(part)) {
      if (mkdir(part.c_str(), 0775) != 0 && errno != EEXIST) return false;
    }
    if (j == std::string::npos) break;
    i = j + 1;
  }
  return is_directory(path);
}

bool path_exists(const std::string& p) {
  struct stat st;
  return stat(p.c_str(), &st) == 0;
}
bool is_directory(const std::string& p) {
  struct stat st;
  return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}
bool file_size_of(const std::string& p, u64& out) {
  struct stat st;
  if (stat(p.c_str(), &st) != 0) return false;
  out = (u64)st.st_size;
  return true;
}

bool free_space_of(const std::string& dir, u64& avail) {
  struct statvfs sv;
  if (statvfs(dir.c_str(), &sv) != 0) return false;
  avail = (u64)sv.f_bavail * (u64)sv.f_frsize;
  return true;
}

bool dir_writable(const std::string& dir, std::string& err) {
  if (!is_directory(dir)) {
    err = "directory does not exist";
    return false;
  }
  std::string probe = path_join(dir, strf(".kratos_probe_%llu", (unsigned long long)now_ms()));
  FILE* f = fopen(probe.c_str(), "wb");
  if (!f) {
    err = strf("cannot write: %s", strerror(errno));
    return false;
  }
  fclose(f);
  remove(probe.c_str());
  return true;
}

std::vector<std::string> list_dir(const std::string& dir) {
  std::vector<std::string> out;
  DIR* d = opendir(dir.c_str());
  if (!d) return out;
  while (dirent* e = readdir(d)) {
    std::string n = e->d_name;
    if (n == "." || n == "..") continue;
    out.push_back(n);
  }
  closedir(d);
  std::sort(out.begin(), out.end());
  return out;
}

bool remove_file(const std::string& p) { return unlink(p.c_str()) == 0; }

bool remove_tree(const std::string& path) {
  struct stat st;
  if (lstat(path.c_str(), &st) != 0) return true;
  if (S_ISDIR(st.st_mode)) {
    for (auto& n : list_dir(path)) remove_tree(path_join(path, n));
    return rmdir(path.c_str()) == 0;
  }
  return unlink(path.c_str()) == 0;
}

bool seekable_fd(int fd) { return lseek(fd, 0, SEEK_CUR) != (off_t)-1; }

std::string unique_path(const std::string& base) {
  if (!path_exists(base)) return base;
  for (int i = 2; i < 100000; i++) {
    std::string c = base + "_" + std::to_string(i);
    if (!path_exists(c)) return c;
  }
  return base + "_" + std::to_string(now_ms());
}

static bool copy_loop(int in, FILE* out, const CancelToken* cancel, u64* copied, std::string& err, bool use_pread) {
  std::vector<char> buf(1u << 20);
  u64 off = 0;
  for (;;) {
    if (cancel && cancel->cancelled()) {
      err = "cancelled";
      return false;
    }
    ssize_t r = use_pread ? pread(in, buf.data(), buf.size(), (off_t)off) : read(in, buf.data(), buf.size());
    if (r < 0) {
      if (errno == EINTR) continue;
      err = strf("read error: %s", strerror(errno));
      return false;
    }
    if (r == 0) break;
    if (fwrite(buf.data(), 1, (size_t)r, out) != (size_t)r) {
      err = strf("write error: %s", strerror(errno));
      return false;
    }
    off += (u64)r;
    if (copied) *copied = off;
  }
  return true;
}

bool copy_fd_to_file(int fd, const std::string& dst, const CancelToken* cancel, u64* copied, std::string& err) {
  FILE* out = fopen(dst.c_str(), "wb");
  if (!out) {
    err = strf("cannot create %s: %s", dst.c_str(), strerror(errno));
    return false;
  }
  bool seek = seekable_fd(fd);
  bool ok = copy_loop(fd, out, cancel, copied, err, seek);
  if (fclose(out) != 0 && ok) {
    err = strf("write error: %s", strerror(errno));
    ok = false;
  }
  if (!ok) remove(dst.c_str());
  return ok;
}

bool copy_file(const std::string& src, const std::string& dst, const CancelToken* cancel, std::string& err) {
  int fd = open(src.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    err = strf("cannot open %s: %s", src.c_str(), strerror(errno));
    return false;
  }
  bool ok = copy_fd_to_file(fd, dst, cancel, nullptr, err);
  close(fd);
  return ok;
}

bool write_text_file(const std::string& path, const std::string& text, std::string& err) {
  FILE* f = fopen(path.c_str(), "wb");
  if (!f) {
    err = strf("cannot create %s: %s", path.c_str(), strerror(errno));
    return false;
  }
  bool ok = fwrite(text.data(), 1, text.size(), f) == text.size();
  if (fclose(f) != 0) ok = false;
  if (!ok) err = strf("write error for %s: %s", path.c_str(), strerror(errno));
  return ok;
}

bool read_text_file(const std::string& path, std::string& out, u64 cap) {
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) return false;
  out.clear();
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
    if (out.size() + n > cap) {
      fclose(f);
      return false;
    }
    out.append(buf, n);
  }
  fclose(f);
  return true;
}

// ---------------- OutFile ----------------
OutFile::OutFile(const std::string& path, size_t buffer_kb, OutLimits lim, std::string comment_prefix)
    : path_(path), lim_(lim), cp_(std::move(comment_prefix)) {
  f_ = fopen(path.c_str(), "wb");
  if (!f_) {
    io_error_ = true;
    io_text_ = strf("cannot create %s: %s", path.c_str(), strerror(errno));
    return;
  }
  size_t sz = std::max<size_t>(4096, std::min<size_t>(buffer_kb, 65536) * 1024);
  buf_.resize(sz);
  setvbuf(f_, buf_.data(), _IOFBF, buf_.size());
}

OutFile::~OutFile() { close(); }

bool OutFile::raw(const char* d, size_t n) {
  if (!f_) return false;
  if (fwrite(d, 1, n, f_) != n) {
    io_error_ = true;
    io_text_ = strf("write error for %s: %s", path_.c_str(), strerror(errno));
    return false;
  }
  bytes_ += n;
  return true;
}

void OutFile::mark_truncated(const std::string& why) {
  if (truncated_) return;
  truncated_ = true;
  reason_ = why;
  std::string m = "\n" + cp_ + "[KRATOS DUMP] output truncated: " + why + "\n";
  if (f_) {
    if (fwrite(m.data(), 1, m.size(), f_) != m.size()) {
      io_error_ = true;
      io_text_ = strf("write error for %s: %s", path_.c_str(), strerror(errno));
    }
  }
}

bool OutFile::write(const std::string& s) {
  if (!f_ || truncated_ || io_error_) return false;
  u64 nl = (u64)std::count(s.begin(), s.end(), '\n');
  if (lim_.max_bytes && bytes_ + s.size() > lim_.max_bytes) {
    mark_truncated(strf("file size limit %llu bytes reached", (unsigned long long)lim_.max_bytes));
    return false;
  }
  if (lim_.max_lines && lines_ + nl > lim_.max_lines) {
    mark_truncated(strf("line limit %llu reached", (unsigned long long)lim_.max_lines));
    return false;
  }
  if (!raw(s.data(), s.size())) return false;
  lines_ += nl;
  return true;
}

bool OutFile::line(const std::string& s) {
  if (!f_ || truncated_ || io_error_) return false;
  if (lim_.max_bytes && bytes_ + s.size() + 1 > lim_.max_bytes) {
    mark_truncated(strf("file size limit %llu bytes reached", (unsigned long long)lim_.max_bytes));
    return false;
  }
  if (lim_.max_lines && lines_ + 1 > lim_.max_lines) {
    mark_truncated(strf("line limit %llu reached", (unsigned long long)lim_.max_lines));
    return false;
  }
  if (!raw(s.data(), s.size())) return false;
  if (!raw("\n", 1)) return false;
  lines_++;
  return true;
}

bool OutFile::object() {
  if (!f_ || truncated_ || io_error_) return false;
  if (lim_.max_objects && objects_ + 1 > lim_.max_objects) {
    mark_truncated(strf("object limit %llu reached", (unsigned long long)lim_.max_objects));
    return false;
  }
  objects_++;
  return true;
}

bool OutFile::close() {
  if (closed_) return !io_error_;
  closed_ = true;
  if (f_) {
    if (fclose(f_) != 0 && !io_error_) {
      io_error_ = true;
      io_text_ = strf("write error for %s: %s", path_.c_str(), strerror(errno));
    }
    f_ = nullptr;
  }
  return !io_error_;
}

}  // namespace kratos
