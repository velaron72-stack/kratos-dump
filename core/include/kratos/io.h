// Hashing, random-access byte sources, filesystem helpers and limit-aware report files.
#pragma once

#include "kratos/common.h"

namespace kratos {

// ---------- hashing ----------
class Sha256 {
 public:
  Sha256();
  void update(const void* data, size_t n);
  std::string finish_hex();

 private:
  void block(const u8* p);
  u32 h_[8];
  u8 buf_[64];
  size_t buf_len_ = 0;
  u64 total_ = 0;
};
u32 crc32_update(u32 crc, const void* data, size_t n);

// ---------- byte sources ----------
class ByteSource {
 public:
  virtual ~ByteSource() = default;
  virtual u64 size() const = 0;
  // Thread-safe positioned read; returns number of bytes read (short only at EOF or on error).
  virtual size_t read_at(u64 off, void* dst, size_t len) const = 0;

  bool read_exact(u64 off, void* dst, size_t len) const;
  // Reads [off, off+len) into out. Fails when len > cap or the range leaves the source.
  bool read_vec(u64 off, u64 len, std::vector<u8>& out, u64 cap) const;
};

class FdSource : public ByteSource {
 public:
  FdSource(int fd, bool own) : fd_(fd), own_(own) { init(); }
  ~FdSource() override;
  static std::unique_ptr<FdSource> open_path(const std::string& path, std::string& err);
  u64 size() const override { return size_; }
  size_t read_at(u64 off, void* dst, size_t len) const override;
  int fd() const { return fd_; }

 private:
  void init();
  int fd_;
  bool own_;
  u64 size_ = 0;
};

class MemSource : public ByteSource {
 public:
  explicit MemSource(std::vector<u8> d) : d_(std::move(d)) {}
  u64 size() const override { return d_.size(); }
  size_t read_at(u64 off, void* dst, size_t len) const override;

 private:
  std::vector<u8> d_;
};

// ---------- filesystem ----------
std::string path_join(const std::string& a, const std::string& b);
bool mkdirs(const std::string& path);
bool path_exists(const std::string& path);
bool is_directory(const std::string& path);
bool file_size_of(const std::string& path, u64& out);
bool free_space_of(const std::string& dir, u64& avail_bytes);
bool dir_writable(const std::string& dir, std::string& err);
bool remove_tree(const std::string& path);
bool remove_file(const std::string& path);
std::vector<std::string> list_dir(const std::string& dir);  // names only
bool seekable_fd(int fd);
// Returns `base` if unused, otherwise base_2, base_3, ...
std::string unique_path(const std::string& base);
bool copy_fd_to_file(int fd, const std::string& dst, const CancelToken* cancel, u64* copied, std::string& err);
bool copy_file(const std::string& src, const std::string& dst, const CancelToken* cancel, std::string& err);
bool write_text_file(const std::string& path, const std::string& text, std::string& err);
bool read_text_file(const std::string& path, std::string& out, u64 cap = 64u << 20);

// ---------- limit-aware streaming report file ----------
struct OutLimits {
  u64 max_bytes = 0;    // 0 = no user limit
  u64 max_lines = 0;
  u64 max_objects = 0;
};

class OutFile {
 public:
  OutFile(const std::string& path, size_t buffer_kb, OutLimits lim, std::string comment_prefix = "# ");
  ~OutFile();
  OutFile(const OutFile&) = delete;
  OutFile& operator=(const OutFile&) = delete;

  bool ok() const { return f_ != nullptr; }
  // Each returns false once the file is truncated by a limit or an I/O error occurred.
  bool write(const std::string& s);
  bool line(const std::string& s);
  bool object();  // count one logical object (function, string, xref, ...)
  bool open_for_more() const { return f_ && !truncated_ && !io_error_; }

  bool truncated() const { return truncated_; }
  const std::string& truncation_reason() const { return reason_; }
  bool io_error() const { return io_error_; }
  const std::string& io_error_text() const { return io_text_; }
  u64 bytes() const { return bytes_; }
  u64 lines() const { return lines_; }
  u64 objects() const { return objects_; }
  const std::string& path() const { return path_; }
  bool close();  // flush; returns false on I/O error

 private:
  bool raw(const char* d, size_t n);
  void mark_truncated(const std::string& why);

  std::string path_;
  FILE* f_ = nullptr;
  std::vector<char> buf_;
  OutLimits lim_;
  std::string cp_;
  u64 bytes_ = 0, lines_ = 0, objects_ = 0;
  bool truncated_ = false, io_error_ = false, closed_ = false;
  std::string reason_, io_text_;
};

}  // namespace kratos
