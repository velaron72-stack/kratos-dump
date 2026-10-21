// ZIP/APK reader: central directory (ZIP64 aware), recovery by local-header scan,
// stored/deflate/zstd entries, streaming extraction with CRC and size guards.
#pragma once

#include "kratos/io.h"

namespace kratos {

struct ZipEntry {
  std::string name;
  u64 comp_size = 0, uncomp_size = 0;
  u64 local_off = 0;
  u64 data_off = 0;  // start of compressed data (valid when data_ok)
  bool data_ok = false;
  u32 crc = 0;
  u16 method = 0, flags = 0;
  bool is_dir = false;
  bool encrypted = false;
  bool recovered = false;  // found by local-header scan, not in the central directory
  bool duplicate = false;  // another entry with the same name exists
  u32 dos_time = 0;
};

const char* zip_method_name(u16 m);

// Filled by extract_to_file when data was kept although the entry is damaged (CRC or size mismatch, broken stream).
struct ExtractNote {
  bool damaged = false;
  std::string text;
};

class ZipArchive {
 public:
  // Opens an archive. On success entries() is filled. Never throws.
  static std::unique_ptr<ZipArchive> open(std::shared_ptr<ByteSource> src, std::string& err);

  const std::vector<ZipEntry>& entries() const { return entries_; }
  const std::vector<std::string>& warnings() const { return warnings_; }
  bool recovered() const { return recovered_; }
  bool zip64() const { return zip64_; }
  u64 archive_size() const { return src_->size(); }
  std::shared_ptr<ByteSource> source() const { return src_; }
  const ZipEntry* find(const std::string& name) const;  // last entry with this name wins (Android semantics)

  // Streams the decompressed content to sink. sink returns false to abort (not an error).
  // max_bytes caps the produced bytes (0 = system cap only). CRC is verified when verify_crc is set
  // and the whole entry was produced. Returns false and sets err on failure.
  bool read_entry(const ZipEntry& e, const std::function<bool(const u8*, size_t)>& sink, u64 max_bytes, bool verify_crc, std::string& err,
                  const CancelToken* cancel = nullptr, bool* aborted = nullptr) const;
  // Reads at most n leading bytes of the decompressed content.
  bool read_head(const ZipEntry& e, size_t n, std::vector<u8>& out, std::string& err) const;
  // With note != nullptr, bytes produced before a CRC/size/stream error are kept (note->damaged is set) and true is returned.
  // I/O errors and cancellation always fail and remove the file.
  bool extract_to_file(const ZipEntry& e, const std::string& dst, u64 max_bytes, bool verify_crc, std::string& err, const CancelToken* cancel = nullptr,
                       u64* written = nullptr, ExtractNote* note = nullptr) const;
  // For stored entries returns a view without copying; otherwise nullptr.
  std::shared_ptr<ByteSource> stored_view(const ZipEntry& e) const;

 private:
  bool locate_data(ZipEntry& e);
  bool parse_central(u64 cd_off, u64 cd_size, u64 count, std::string& err);
  bool scan_local_headers(std::string& err);
  void finish();

  std::shared_ptr<ByteSource> src_;
  std::vector<ZipEntry> entries_;
  std::vector<std::string> warnings_;
  bool recovered_ = false;
  bool zip64_ = false;
};

// A window into another source.
class SliceSource : public ByteSource {
 public:
  SliceSource(std::shared_ptr<ByteSource> parent, u64 off, u64 len) : p_(std::move(parent)), off_(off), len_(len) {}
  u64 size() const override { return len_; }
  size_t read_at(u64 off, void* dst, size_t len) const override {
    if (off >= len_) return 0;
    size_t n = (size_t)std::min<u64>(len, len_ - off);
    return p_->read_at(off_ + off, dst, n);
  }

 private:
  std::shared_ptr<ByteSource> p_;
  u64 off_, len_;
};

}  // namespace kratos
