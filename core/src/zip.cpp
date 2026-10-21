#include "kratos/zip.h"

#include <zlib.h>
#include <zstd.h>

namespace kratos {

namespace {
constexpr u32 kSigLocal = 0x04034b50, kSigCentral = 0x02014b50, kSigEocd = 0x06054b50, kSigEocd64 = 0x06064b50, kSigLoc64 = 0x07064b50;

inline u16 le16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
inline u32 le32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
inline u64 le64(const u8* p) { return (u64)le32(p) | ((u64)le32(p + 4) << 32); }

// Applies the ZIP64 extended information extra field to the 0xFFFFFFFF-valued fields.
void apply_zip64_extra(const u8* extra, size_t n, u64& usize, u64& csize, u64& loff, bool need_u, bool need_c, bool need_o) {
  size_t i = 0;
  while (i + 4 <= n) {
    u16 id = le16(extra + i), sz = le16(extra + i + 2);
    i += 4;
    if (i + sz > n) return;
    if (id == 0x0001) {
      size_t p = i;
      if (need_u && p + 8 <= i + sz) { usize = le64(extra + p); p += 8; }
      if (need_c && p + 8 <= i + sz) { csize = le64(extra + p); p += 8; }
      if (need_o && p + 8 <= i + sz) { loff = le64(extra + p); p += 8; }
      return;
    }
    i += sz;
  }
}
}  // namespace

const char* zip_method_name(u16 m) {
  switch (m) {
    case 0: return "stored";
    case 8: return "deflate";
    case 9: return "deflate64";
    case 12: return "bzip2";
    case 14: return "lzma";
    case 93: return "zstd";
    case 95: return "xz";
    default: return "unknown";
  }
}

const ZipEntry* ZipArchive::find(const std::string& name) const {
  const ZipEntry* r = nullptr;
  for (auto& e : entries_)
    if (e.name == name) r = &e;
  return r;
}

bool ZipArchive::locate_data(ZipEntry& e) {
  u8 h[30];
  if (e.local_off + 30 > src_->size() || !src_->read_exact(e.local_off, h, 30) || le32(h) != kSigLocal) {
    e.data_ok = false;
    return false;
  }
  u64 off = e.local_off + 30 + le16(h + 26) + le16(h + 28);
  if (off > src_->size() || e.comp_size > src_->size() - off) {
    e.data_ok = false;
    return false;
  }
  e.data_off = off;
  e.data_ok = true;
  return true;
}

bool ZipArchive::parse_central(u64 cd_off, u64 cd_size, u64 count, std::string& err) {
  if (cd_off > src_->size() || cd_size > src_->size() - cd_off) {
    err = "central directory lies outside the file";
    return false;
  }
  if (cd_size > syscap::kMaxTableBytes / 2) {
    err = "central directory is too large";
    return false;
  }
  std::vector<u8> cd;
  if (!src_->read_vec(cd_off, cd_size, cd, syscap::kMaxTableBytes)) {
    err = "cannot read central directory";
    return false;
  }
  size_t p = 0;
  entries_.clear();
  while (p + 46 <= cd.size()) {
    if (le32(&cd[p]) != kSigCentral) break;
    if (entries_.size() >= syscap::kMaxZipEntries) {
      warnings_.push_back("entry limit reached while reading central directory");
      break;
    }
    ZipEntry e;
    const u8* h = &cd[p];
    e.flags = le16(h + 8);
    e.method = le16(h + 10);
    e.dos_time = le32(h + 12);
    e.crc = le32(h + 16);
    u64 csize = le32(h + 20), usize = le32(h + 24), loff = le32(h + 42);
    u16 nl = le16(h + 28), xl = le16(h + 30), cl = le16(h + 32);
    if (p + 46 + (size_t)nl + xl + cl > cd.size()) {
      warnings_.push_back("central directory entry is truncated");
      break;
    }
    e.name.assign((const char*)h + 46, nl);
    apply_zip64_extra(h + 46 + nl, xl, usize, csize, loff, le32(h + 24) == 0xFFFFFFFFu, le32(h + 20) == 0xFFFFFFFFu, le32(h + 42) == 0xFFFFFFFFu);
    e.comp_size = csize;
    e.uncomp_size = usize;
    e.local_off = loff;
    e.encrypted = (e.flags & 1) != 0;
    e.is_dir = !e.name.empty() && e.name.back() == '/';
    entries_.push_back(std::move(e));
    p += 46 + (size_t)nl + xl + cl;
  }
  if (entries_.empty() && count > 0) {
    err = "central directory contains no valid entries";
    return false;
  }
  if (count && entries_.size() != count) warnings_.push_back(strf("central directory declares %llu entries, %zu read", (unsigned long long)count, entries_.size()));
  return true;
}

bool ZipArchive::scan_local_headers(std::string& err) {
  entries_.clear();
  recovered_ = true;
  const u64 total = src_->size();
  u64 pos = 0;
  std::vector<u8> buf(1u << 20);
  while (pos + 30 <= total) {
    // Find next local header signature.
    bool found = false;
    u64 scan = pos;
    while (scan + 4 <= total) {
      size_t n = src_->read_at(scan, buf.data(), (size_t)std::min<u64>(buf.size(), total - scan));
      if (n < 4) break;
      for (size_t i = 0; i + 4 <= n; i++) {
        if (buf[i] == 'P' && buf[i + 1] == 'K' && buf[i + 2] == 3 && buf[i + 3] == 4) {
          pos = scan + i;
          found = true;
          break;
        }
      }
      if (found) break;
      scan += n - 3;
    }
    if (!found) break;
    u8 h[30];
    if (!src_->read_exact(pos, h, 30)) break;
    ZipEntry e;
    e.flags = le16(h + 6);
    e.method = le16(h + 8);
    e.dos_time = le32(h + 10);
    e.crc = le32(h + 14);
    e.comp_size = le32(h + 18);
    e.uncomp_size = le32(h + 22);
    u16 nl = le16(h + 26), xl = le16(h + 28);
    if (pos + 30 + nl + xl > total) break;
    std::vector<char> nm(nl);
    if (nl && !src_->read_exact(pos + 30, nm.data(), nl)) break;
    e.name.assign(nm.begin(), nm.end());
    e.local_off = pos;
    e.data_off = pos + 30 + nl + xl;
    e.recovered = true;
    e.encrypted = (e.flags & 1) != 0;
    e.is_dir = !e.name.empty() && e.name.back() == '/';
    if (xl) {
      std::vector<u8> ex(xl);
      if (src_->read_exact(pos + 30 + nl, ex.data(), xl)) apply_zip64_extra(ex.data(), xl, e.uncomp_size, e.comp_size, e.local_off, le32(h + 22) == 0xFFFFFFFFu, le32(h + 18) == 0xFFFFFFFFu, false);
    }
    bool sizes_unknown = (e.flags & 8) != 0 && e.comp_size == 0;
    if (sizes_unknown) {
      if (e.method == 8) {
        // Determine the compressed length by inflating until the end of the deflate stream.
        z_stream zs;
        memset(&zs, 0, sizeof zs);
        if (inflateInit2(&zs, -15) == Z_OK) {
          std::vector<u8> in(1u << 16), out(1u << 16);
          u64 off = e.data_off, produced = 0;
          int rc = Z_OK;
          while (rc != Z_STREAM_END) {
            if (zs.avail_in == 0) {
              size_t n = src_->read_at(off, in.data(), (size_t)std::min<u64>(in.size(), total - std::min(total, off)));
              if (n == 0) break;
              off += n;
              zs.next_in = in.data();
              zs.avail_in = (uInt)n;
            }
            zs.next_out = out.data();
            zs.avail_out = (uInt)out.size();
            rc = inflate(&zs, Z_NO_FLUSH);
            produced += out.size() - zs.avail_out;
            if (rc != Z_OK && rc != Z_STREAM_END) break;
            if (produced > syscap::kMaxEntrySize) break;
          }
          if (rc == Z_STREAM_END) {
            e.comp_size = zs.total_in;
            e.uncomp_size = zs.total_out;
          }
          inflateEnd(&zs);
        }
      }
      if (e.comp_size == 0 && !e.is_dir) {
        warnings_.push_back("entry with data descriptor skipped during recovery: " + e.name);
        pos += 4;
        continue;
      }
    }
    if (e.data_off > total || e.comp_size > total - e.data_off) {
      warnings_.push_back("truncated entry during recovery: " + e.name);
      e.comp_size = total - std::min(total, e.data_off);
      e.data_ok = true;
      entries_.push_back(std::move(e));
      break;
    }
    e.data_ok = true;
    u64 next = e.data_off + e.comp_size;
    if (e.flags & 8) {
      u8 d[4];
      if (src_->read_exact(next, d, 4) && le32(d) == 0x08074b50) next += 16;
      else next += 12;
    }
    entries_.push_back(std::move(e));
    if (entries_.size() >= syscap::kMaxZipEntries) break;
    pos = std::max(next, pos + 4);
  }
  if (entries_.empty()) {
    err = "no ZIP entries could be recovered";
    return false;
  }
  warnings_.push_back("central directory not usable; entries recovered from local headers (" + std::to_string(entries_.size()) + ")");
  return true;
}

void ZipArchive::finish() {
  std::unordered_map<std::string, int> cnt;
  for (auto& e : entries_) cnt[e.name]++;
  for (auto& e : entries_) {
    if (cnt[e.name] > 1) e.duplicate = true;
    if (!e.data_ok) locate_data(e);
  }
}

std::unique_ptr<ZipArchive> ZipArchive::open(std::shared_ptr<ByteSource> src, std::string& err) {
  std::unique_ptr<ZipArchive> z(new ZipArchive());
  z->src_ = std::move(src);
  const u64 total = z->src_->size();
  if (total < 22) {
    err = "file is too small to be a ZIP archive";
    return nullptr;
  }
  // Locate the end-of-central-directory record.
  u64 tail = std::min<u64>(total, 22 + 65535 + 20);
  std::vector<u8> t;
  std::string cd_err;
  bool cd_ok = false;
  if (z->src_->read_vec(total - tail, tail, t, tail)) {
    for (i64 i = (i64)t.size() - 22; i >= 0; i--) {
      if (le32(&t[(size_t)i]) != kSigEocd) continue;
      const u8* e = &t[(size_t)i];
      u64 count = le16(e + 10), cdsize = le32(e + 12), cdoff = le32(e + 16);
      u64 eocd_pos = total - tail + (u64)i;
      if (count == 0xFFFF || cdsize == 0xFFFFFFFFu || cdoff == 0xFFFFFFFFu) {
        // ZIP64: locator sits right before the EOCD.
        if (eocd_pos >= 20) {
          u8 loc[20];
          if (z->src_->read_exact(eocd_pos - 20, loc, 20) && le32(loc) == kSigLoc64) {
            u64 r64 = le64(loc + 8);
            u8 r[56];
            if (r64 + 56 <= total && z->src_->read_exact(r64, r, 56) && le32(r) == kSigEocd64) {
              count = le64(r + 32);
              cdsize = le64(r + 40);
              cdoff = le64(r + 48);
              z->zip64_ = true;
            }
          }
        }
      }
      // Some APKs carry junk before the archive: shift offsets when the directory is not where declared.
      if (z->parse_central(cdoff, cdsize, count, cd_err)) {
        cd_ok = true;
      } else if (eocd_pos >= cdsize && z->parse_central(eocd_pos - cdsize, cdsize, count, cd_err)) {
        z->warnings_.push_back("central directory offset corrected using the EOCD position");
        cd_ok = true;
      }
      break;
    }
  }
  if (!cd_ok) {
    std::string e2;
    if (!z->scan_local_headers(e2)) {
      err = cd_err.empty() ? "not a ZIP archive: " + e2 : cd_err + "; recovery failed: " + e2;
      return nullptr;
    }
  }
  z->finish();
  return z;
}

bool ZipArchive::read_entry(const ZipEntry& e, const std::function<bool(const u8*, size_t)>& sink, u64 max_bytes, bool verify_crc, std::string& err,
                            const CancelToken* cancel, bool* aborted) const {
  if (aborted) *aborted = false;
  if (e.encrypted) {
    err = "entry is encrypted";
    return false;
  }
  if (!e.data_ok) {
    err = "entry data lies outside the archive";
    return false;
  }
  const u64 cap = max_bytes ? std::min(max_bytes, syscap::kMaxEntrySize) : syscap::kMaxEntrySize;
  std::vector<u8> in(1u << 16), out(1u << 17);
  u64 in_off = e.data_off, in_left = e.comp_size, produced = 0;
  u32 crc = 0;

  auto emit = [&](const u8* p, size_t n) -> int {  // 1 ok, 0 aborted by sink, -1 error
    if (produced + n > cap) {
      err = strf("entry exceeds the size limit of %llu bytes", (unsigned long long)cap);
      return -1;
    }
    crc = crc32_update(crc, p, n);
    produced += n;
    if (sink && !sink(p, n)) {
      if (aborted) *aborted = true;
      return 0;
    }
    return 1;
  };

  auto fetch = [&](size_t& n) -> bool {
    n = (size_t)std::min<u64>(in.size(), in_left);
    if (n == 0) return true;
    if (src_->read_at(in_off, in.data(), n) != n) {
      err = "read error in archive data";
      return false;
    }
    in_off += n;
    in_left -= n;
    return true;
  };

  if (e.method == 0) {
    while (in_left) {
      if (cancel && cancel->cancelled()) { err = "cancelled"; return false; }
      size_t n;
      if (!fetch(n)) return false;
      int r = emit(in.data(), n);
      if (r < 0) return false;
      if (r == 0) return true;
    }
  } else if (e.method == 8) {
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, -15) != Z_OK) {
      err = "inflateInit failed";
      return false;
    }
    int rc = Z_OK;
    u64 consumed = 0;
    while (rc != Z_STREAM_END) {
      if (cancel && cancel->cancelled()) { inflateEnd(&zs); err = "cancelled"; return false; }
      if (zs.avail_in == 0) {
        size_t n;
        if (!fetch(n)) { inflateEnd(&zs); return false; }
        if (n == 0) {
          inflateEnd(&zs);
          err = "deflate stream is truncated";
          return false;
        }
        consumed += n;
        zs.next_in = in.data();
        zs.avail_in = (uInt)n;
      }
      zs.next_out = out.data();
      zs.avail_out = (uInt)out.size();
      rc = inflate(&zs, Z_NO_FLUSH);
      if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        err = strf("inflate error %d (%s)", rc, zs.msg ? zs.msg : "");
        inflateEnd(&zs);
        return false;
      }
      size_t got = out.size() - zs.avail_out;
      if (got) {
        int r = emit(out.data(), got);
        if (r < 0) { inflateEnd(&zs); return false; }
        if (r == 0) { inflateEnd(&zs); return true; }
        if (produced > (64u << 20) && (double)produced / (double)std::max<u64>(1, consumed) > syscap::kMaxInflateRatio) {
          err = "compression ratio exceeds the safety threshold";
          inflateEnd(&zs);
          return false;
        }
      } else if (rc == Z_BUF_ERROR && zs.avail_in != 0) {
        inflateEnd(&zs);
        err = "inflate made no progress";
        return false;
      }
    }
    inflateEnd(&zs);
  } else if (e.method == 93) {
    ZSTD_DCtx* ctx = ZSTD_createDCtx();
    if (!ctx) { err = "cannot create zstd context"; return false; }
    bool ok = true, done = false;
    u64 consumed = 0;
    while (!done && ok) {
      if (cancel && cancel->cancelled()) { err = "cancelled"; ok = false; break; }
      size_t n;
      if (!fetch(n)) { ok = false; break; }
      if (n == 0) { err = "zstd stream is truncated"; ok = false; break; }
      consumed += n;
      ZSTD_inBuffer ib{in.data(), n, 0};
      while (ib.pos < ib.size) {
        ZSTD_outBuffer ob{out.data(), out.size(), 0};
        size_t r = ZSTD_decompressStream(ctx, &ob, &ib);
        if (ZSTD_isError(r)) { err = std::string("zstd error: ") + ZSTD_getErrorName(r); ok = false; break; }
        if (ob.pos) {
          int rr = emit(out.data(), ob.pos);
          if (rr < 0) { ok = false; break; }
          if (rr == 0) { ZSTD_freeDCtx(ctx); return true; }
          if (produced > (64u << 20) && (double)produced / (double)std::max<u64>(1, consumed) > syscap::kMaxInflateRatio) {
            err = "compression ratio exceeds the safety threshold";
            ok = false;
            break;
          }
        }
        if (r == 0) { done = true; break; }
      }
    }
    ZSTD_freeDCtx(ctx);
    if (!ok) return false;
  } else {
    err = strf("unsupported compression method %u (%s)", e.method, zip_method_name(e.method));
    return false;
  }

  if (!e.recovered && produced != e.uncomp_size) {
    err = strf("size mismatch: %llu bytes produced, %llu declared", (unsigned long long)produced, (unsigned long long)e.uncomp_size);
    return false;
  }
  if (verify_crc && !((e.flags & 8) && e.crc == 0) && crc != e.crc) {
    err = strf("CRC32 mismatch: computed %08x, declared %08x", crc, e.crc);
    return false;
  }
  return true;
}

bool ZipArchive::read_head(const ZipEntry& e, size_t n, std::vector<u8>& out, std::string& err) const {
  out.clear();
  bool aborted = false;
  bool ok = read_entry(
      e,
      [&](const u8* p, size_t k) {
        size_t take = std::min(k, n - out.size());
        out.insert(out.end(), p, p + take);
        return out.size() < n;
      },
      0, false, err, nullptr, &aborted);
  return ok || aborted;
}

bool ZipArchive::extract_to_file(const ZipEntry& e, const std::string& dst, u64 max_bytes, bool verify_crc, std::string& err, const CancelToken* cancel,
                                 u64* written, ExtractNote* note) const {
  FILE* f = fopen(dst.c_str(), "wb");
  if (!f) {
    err = strf("cannot create %s: %s", dst.c_str(), strerror(errno));
    return false;
  }
  static const size_t kBuf = 1u << 20;
  std::vector<char> iobuf(kBuf);
  setvbuf(f, iobuf.data(), _IOFBF, iobuf.size());
  u64 w = 0;
  bool io_fail = false;
  bool ok = read_entry(
      e,
      [&](const u8* p, size_t n) {
        if (fwrite(p, 1, n, f) != n) {
          io_fail = true;
          return false;
        }
        w += n;
        return true;
      },
      max_bytes, verify_crc, err, cancel);
  if (fclose(f) != 0) io_fail = true;
  if (io_fail) {
    err = strf("write error for %s: %s", dst.c_str(), strerror(errno));
    ok = false;
  } else if (!ok && note && w > 0 && err != "cancelled" && !(cancel && cancel->cancelled())) {
    note->damaged = true;
    note->text = err;
    err.clear();
    ok = true;
  }
  if (!ok) remove(dst.c_str());
  if (written) *written = w;
  return ok;
}

std::shared_ptr<ByteSource> ZipArchive::stored_view(const ZipEntry& e) const {
  if (e.method != 0 || !e.data_ok || e.encrypted) return nullptr;
  return std::make_shared<SliceSource>(src_, e.data_off, e.comp_size);
}

}  // namespace kratos
