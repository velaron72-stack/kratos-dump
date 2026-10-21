// String extraction: ASCII / UTF-8 / UTF-16 (LE, BE), streamed in offset order, optionally sorted, grouped and deduplicated.
#include <deque>
#include <functional>
#include <queue>

#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

constexpr u64 kInf = ~(u64)0;

inline bool u16_text(u32 u) {
  return (u >= 0x20 && u <= 0x7E) || u == 0x09 || (u >= 0xA0 && u <= 0x24F) || (u >= 0x400 && u <= 0x4FF) || (u >= 0x3040 && u <= 0x30FF) ||
         (u >= 0x4E00 && u <= 0x9FFF) || (u >= 0xAC00 && u <= 0xD7A3);
}
void put_utf8(std::string& o, u32 cp) {
  if (cp < 0x80) o.push_back((char)cp);
  else if (cp < 0x800) { o.push_back((char)(0xC0 | (cp >> 6))); o.push_back((char)(0x80 | (cp & 0x3F))); }
  else { o.push_back((char)(0xE0 | (cp >> 12))); o.push_back((char)(0x80 | ((cp >> 6) & 0x3F))); o.push_back((char)(0x80 | (cp & 0x3F))); }
}

struct Opts {
  u64 min_len = 4, max_len = 0;
  bool ascii = true, utf8 = true, u16le = true, u16be = false;
};

struct Cmp {
  bool operator()(const StringRec& a, const StringRec& b) const { return a.off != b.off ? a.off > b.off : a.enc > b.enc; }
};

class Scanner {
 public:
  Scanner(const Opts& o, std::function<void(StringRec&&)> sink) : o_(o), sink_(std::move(sink)) {
    if (o_.u16le) { u16_.push_back({false, 0}); u16_.push_back({false, 1}); }
    if (o_.u16be) { u16_.push_back({true, 0}); u16_.push_back({true, 1}); }
  }

  void begin_range(bool decompressed, int sec) {
    decompressed_ = decompressed;
    sec_ = sec;
    reset_text();
    for (auto& m : u16_) m.reset();
  }

  // Works through the buffer in short blocks and releases finished hits after each one. Without this, a large read buffer
  // would pile up every hit of the buffer before the first one is checked against its neighbours.
  void feed(u64 off, const u8* p, size_t n) {
    constexpr size_t kBlock = 64 * 1024;
    for (size_t base = 0; base < n; base += kBlock) {
      const size_t end = std::min(n, base + kBlock);
      for (size_t i = base; i < end; i++) {
        u64 o = off + i;
        u8 b = p[i];
        if (o_.ascii || o_.utf8) text_byte(o, b);
        for (auto& m : u16_) u16_byte(m, o, b);
      }
      flush(std::min(min_active(), off + end));
    }
  }

  void end_range(u64 end_off) {
    if (o_.ascii || o_.utf8) text_finish();
    for (auto& m : u16_) u16_finish(m);
    (void)end_off;
    flush(kInf);
  }

 private:
  struct U16 {
    bool be;
    int parity;
    bool have_first = false;
    u8 first = 0;
    u64 start = kInf;
    u32 chars = 0;
    std::string text;
    u8 scripts = 0;       // 1 Latin-1/Extended (non-ASCII), 2 Cyrillic, 4 Kana, 8 Han, 16 Hangul
    u32 cjk_units = 0, cjk_ascii_bytes = 0;  // CJK-class units and how many of their bytes are NUL or printable ASCII
    U16(bool b, int p) : be(b), parity(p) {}
    void reset() { have_first = false; start = kInf; chars = 0; text.clear(); scripts = 0; cjk_units = cjk_ascii_bytes = 0; }
  };

  void reset_text() {
    cur_.clear();
    cstart_ = kInf;
    chars_ = 0;
    pending_ = 0;
    multi_ = false;
    seq_start_ = 0;
    seq_chars_ = 0;
  }

  u64 min_active() const {
    u64 m = cstart_;
    for (auto& u : u16_) m = std::min(m, u.start);
    return m;
  }

  void push(StringRec&& r) {
    r.decompressed = decompressed_;
    r.sec = sec_;
    heap_.push(std::move(r));
  }

  void text_emit() {
    if (cstart_ == kInf) return;
    std::string s = cur_;
    u64 chars = chars_;
    bool multi = multi_;
    if (pending_) {  // drop an incomplete trailing sequence
      s.resize(seq_start_);
      chars = seq_chars_;
      multi = multi_ && seq_multi_before_;
    }
    const u64 raw_bytes = s.size();
    if (chars >= o_.min_len && (multi ? o_.utf8 : o_.ascii)) {
      if (o_.max_len && chars > o_.max_len) {
        // Truncate at a character boundary.
        size_t i = 0;
        u64 cc = 0;
        while (i < s.size() && cc < o_.max_len) {
          unsigned char c = (unsigned char)s[i];
          i += c < 0x80 ? 1 : (c >= 0xF0 ? 4 : (c >= 0xE0 ? 3 : 2));
          cc++;
        }
        s.resize(std::min(i, s.size()));
        chars = o_.max_len;
      }
      StringRec r;
      r.off = cstart_;
      r.enc = multi ? ENC_UTF8 : ENC_ASCII;
      r.span = (u32)std::min<u64>(raw_bytes, 0xFFFFFFFFull);
      r.chars = (u32)chars;
      r.text = std::move(s);
      push(std::move(r));
    }
    cur_.clear();
    cstart_ = kInf;
    chars_ = 0;
    pending_ = 0;
    multi_ = false;
  }

  void text_finish() { text_emit(); }

  void text_byte(u64 o, u8 b) {
    if (pending_) {
      if ((b & 0xC0) == 0x80) {
        cur_.push_back((char)b);
        if (--pending_ == 0) chars_++;
        return;
      }
      text_emit();  // broken sequence: flush what we have and reconsider this byte
    }
    if ((b >= 0x20 && b <= 0x7E) || b == 0x09) {
      if (cstart_ == kInf) cstart_ = o;
      cur_.push_back((char)b);
      chars_++;
    } else if (b >= 0xC2 && b <= 0xF4) {
      if (cstart_ == kInf) cstart_ = o;
      seq_multi_before_ = multi_;
      seq_start_ = cur_.size();
      seq_chars_ = chars_;
      cur_.push_back((char)b);
      pending_ = b >= 0xF0 ? 3 : (b >= 0xE0 ? 2 : 1);
      multi_ = true;
    } else {
      text_emit();
      return;
    }
    if (cur_.size() >= syscap::kMaxStringLen) text_emit();
  }

  // ASCII text (often NUL separated) read with the wrong byte pairing looks like CJK text ("ka" -> U+616B). A run that contains
  // CJK, Kana or Hangul units is accepted only when it is at least 6 characters long and those units are not made of
  // ASCII/NUL bytes (real CJK text has about half of its bytes outside that set; the misread ASCII has all of them inside).
  static bool u16_plausible(const U16& m) {
    const u8 cjk = m.scripts & (4 | 8 | 16);
    if (!cjk) return true;
    if (m.scripts & (1 | 2)) return false;  // accented Latin or Cyrillic mixed with CJK is noise
    if (cjk != 4 && cjk != 8 && cjk != 16 && cjk != (4 | 8)) return false;  // Kana+Han is Japanese; other mixes are noise
    return m.chars >= 6 && m.cjk_units > 0 && (u64)m.cjk_ascii_bytes * 100 < (u64)m.cjk_units * 2 * 85;
  }

  void u16_emit(U16& m) {
    if (m.start != kInf && m.chars >= o_.min_len && !u16_plausible(m)) {
      m.start = kInf;
    }
    if (m.start != kInf && m.chars >= o_.min_len) {
      std::string t = m.text;
      u64 chars = m.chars;
      if (o_.max_len && chars > o_.max_len) {
        // Characters may be 1-3 bytes; recompute by decoding length.
        size_t i = 0;
        u64 cc = 0;
        while (i < t.size() && cc < o_.max_len) {
          unsigned char c = (unsigned char)t[i];
          i += c < 0x80 ? 1 : (c >= 0xE0 ? 3 : 2);
          cc++;
        }
        t.resize(std::min(i, t.size()));
        chars = o_.max_len;
      }
      StringRec r;
      r.off = m.start;
      r.enc = m.be ? ENC_UTF16BE : ENC_UTF16LE;
      r.span = (u32)std::min<u64>(2 * m.chars, 0xFFFFFFFFull);
      r.chars = (u32)chars;
      r.text = std::move(t);
      push(std::move(r));
    }
    m.start = kInf;
    m.chars = 0;
    m.text.clear();
    m.scripts = 0;
    m.cjk_units = m.cjk_ascii_bytes = 0;
  }
  void u16_finish(U16& m) { u16_emit(m); }

  void u16_byte(U16& m, u64 o, u8 b) {
    if ((int)(o & 1) == m.parity) {
      m.have_first = true;
      m.first = b;
      return;
    }
    if (!m.have_first) return;
    m.have_first = false;
    u32 u = m.be ? ((u32)m.first << 8) | b : ((u32)b << 8) | m.first;
    if (u16_text(u)) {
      if (m.start == kInf) m.start = o - 1;
      put_utf8(m.text, u);
      m.chars++;
      if (u >= 0xA0) m.scripts |= u <= 0x24F ? 1 : (u <= 0x4FF ? 2 : (u <= 0x30FF ? 4 : (u <= 0x9FFF ? 8 : 16)));
      if (u > 0x4FF) {
        m.cjk_units++;
        for (u8 x : {m.first, b})
          if (x == 0 || (x >= 0x20 && x <= 0x7E)) m.cjk_ascii_bytes++;
      }
      if (m.text.size() >= syscap::kMaxStringLen) u16_emit(m);
    } else {
      u16_emit(m);
    }
  }

  static bool is_u16(const StringRec& r) { return r.enc == ENC_UTF16LE || r.enc == ENC_UTF16BE; }
  static u64 end_of(const StringRec& r) { return r.off + r.span; }
  static u64 overlap(const StringRec& a, const StringRec& b) {
    u64 lo = std::max(a.off, b.off), hi = std::min(end_of(a), end_of(b));
    return hi > lo ? hi - lo : 0;
  }

  // Wide-string hits are often misreadings of other data, so overlapping hits are sorted out here:
  //  - ASCII text in UTF-16 of one byte order also reads as the other byte order when shifted by one byte. The hit at the even
  //    file offset is kept, because wide strings are 2-aligned.
  //  - A UTF-16 hit that mostly lies over ASCII or UTF-8 text is a misreading of that text.
  void enqueue(StringRec&& r) {
    const bool r16 = is_u16(r);
    for (auto it = q_.begin(); it != q_.end();) {
      const bool h16 = is_u16(*it);
      if (r16 && h16) {
        if (it->enc != r.enc && overlap(*it, r) > 0 && ((it->off ^ r.off) & 1)) {
          if (it->off & 1) {
            it = q_.erase(it);
            continue;
          }
          return;
        }
      } else if (r16 != h16) {
        const StringRec& wide = r16 ? r : *it;
        if (wide.span && overlap(*it, r) * 2 >= wide.span) {
          if (r16) return;
          it = q_.erase(it);
          continue;
        }
      }
      ++it;
    }
    q_.push_back(std::move(r));
  }

  // A hit waits until no later hit can overlap it, so the output keeps its offset order.
  void release(u64 safe) {
    while (!q_.empty()) {
      if (end_of(q_.front()) > safe) break;
      sink_(std::move(q_.front()));
      q_.pop_front();
    }
  }

  void flush(u64 safe) {
    while (!heap_.empty() && heap_.top().off < safe) {
      StringRec r = heap_.top();
      heap_.pop();
      release(r.off);  // hits that end before this one starts cannot overlap it or any later hit
      enqueue(std::move(r));
    }
    release(safe);
  }

  Opts o_;
  std::function<void(StringRec&&)> sink_;
  std::vector<U16> u16_;
  std::priority_queue<StringRec, std::vector<StringRec>, Cmp> heap_;
  std::deque<StringRec> q_;
  bool decompressed_ = false;
  int sec_ = -1;
  std::string cur_;
  u64 cstart_ = kInf, chars_ = 0;
  int pending_ = 0;
  bool multi_ = false, seq_multi_before_ = false;
  size_t seq_start_ = 0;
  u64 seq_chars_ = 0;
};

struct Rng {
  u64 off, len;
};

std::vector<Rng> merge_ranges(std::vector<Rng> v) {
  std::sort(v.begin(), v.end(), [](const Rng& a, const Rng& b) { return a.off < b.off; });
  std::vector<Rng> out;
  for (auto& r : v) {
    if (r.len == 0) continue;
    if (!out.empty() && r.off <= out.back().off + out.back().len) {
      u64 e = std::max(out.back().off + out.back().len, r.off + r.len);
      out.back().len = e - out.back().off;
    } else {
      out.push_back(r);
    }
  }
  return out;
}

std::string escape_text(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 2);
  for (unsigned char c : s) {
    if (c == '\\') o += "\\\\";
    else if (c == '"') o += "\\\"";
    else if (c == '\t') o += "\\t";
    else if (c < 0x20 || c == 0x7F) o += strf("\\x%02x", c);
    else o.push_back((char)c);
  }
  return o;
}

const char* enc_name(u8 e) {
  switch (e) {
    case ENC_ASCII: return "ascii";
    case ENC_UTF8: return "utf-8";
    case ENC_UTF16LE: return "utf-16le";
    default: return "utf-16be";
  }
}

bool matches_any(const std::string& text, const std::vector<std::string>& toks) {
  for (auto& t : toks)
    if (contains_ci(text, t)) return true;
  return false;
}

}  // namespace

bool stage_strings(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  StringsResult& sr = lc.strings;
  sr.ran = true;
  const ElfModel& m = lc.elf;

  Opts o;
  o.min_len = (u64)cfg.i("strings.min_len");
  o.max_len = cfg.limit("strings.max_len");
  o.ascii = cfg.flag("strings.encodings", "ascii");
  o.utf8 = cfg.flag("strings.encodings", "utf8");
  o.u16le = cfg.flag("strings.encodings", "utf16le");
  o.u16be = cfg.flag("strings.encodings", "utf16be");
  if (!o.ascii && !o.utf8 && !o.u16le && !o.u16be) {
    rc.warn("strings", "no string encodings are enabled; nothing to search");
    return true;
  }
  std::vector<std::string> inc = split(cfg.s("strings.filter"), ','), exc = split(cfg.s("strings.exclude"), ',');
  std::string sort = cfg.s("strings.sort"), group = cfg.s("strings.group"), scope = cfg.s("strings.scope");
  bool dedupe = cfg.b("strings.dedupe");
  const bool want_report = report_wanted(rc, "out.strings");
  const bool want_index = cfg.flag("xref.types", "string") && cfg.i("general.depth") >= 4;
  const bool detailed = cfg.s("general.detail_level") == "detailed" || cfg.s("general.detail_level") == "full";
  const AddrCols ac = AddrCols::from(cfg);
  const u64 max_strings = cfg.limit("limits.max_strings");

  bool in_memory = (sort != "offset" || group != "none" || dedupe);
  if (in_memory && lc.large_file) {
    rc.warn("strings", strf("file is above the large-file threshold: sorting, grouping and deduplication are disabled (streaming only)"));
    rc.ledger.add_gap("skipped", "strings sort/group/dedupe", "large file: streaming mode only", lc.index);
    in_memory = false;
    sort = "offset";
    group = "none";
    dedupe = false;
  }

  // ---- scan ranges ----
  std::vector<Rng> ranges;
  std::string scope_note = scope;
  auto seg_ranges = [&]() {
    std::vector<Rng> v;
    for (auto& s : m.segs)
      if (s.type == elf::PT_LOAD && s.filesz && s.offset < lc.size) v.push_back({s.offset, std::min(s.filesz, lc.size - s.offset)});
    return v;
  };
  if (scope == "loaded_segments") {
    ranges = seg_ranges();
    if (ranges.empty()) {
      scope_note = "whole_file (no program headers)";
      ranges.push_back({0, lc.size});
    }
  } else if (scope == "sections") {
    for (auto& s : m.secs)
      if (!s.synthetic && s.alloc() && s.has_file_data() && s.size && s.offset < lc.size) ranges.push_back({s.offset, std::min(s.size, lc.size - s.offset)});
    if (ranges.empty()) {
      scope_note = "loaded_segments (no usable section table)";
      ranges = seg_ranges();
    }
    if (ranges.empty()) {
      scope_note = "whole_file (no usable tables)";
      ranges.push_back({0, lc.size});
    }
  } else {
    ranges.push_back({0, lc.size});
  }
  if (scope_note != scope) rc.warn("strings", "scope " + scope + " unavailable, using " + scope_note);
  for (auto& r : ranges) lc.range.clip_file(m, r.off, r.len);
  ranges = merge_ranges(ranges);
  sr.ranges = ranges.size();
  u64 total_bytes = 0;
  for (auto& r : ranges) total_bytes += r.len;

  // Section lookup by file offset.
  std::vector<std::pair<u64, int>> sec_starts;
  std::vector<u64> sec_ends;
  {
    std::vector<const ElfSection*> v;
    for (auto& s : m.secs)
      if (!s.synthetic && s.has_file_data() && s.size) v.push_back(&s);
    std::sort(v.begin(), v.end(), [](const ElfSection* a, const ElfSection* b) { return a->offset < b->offset; });
    for (auto* s : v) {
      sec_starts.push_back({s->offset, s->index});
      sec_ends.push_back(s->offset + s->size);
    }
  }
  auto sec_of = [&](u64 off) -> int {
    size_t lo = 0, hi = sec_starts.size();
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (sec_starts[mid].first <= off) lo = mid + 1;
      else hi = mid;
    }
    // Walk back over small nested sections.
    for (size_t i = lo; i-- > 0 && lo - i < 8;)
      if (off < sec_ends[i]) return sec_starts[i].second;
    return -1;
  };

  // ---- output ----
  std::unique_ptr<ReportFile> rf;
  bool write_ok = false;
  if (want_report) {
    rf.reset(new ReportFile(rc, lc.index, "strings.txt", lc.reports_dir, lc.rel_reports, max_strings));
    if (!rf->ok()) {
      report_failed(rc, lc.index, "strings.txt", rf->create_error());
      rf.reset();
    } else {
      write_ok = true;
      rf->header("strings", &lc);
      OutFile& f = rf->f();
      f.line(strf("# scope: %s; min length %llu chars; encodings:%s%s%s%s", scope_note.c_str(), (unsigned long long)o.min_len, o.ascii ? " ascii" : "", o.utf8 ? " utf-8" : "",
                  o.u16le ? " utf-16le" : "", o.u16be ? " utf-16be" : ""));
      f.line("# columns: [encoding] " + ac.header() + "length [section] text");
      f.line("# UTF-16 detection covers Latin, Cyrillic, Hangul and CJK code points (CJK runs need 6+ characters that are not misread ASCII); text is shown as UTF-8");
      if (!inc.empty()) f.line("# filter (contains any of): " + join(inc, ", "));
      if (!exc.empty()) f.line("# excluded: " + join(exc, ", "));
      f.line("");
    }
  }

  auto sec_name = [&](const StringRec& r) -> std::string {
    if (r.sec >= 0 && r.sec < (int)m.secs.size()) return m.secs[(size_t)r.sec].name;
    return "-";
  };
  auto format_line = [&](const StringRec& r) {
    std::string s = strf("[%-8s] ", enc_name(r.enc));
    if (r.decompressed) {
      s += strf("%-10s ", "-");
      if (ac.va) s += strf("%-10s ", "-");
      if (ac.rva) s += strf("%-10s ", "-");
      if (ac.foff) s = strf("[%-8s] (dec+0x%llx) ", enc_name(r.enc), (unsigned long long)r.off);
    } else {
      u64 va = 0;
      bool hv = m.off_to_vaddr(r.off, va);
      s += ac.fmt(m, true, r.off, hv, va);
    }
    s += strf("len=%u ", r.chars);
    if (r.count > 1) s += strf("x%u ", r.count);
    if (detailed || r.decompressed) s += "[" + sec_name(r) + (r.decompressed ? ",decompressed" : "") + "] ";
    s += "\"" + escape_text(r.text) + "\"";
    return s;
  };

  std::vector<StringRec> mem;
  std::unordered_map<std::string, size_t> dedupe_idx;
  u64 mem_reserved = 0;
  bool stop_scan = false;
  u64 written = 0;

  auto stream_write = [&](const StringRec& r) {
    if (!write_ok || !rf) return;
    OutFile& f = rf->f();
    if (!f.open_for_more()) return;
    if (!f.object()) return;
    if (f.line(format_line(r))) written++;
  };

  auto sink = [&](StringRec&& r) {
    // Classification and filters.
    if (!inc.empty() && !matches_any(r.text, inc)) { sr.filtered_out++; return; }
    if (!exc.empty() && matches_any(r.text, exc)) { sr.filtered_out++; return; }
    sr.total_found++;
    sr.by_enc[r.enc]++;
    if (!r.decompressed) {
      if (r.sec < 0) r.sec = sec_of(r.off);
      u64 va;
      r.has_vaddr = m.off_to_vaddr(r.off, va);
      r.vaddr = r.has_vaddr ? va : 0;
      if (want_index && (r.enc == ENC_ASCII || r.enc == ENC_UTF8)) {
        if (sr.index.size() < 8'000'000 && rc.mem->try_reserve(16)) sr.index.push_back({r.off, (u32)r.text.size()});
        else sr.index_partial = true;
      }
    }
    if (!rf) return;
    if (!in_memory) {
      stream_write(r);
      if (rf->f().truncated() && !want_index) stop_scan = true;
      return;
    }
    // In-memory path (sorting, grouping, deduplication).
    if (dedupe) {
      auto it = dedupe_idx.find(r.text + (char)(r.enc + 1));
      if (it != dedupe_idx.end()) {
        mem[it->second].count++;
        return;
      }
    }
    u64 est = sizeof(StringRec) + r.text.size() + 48;
    if (!rc.mem->try_reserve(est)) {
      if (!sr.memory_partial) rc.warn("strings", "memory limit reached: the sorted/grouped string list is incomplete");
      sr.memory_partial = true;
      return;
    }
    mem_reserved += est;
    if (dedupe) dedupe_idx[r.text + (char)(r.enc + 1)] = mem.size();
    mem.push_back(std::move(r));
  };

  Scanner sc(o, sink);

  // ---- scan file ranges ----
  std::vector<u8> buf((size_t)std::min<u64>(std::max<u64>(io_buffer_kb(cfg) * 1024ull, 65536), 16u << 20));
  u64 done = 0;
  sc.begin_range(false, -1);
  for (auto& r : ranges) {
    sc.begin_range(false, -1);
    u64 pos = r.off, end = r.off + r.len;
    while (pos < end && !stop_scan) {
      if (rc.cancel->cancelled()) return false;
      size_t n = (size_t)std::min<u64>(buf.size(), end - pos);
      size_t got = lc.src->read_at(pos, buf.data(), n);
      if (got == 0) {
        rc.warn("strings", strf("read error at offset 0x%llx; remaining bytes of this range skipped", (unsigned long long)pos));
        break;
      }
      sc.feed(pos, buf.data(), got);
      pos += got;
      done += got;
      sr.bytes_scanned += got;
      rc.prog("strings", done, total_bytes, "scanning strings");
    }
    sc.end_range(end);
    if (stop_scan) break;
  }

  // ---- compressed sections ----
  if (!stop_scan && cfg.b("lib.decompress_sections") && m.secs_ok) {
    ParseCtx pc{*lc.src, cfg, *rc.log, *rc.mem, rc.cancel};
    for (auto& s : m.secs) {
      if (!(s.flags & elf::SHF_COMPRESSED) || !s.has_file_data()) continue;
      if (rc.cancel->cancelled()) return false;
      std::vector<u8> data;
      std::string err;
      bool was = false;
      u64 cap = std::min<u64>(256u << 20, rc.mem->limit() / 4);
      if (!rc.mem->try_reserve(cap / 4 + 1)) { rc.warn("strings", "not enough memory budget to decompress " + s.name); continue; }
      bool ok = elf_read_section(pc, m, s, data, cap, true, &was, err);
      rc.mem->release(cap / 4 + 1);
      if (!ok) {
        rc.warn("strings", "compressed section " + s.name + " not decompressed: " + err);
        rc.ledger.add_gap("unavailable", "strings in section " + s.name, "decompression failed: " + err, lc.index);
        continue;
      }
      rc.log->log(LogLevel::Info, "strings", strf("section %s decompressed: %zu bytes", s.name.c_str(), data.size()));
      sc.begin_range(true, s.index);
      sc.feed(0, data.data(), data.size());
      sc.end_range(data.size());
      sr.bytes_scanned += data.size();
    }
  }

  // ---- finish in-memory output ----
  if (rf && in_memory) {
    std::stable_sort(mem.begin(), mem.end(), [&](const StringRec& a, const StringRec& b) {
      if (group == "section") {
        if (a.decompressed != b.decompressed) return !a.decompressed;
        if (a.sec != b.sec) return a.sec < b.sec;
      } else if (group == "encoding") {
        if (a.enc != b.enc) return a.enc < b.enc;
      }
      if (sort == "length") return a.chars != b.chars ? a.chars > b.chars : a.off < b.off;
      if (sort == "alpha") {
        int c = a.text.compare(b.text);
        return c != 0 ? c < 0 : a.off < b.off;
      }
      return a.off < b.off;
    });
    std::string last_group = "\x01";
    for (auto& r : mem) {
      std::string g;
      if (group == "section") g = r.decompressed ? "decompressed " + sec_name(r) : sec_name(r);
      else if (group == "encoding") g = enc_name(r.enc);
      if (group != "none" && g != last_group) {
        rf->f().line("");
        rf->f().line("== " + g + " ==");
        last_group = g;
      }
      stream_write(r);
      if (!rf->f().open_for_more()) break;
    }
    rc.mem->release(mem_reserved);
  }
  sr.written = written;
  if (rf) {
    sr.truncated = rf->f().truncated();
    if (sr.memory_partial) rf->f().line("# NOTE: memory limit reached; the list above is incomplete");
    rf->f().line("");
    rf->f().line(strf("# total: %llu strings found (%llu written, %llu excluded by filters)", (unsigned long long)sr.total_found, (unsigned long long)written, (unsigned long long)sr.filtered_out));
    rf->finish();
  }
  if (stop_scan) {
    rc.ledger.add_gap("partial", "string count", "scan stopped when the output limit was reached; totals are a lower bound", lc.index);
  }
  if (sr.index_partial) rc.ledger.add_gap("partial", "string reference index", "memory or object limit reached; string xrefs may be incomplete", lc.index);
  std::sort(sr.index.begin(), sr.index.end());
  rc.ledger.add_counter("strings.found", sr.total_found);
  rc.log->log(LogLevel::Ok, "strings",
              strf("%llu strings (ascii %llu, utf-8 %llu, utf-16le %llu, utf-16be %llu); %llu written", (unsigned long long)sr.total_found, (unsigned long long)sr.by_enc[0],
                   (unsigned long long)sr.by_enc[1], (unsigned long long)sr.by_enc[2], (unsigned long long)sr.by_enc[3], (unsigned long long)written));
  return true;
}

}  // namespace kratos
