// IL2CPP metadata (global-metadata.dat): signature, header, section table, string literals and identifiers.
// Type/method tables are not decoded: their record layout changes with every metadata version and cannot be
// verified here, so the report lists them by offset and size only.
#include <unistd.h>

#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

constexpr u32 kSanity = 0xFAB11BAFu;
constexpr i32 kMinVersion = 16, kMaxVersion = 31;
const char* const kPairNames[] = {"stringLiteral",   "stringLiteralData",  "string",           "events",         "properties",
                                  "methods",         "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
                                  "fieldMarshaledSizes", "parameters",     "fields",           "genericParameters", "genericParameterConstraints",
                                  "genericContainers", "nestedTypes",      "interfaces",       "vtableMethods",  "interfaceOffsets",
                                  "typeDefinitions"};
constexpr size_t kNamedPairs = sizeof(kPairNames) / sizeof(kPairNames[0]);

struct Sect {
  std::string name;
  u32 off = 0, size = 0;
  bool in_range = true;
};

struct Il2cpp {
  bool sanity = false;
  i32 version = 0;
  bool version_known = false;
  u32 header_size = 0;
  bool header_inferred = false;
  std::vector<Sect> sects;
  u64 file_size = 0;
  u64 literal_count = 0, literal_bad = 0, literal_chars = 0;
  bool literals_ok = false;
  u64 ident_count = 0, ident_bytes = 0;
  bool idents_ok = false, ident_unterminated = false;
  std::vector<std::string> images;
  bool images_found = false;
  std::vector<std::string> problems;
};

std::string escape_text(const u8* p, size_t n) {
  std::string o;
  o.reserve(n + 8);
  for (size_t i = 0; i < n;) {
    u8 c = p[i];
    if (c >= 0x20 && c < 0x7f) {
      if (c == '\\') o += "\\\\";
      else o += (char)c;
      i++;
    } else if (c == '\n') { o += "\\n"; i++; }
    else if (c == '\r') { o += "\\r"; i++; }
    else if (c == '\t') { o += "\\t"; i++; }
    else if (c >= 0xc2 && c < 0xf5) {
      size_t len = c < 0xe0 ? 2 : (c < 0xf0 ? 3 : 4);
      bool ok = i + len <= n;
      for (size_t k = 1; ok && k < len; k++) ok = (p[i + k] & 0xc0) == 0x80;
      if (ok) {
        o.append((const char*)p + i, len);
        i += len;
      } else {
        o += strf("\\x%02x", c);
        i++;
      }
    } else {
      o += strf("\\x%02x", c);
      i++;
    }
  }
  return o;
}

bool parse_header(const ByteSource& src, Il2cpp& m) {
  m.file_size = src.size();
  const size_t want = (size_t)std::min<u64>(m.file_size, 1024);
  std::vector<u8> h(want);
  if (want && src.read_at(0, h.data(), want) != want) {
    m.problems.push_back("read error while reading the header");
    return false;
  }
  if (want < 8) {
    m.problems.push_back(strf("the file is %llu bytes long: too short for an IL2CPP header", (unsigned long long)m.file_size));
    return false;
  }
  u32 sig = rd32(h.data(), true);
  if (sig != kSanity) {
    m.problems.push_back(strf("signature 0xFAB11BAF not found (the file starts with 0x%08x)", sig));
    return false;
  }
  m.sanity = true;
  m.version = (i32)rd32(h.data() + 4, true);
  m.version_known = m.version >= kMinVersion && m.version <= kMaxVersion;
  if (!m.version_known) m.problems.push_back(strf("metadata version %d is outside the range 16..31 this build was written for; the generic parts are still read", m.version));

  // The first table starts right after the header, so its offset is the header size.
  u32 hs = want >= 12 ? rd32(h.data() + 8, true) : 0;
  if (hs >= 16 && hs <= 1024 && hs <= m.file_size && hs <= want) {
    m.header_size = hs;
  } else {
    m.header_inferred = true;
    m.header_size = (u32)std::min<size_t>(want, 0x100);
    m.problems.push_back(strf("the header size could not be taken from the first table offset (0x%x); assuming %u bytes", hs, m.header_size));
  }
  if ((m.header_size - 8) % 8 != 0) m.problems.push_back(strf("header size %u is not 8 + 8*N; the incomplete tail is ignored", m.header_size));
  const size_t n = (m.header_size - 8) / 8;
  for (size_t i = 0; i < n; i++) {
    Sect s;
    s.name = i < kNamedPairs ? kPairNames[i] : strf("section_%zu", i);
    s.off = rd32(h.data() + 8 + i * 8, true);
    s.size = rd32(h.data() + 12 + i * 8, true);
    if (s.size != 0) {
      s.in_range = s.off >= m.header_size && (u64)s.off + s.size <= m.file_size;
      if (!s.in_range)
        m.problems.push_back(strf("%s: range [0x%x, 0x%llx) lies outside the file (size %llu)", s.name.c_str(), s.off, (unsigned long long)s.off + s.size,
                                  (unsigned long long)m.file_size));
    }
    m.sects.push_back(s);
  }
  return true;
}

const Sect* sect(const Il2cpp& m, size_t i) { return i < m.sects.size() ? &m.sects[i] : nullptr; }
bool usable(const Sect* s) { return s && s->size != 0 && s->in_range; }

bool read_ident_at(const ByteSource& src, const Sect& str, u32 index, std::string& out) {
  out.clear();
  if (index >= str.size) return false;
  size_t n = (size_t)std::min<u64>(260, str.size - index);
  std::vector<u8> b(n);
  if (src.read_at((u64)str.off + index, b.data(), n) != n) return false;
  size_t len = 0;
  while (len < n && b[len]) len++;
  if (len == n) return false;
  out.assign((const char*)b.data(), len);
  return true;
}

// Counts literals and identifiers; looks for the image table by structure.
void scan_counts(const ByteSource& src, Il2cpp& m, const CancelToken* cancel) {
  const Sect* lit = sect(m, 0);
  const Sect* dat = sect(m, 1);
  const Sect* str = sect(m, 2);
  if (usable(lit) && dat && dat->in_range) {
    m.literal_count = lit->size / 8;
    if (lit->size % 8) m.problems.push_back("stringLiteral table size is not a multiple of 8; the last partial record is ignored");
    std::vector<u8> buf;
    const u64 per = 8192;
    for (u64 i = 0; i < m.literal_count; i += per) {
      if (cancel && cancel->cancelled()) return;
      u64 cnt = std::min<u64>(per, m.literal_count - i);
      buf.resize((size_t)cnt * 8);
      if (src.read_at((u64)lit->off + i * 8, buf.data(), buf.size()) != buf.size()) {
        m.problems.push_back("read error in the stringLiteral table");
        break;
      }
      for (u64 k = 0; k < cnt; k++) {
        u32 len = rd32(&buf[k * 8], true), idx = rd32(&buf[k * 8 + 4], true);
        if ((u64)idx + len <= dat->size) m.literal_chars += len;
        else m.literal_bad++;
      }
    }
    m.literals_ok = true;
    if (m.literal_bad) m.problems.push_back(strf("%llu string literals point outside stringLiteralData", (unsigned long long)m.literal_bad));
  } else if (lit && lit->size) {
    m.problems.push_back("string literals are unavailable: the table or its data lies outside the file");
  }
  if (usable(str)) {
    std::vector<u8> buf(1u << 20);
    u64 pos = 0;
    u64 cur = 0;
    while (pos < str->size) {
      if (cancel && cancel->cancelled()) return;
      size_t n = (size_t)std::min<u64>(buf.size(), str->size - pos);
      if (src.read_at((u64)str->off + pos, buf.data(), n) != n) {
        m.problems.push_back("read error in the string table");
        return;
      }
      for (size_t i = 0; i < n; i++) {
        if (buf[i]) cur++;
        else {
          if (cur) {
            m.ident_count++;
            m.ident_bytes += cur;
          }
          cur = 0;
        }
      }
      pos += n;
    }
    if (cur) {
      m.ident_unterminated = true;
      m.ident_count++;
      m.ident_bytes += cur;
    }
    m.idents_ok = true;

    // Image table: 40-byte records (nameIndex first). Accepted only when every record passes a plausibility check.
    for (size_t i = 19; i < m.sects.size() && i < 27 && !m.images_found; i++) {
      const Sect& s = m.sects[i];
      if (!usable(&s) || s.size % 40 != 0 || s.size / 40 > 4096) continue;
      std::vector<std::string> names;
      bool ok = true;
      for (u32 r = 0; r < s.size / 40 && ok; r++) {
        u8 rec[4];
        if (src.read_at((u64)s.off + (u64)r * 40, rec, 4) != 4) { ok = false; break; }
        u32 ni = rd32(rec, true);
        std::string nm;
        ok = read_ident_at(src, *str, ni, nm) && nm.size() >= 5 && ends_with(to_lower(nm), ".dll");
        for (char c : nm) ok = ok && (unsigned char)c >= 0x20;
        if (ok) names.push_back(nm);
      }
      if (ok && !names.empty()) {
        m.images = names;
        m.images_found = true;
      }
    }
  }
}

Json info_json(const Il2cpp& m) {
  Json j = Json::object();
  j.set("version", m.version);
  j.set("version_in_supported_range", m.version_known);
  j.set("header_size", (u64)m.header_size);
  j.set("header_size_inferred", m.header_inferred);
  Json secs = Json::array();
  for (auto& s : m.sects) {
    Json o = Json::object();
    o.set("name", s.name);
    o.set("offset", (u64)s.off);
    o.set("size", (u64)s.size);
    o.set("in_range", s.in_range);
    secs.push(o);
  }
  j.set("sections", secs);
  Json lit = Json::object();
  lit.set("count", m.literal_count);
  lit.set("invalid", m.literal_bad);
  lit.set("total_bytes", m.literal_chars);
  lit.set("counted", m.literals_ok);
  j.set("string_literals", lit);
  Json id = Json::object();
  id.set("count", m.ident_count);
  id.set("total_bytes", m.ident_bytes);
  id.set("counted", m.idents_ok);
  j.set("identifiers", id);
  Json im = Json::array();
  for (auto& n : m.images) im.push(Json(n));
  j.set("images", im);
  j.set("images_found", m.images_found);
  Json pr = Json::array();
  for (auto& p : m.problems) pr.push(Json(p));
  j.set("problems", pr);
  return j;
}

bool find_entry(RunContext& rc, const std::string& full, ZipArchive*& z, const ZipEntry*& e) {
  z = rc.zip.get();
  std::string name = full;
  for (auto& kv : rc.nested_zips) {
    if (full.size() > kv.first.size() + 1 && full.compare(0, kv.first.size(), kv.first) == 0 && full[kv.first.size()] == '!') {
      z = kv.second.get();
      name = full.substr(kv.first.size() + 1);
      break;
    }
  }
  if (!z) return false;
  e = z->find(name);
  return e != nullptr;
}

// ---- library markers ----
struct LibMarkers {
  size_t exports = 0, symbols = 0;
  bool mentions_file = false;
  bool scanned = false;
};

LibMarkers lib_markers(RunContext& rc, LibContext& lc) {
  LibMarkers r;
  if (!lc.elf_ok) return r;
  for (auto& s : lc.elf.dynsym)
    if (!s.undefined() && starts_with(s.name, "il2cpp_")) r.exports++;
  for (auto& s : lc.elf.symtab)
    if (!s.undefined() && s.name.find("il2cpp") != std::string::npos) r.symbols++;
  if (lc.src) {
    static const char kNeedle[] = "global-metadata.dat";
    const size_t nl = sizeof(kNeedle) - 1;
    std::vector<char> buf((4u << 20) + nl);
    u64 off = 0;
    size_t carry = 0;
    const u64 size = lc.src->size();
    r.scanned = true;
    while (off < size) {
      if (rc.cancel->cancelled()) { r.scanned = false; break; }
      size_t n = (size_t)std::min<u64>(4u << 20, size - off);
      size_t got = lc.src->read_at(off, buf.data() + carry, n);
      if (got == 0) { r.scanned = false; break; }
      if (memmem(buf.data(), carry + got, kNeedle, nl)) {
        r.mentions_file = true;
        break;
      }
      size_t keep = std::min<size_t>(nl - 1, carry + got);
      memmove(buf.data(), buf.data() + carry + got - keep, keep);
      carry = keep;
      off += got;
    }
  }
  return r;
}

}  // namespace

bool stage_metadata(RunContext& rc) {
  MetaResult& mr = rc.meta;
  mr = MetaResult();
  mr.probed = true;
  const Config& cfg = rc.cfg;
  if (!cfg.flag("meta.handlers", "il2cpp")) {
    rc.ledger.add_gap("skipped", "metadata", "all metadata handlers are disabled in settings");
    stage_note("no metadata handler is enabled");
    return true;
  }
  std::string err;
  std::string local;
  const u64 max_extract = cfg.limit("limits.max_extract_mb") * 1048576ull;
  mkdirs(rc.meta_dir);

  if (rc.req.meta_fd >= 0) {
    mr.source = "file";
    mr.name = rc.req.meta_name.empty() ? "metadata.dat" : base_name(rc.req.meta_name);
    local = unique_path(path_join(rc.meta_dir, sanitize_filename(mr.name)));
    u64 copied = 0;
    rc.log->log(LogLevel::Info, "metadata", "copying the metadata file " + mr.name);
    if (!copy_fd_to_file(rc.req.meta_fd, local, rc.cancel, &copied, err)) {
      if (rc.cancel->cancelled()) return false;
      rc.error("metadata", "cannot read the metadata file: " + err);
      rc.ledger.add_gap("unavailable", "metadata", "the selected metadata file could not be read: " + err);
      mr.found = true;
      mr.status = "invalid";
      mr.notes.push_back("the file could not be read: " + err);
      return false;
    }
  } else if (rc.zip) {
    const MetaCandidate* cand = nullptr;
    const std::string& sel = rc.req.selected_meta;
    if (sel == "none") {
      rc.ledger.add_gap("skipped", "metadata", "the user chose to analyze without metadata");
      return true;
    }
    if (!sel.empty()) {
      for (auto& c : rc.apk.metas)
        if (c.entry == sel) cand = &c;
      if (!cand) {
        // The user may pick any entry: probe it directly.
        static MetaCandidate manual;
        manual = MetaCandidate();
        manual.entry = sel;
        manual.name = base_name(sel);
        manual.handler = "il2cpp";
        cand = &manual;
        mr.source = "manual";
      }
    } else if (cfg.b("meta.auto_find")) {
      for (auto& c : rc.apk.metas)
        if (c.status != "invalid" && !cand) cand = &c;
      if (!cand)
        for (auto& c : rc.apk.metas)
          if (!cand) cand = &c;
      mr.source = "auto";
    } else {
      rc.ledger.add_gap("skipped", "metadata", "automatic metadata search is off and no file was selected");
      return true;
    }
    if (!cand) {
      rc.log->log(LogLevel::Info, "metadata", "no metadata files found in the archive");
      if (cfg.b("meta.auto_find")) rc.ledger.add_gap("unavailable", "metadata", "no file recognized by an enabled metadata handler was found in the archive");
      return true;
    }
    if (mr.source.empty()) mr.source = "manual";
    mr.name = cand->name;
    ZipArchive* z = nullptr;
    const ZipEntry* e = nullptr;
    if (!find_entry(rc, cand->entry, z, e)) {
      rc.warn("metadata", "entry " + cand->entry + " not found in the archive");
      rc.ledger.add_gap("unavailable", "metadata", "entry " + cand->entry + " was not found in the archive");
      return true;
    }
    local = unique_path(path_join(rc.meta_dir, sanitize_filename(base_name(e->name))));
    u64 written = 0;
    ExtractNote note;
    rc.log->log(LogLevel::Info, "metadata", strf("extracting %s (%s)", cand->entry.c_str(), human_size(e->uncomp_size).c_str()));
    if (!z->extract_to_file(*e, local, max_extract, cfg.b("general.verify_input"), err, rc.cancel, &written, &note)) {
      if (rc.cancel->cancelled()) return false;
      rc.error("metadata", cand->entry + ": " + err);
      rc.ledger.add_gap("unavailable", "metadata", "extraction failed: " + err);
      mr.found = true;
      mr.status = "invalid";
      mr.notes.push_back("extraction failed: " + err);
      return false;
    }
    if (note.damaged) {
      rc.warn("metadata", cand->entry + ": the archive entry is damaged (" + note.text + "); the bytes that could be read were kept");
      rc.ledger.add_gap("partial", "metadata", "archive entry damaged: " + note.text);
      mr.notes.push_back("archive entry damaged: " + note.text);
      stage_partial("metadata entry damaged");
    }
  } else {
    rc.log->log(LogLevel::Info, "metadata", "no metadata file was provided");
    return true;
  }

  mr.found = true;
  mr.handler = "il2cpp";
  mr.local_path = local;
  mr.rel_path = local.size() > rc.run_dir.size() ? local.substr(rc.run_dir.size() + 1) : local;
  auto fs = FdSource::open_path(local, err);
  if (!fs) {
    rc.error("metadata", err);
    mr.status = "invalid";
    return false;
  }
  mr.size = fs->size();
  {
    FileRec fr;
    fr.name = base_name(local);
    fr.rel_path = mr.rel_path;
    fr.bytes = mr.size;
    rc.ledger.add_file(fr);
  }
  Il2cpp m;
  if (!parse_header(*fs, m)) {
    mr.status = "invalid";
    mr.notes = m.problems;
    mr.info = info_json(m);
    rc.warn("metadata", "the file is not valid IL2CPP metadata: " + (m.problems.empty() ? std::string("unknown reason") : m.problems[0]));
    rc.ledger.add_gap("unavailable", "metadata analysis", "the file is not valid IL2CPP metadata: " + (m.problems.empty() ? std::string("unknown") : m.problems[0]));
    return true;
  }
  scan_counts(*fs, m, rc.cancel);
  if (rc.cancel->cancelled()) return false;
  mr.info = info_json(m);
  bool any_bad = false;
  for (auto& s : m.sects)
    if (!s.in_range) any_bad = true;
  mr.status = !m.version_known ? "unsupported_version" : (any_bad ? "invalid" : "ok");
  for (auto& p : m.problems) mr.notes.push_back(p);
  if (any_bad) {
    rc.ledger.add_gap("partial", "metadata sections", "some section ranges lie outside the file; only readable sections are reported");
    stage_partial("metadata has out-of-range sections");
  }
  if (!m.version_known) {
    std::string why = "the metadata version is outside the range this build knows; only the generic parts (string literals, identifiers) were read";
    rc.warn("metadata", why);
    rc.ledger.add_gap("partial", "metadata analysis", why);
    stage_partial("metadata version is not supported");
  }
  rc.ledger.add_counter("metadata.string_literals", m.literal_count);
  rc.ledger.add_counter("metadata.identifiers", m.ident_count);
  rc.log->log((any_bad || !m.version_known) ? LogLevel::Warning : LogLevel::Ok, "metadata",
              strf("IL2CPP metadata v%d: %llu string literals, %llu identifiers%s", m.version, (unsigned long long)m.literal_count, (unsigned long long)m.ident_count,
                   any_bad ? " (damaged sections)" : ""));
  return true;
}

bool stage_metadata_report(RunContext& rc) {
  if (!report_wanted(rc, "out.metadata_report")) return true;
  const MetaResult& mr = rc.meta;
  if (!mr.found) return true;  // the gate in the executor records why there is no report
  if (mr.local_path.empty()) {
    report_unavailable(rc, -1, "metadata_report.txt", "the metadata file could not be read");
    return true;
  }
  std::string err;
  auto fs = FdSource::open_path(mr.local_path, err);
  if (!fs) {
    report_failed(rc, -1, "metadata_report.txt", err);
    stage_partial("cannot reopen the metadata file");
    return true;
  }
  const bool detailed = rc.cfg.s("meta.detail") == "detailed";
  ReportFile rf(rc, -1, "metadata_report.txt", rc.reports_root, "reports", rc.cfg.limit("limits.max_strings"));
  if (!rf.ok()) {
    report_failed(rc, -1, "metadata_report.txt", rf.create_error());
    stage_partial("metadata_report.txt could not be created");
    return true;
  }
  rf.header("metadata report", nullptr);
  OutFile& f = rf.f();
  f.line("handler: il2cpp");
  f.line("file: " + mr.name + "  (" + std::to_string(mr.size) + " bytes)");
  f.line("source: " + mr.source);
  f.line("status: " + mr.status);
  Il2cpp m;
  bool hdr = parse_header(*fs, m);
  if (!hdr) {
    f.line("");
    f.line("The file has no valid IL2CPP header:");
    for (auto& p : m.problems) f.line("  - " + p);
    f.line("");
    f.line("Nothing else can be read from this file.");
    close_report(rc, rf);
    return true;
  }
  scan_counts(*fs, m, rc.cancel);
  f.line(strf("metadata version: %d%s", m.version, m.version_known ? "" : "  (outside 16..31: not verified by this build)"));
  f.line(strf("header size: %u bytes%s", m.header_size, m.header_inferred ? "  (inferred)" : ""));
  f.line("");
  f.line("Sections (offset and size come from the header; the table layout is not decoded)");
  f.line(strf("%-36s %-12s %-12s %s", "name", "offset", "size", "state"));
  for (auto& s : m.sects) {
    f.line(strf("%-36s 0x%08x   0x%08x   %s", s.name.c_str(), s.off, s.size, s.size == 0 ? "empty" : (s.in_range ? "ok" : "OUT OF FILE")));
    f.object();
  }
  f.line("");
  f.line("Summary");
  if (m.literals_ok)
    f.line(strf("  string literals: %llu (%llu bytes of text%s)", (unsigned long long)m.literal_count, (unsigned long long)m.literal_chars,
                m.literal_bad ? strf(", %llu records point outside the data", (unsigned long long)m.literal_bad).c_str() : ""));
  else f.line("  string literals: not available");
  if (m.idents_ok) f.line(strf("  identifiers: %llu strings (%llu bytes)", (unsigned long long)m.ident_count, (unsigned long long)m.ident_bytes));
  else f.line("  identifiers: not available");
  if (m.images_found) {
    f.line(strf("  assembly images (found by structure check, %zu):", m.images.size()));
    for (auto& n : m.images) f.line("    " + n);
  } else {
    f.line("  assembly images: not determined (no table passed the structure check)");
  }
  if (!m.problems.empty()) {
    f.line("");
    f.line("Problems");
    for (auto& p : m.problems) f.line("  - " + p);
  }

  // ---- compatibility with the analyzed libraries ----
  if (rc.cfg.b("meta.check_compat")) {
    f.line("");
    f.line("Library compatibility (presence of IL2CPP markers only; the metadata version cannot be compared statically)");
    bool any = false;
    for (auto& lp : rc.libs) {
      LibContext& lc = *lp;
      any = true;
      if (!lc.elf_ok) {
        f.line("  " + lc.display + ": not a readable ELF file, no check possible");
        continue;
      }
      LibMarkers k = lib_markers(rc, lc);
      f.line(strf("  %s: il2cpp_* exports=%zu, il2cpp symbols in .symtab=%zu, mentions global-metadata.dat=%s -> %s", lc.display.c_str(), k.exports, k.symbols,
                  k.scanned ? (k.mentions_file ? "yes" : "no") : "unknown",
                  (k.exports || k.mentions_file || k.symbols) ? "IL2CPP markers present" : "no IL2CPP markers (stripped, protected or not an IL2CPP library)"));
    }
    if (!any) f.line("  no library was analyzed");
  }

  if (detailed && m.literals_ok && usable(sect(m, 0)) && usable(sect(m, 1))) {
    const Sect& lit = *sect(m, 0);
    const Sect& dat = *sect(m, 1);
    f.line("");
    f.line("String literals (index: text; control characters are escaped)");
    std::vector<u8> buf, text;
    const u64 per = 4096;
    bool more = true;
    for (u64 i = 0; i < m.literal_count && more; i += per) {
      if (rc.cancel->cancelled()) break;
      u64 cnt = std::min<u64>(per, m.literal_count - i);
      buf.resize((size_t)cnt * 8);
      if (fs->read_at((u64)lit.off + i * 8, buf.data(), buf.size()) != buf.size()) break;
      for (u64 k = 0; k < cnt && more; k++) {
        u32 len = rd32(&buf[k * 8], true), idx = rd32(&buf[k * 8 + 4], true);
        if ((u64)idx + len > dat.size) {
          more = f.line(strf("%llu: <invalid record len=%u index=%u>", (unsigned long long)(i + k), len, idx));
        } else {
          u32 take = (u32)std::min<u64>(len, syscap::kMaxStringLen);
          text.resize(take);
          if (take && fs->read_at((u64)dat.off + idx, text.data(), take) != take) { text.clear(); }
          more = f.line(strf("%llu: ", (unsigned long long)(i + k)) + escape_text(text.data(), text.size()) + (take < len ? " ...(cut)" : ""));
        }
        f.object();
        if (!f.open_for_more()) more = false;
      }
    }
  }
  if (detailed && m.idents_ok && usable(sect(m, 2)) && f.open_for_more()) {
    const Sect& str = *sect(m, 2);
    f.line("");
    f.line("Identifiers (string table; offset: text)");
    std::vector<u8> buf(1u << 20);
    std::string cur;
    u64 cur_off = 0, pos = 0;
    bool more = true;
    while (pos < str.size && more) {
      if (rc.cancel->cancelled()) break;
      size_t n = (size_t)std::min<u64>(buf.size(), str.size - pos);
      if (fs->read_at((u64)str.off + pos, buf.data(), n) != n) break;
      for (size_t i = 0; i < n && more; i++) {
        if (buf[i]) {
          if (cur.empty()) cur_off = pos + i;
          if (cur.size() < syscap::kMaxStringLen) cur.push_back((char)buf[i]);
        } else if (!cur.empty()) {
          more = f.line(strf("0x%08llx: ", (unsigned long long)cur_off) + escape_text((const u8*)cur.data(), cur.size()));
          f.object();
          cur.clear();
          if (!f.open_for_more()) more = false;
        }
      }
      pos += n;
    }
    if (more && !cur.empty()) f.line(strf("0x%08llx: ", (unsigned long long)cur_off) + escape_text((const u8*)cur.data(), cur.size()));
  } else if (!detailed) {
    f.line("");
    f.line("The string lists are not included in the short report (setting \"Подробность отчёта\" = Кратко).");
  }
  close_report(rc, rf);
  return true;
}

Json probe_metadata_source(const ByteSource& src, const std::string& name) {
  Json out = Json::object();
  out.set("name", name);
  out.set("size", src.size());
  Il2cpp m;
  bool ok = parse_header(src, m);
  out.set("handler", "il2cpp");
  if (!ok) {
    out.set("status", "invalid");
    out.set("recognized", false);
  } else {
    out.set("recognized", true);
    out.set("status", m.version_known ? "ok" : "unsupported_version");
    out.set("version", m.version);
  }
  Json pr = Json::array();
  for (auto& p : m.problems) pr.push(Json(p));
  out.set("problems", pr);
  return out;
}

}  // namespace kratos
