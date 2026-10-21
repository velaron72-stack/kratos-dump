// ELF stage: runs the parser phases in the right order, applies the user settings and records what was recovered by fallbacks.
// Also hosts the independent cross-check with ELFIO.
#include <istream>
#include <streambuf>

#include <elfio/elfio.hpp>

#include "kratos/disasm.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

bool parse_range(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  std::string a = trim(cfg.s("lib.range_start")), b = trim(cfg.s("lib.range_end"));
  lc.range = RangeFilter();
  if (a.empty() && b.empty()) return true;
  u64 lo = 0, hi = ~(u64)0;
  if (!a.empty() && !parse_u64(a, lo)) {
    rc.warn("elf", "range start '" + a + "' is not a number; the range is ignored");
    rc.ledger.add_gap("skipped", "analysis range", "start value is not a valid number", lc.index);
    return false;
  }
  if (!b.empty() && !parse_u64(b, hi)) {
    rc.warn("elf", "range end '" + b + "' is not a number; the range is ignored");
    rc.ledger.add_gap("skipped", "analysis range", "end value is not a valid number", lc.index);
    return false;
  }
  if (lo >= hi) {
    rc.warn("elf", "range start is not below the end; the range is ignored");
    rc.ledger.add_gap("skipped", "analysis range", "start is not below the end", lc.index);
    return false;
  }
  lc.range.active = true;
  lc.range.vaddr_space = cfg.s("lib.range_space") == "vaddr";
  lc.range.lo = lo;
  lc.range.hi = hi;
  rc.log->log(LogLevel::Info, "elf", strf("analysis range (%s): 0x%llx - 0x%llx", lc.range.vaddr_space ? "virtual addresses" : "file offsets", (unsigned long long)lo,
                                         (unsigned long long)(hi == ~(u64)0 ? lc.size : hi)));
  return true;
}

// std::istream view over a ByteSource (read-only, seekable) for ELFIO.
class SrcBuf : public std::streambuf {
 public:
  explicit SrcBuf(const ByteSource& s) : s_(s), buf_(1 << 16) { setg(nullptr, nullptr, nullptr); }

 protected:
  int_type underflow() override {
    if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
    size_t n = s_.read_at(pos_, buf_.data(), buf_.size());
    if (n == 0) return traits_type::eof();
    base_ = pos_;
    pos_ += n;
    setg(buf_.data(), buf_.data(), buf_.data() + n);
    return traits_type::to_int_type(*gptr());
  }
  pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode) override {
    i64 cur = (i64)(base_ + (u64)(gptr() - eback()));
    if (!eback()) cur = (i64)pos_;
    i64 target = 0;
    if (dir == std::ios_base::beg) target = off;
    else if (dir == std::ios_base::cur) target = cur + off;
    else target = (i64)s_.size() + off;
    return seekpos((pos_type)target, std::ios_base::in);
  }
  pos_type seekpos(pos_type p, std::ios_base::openmode) override {
    if (p < 0) return pos_type(off_type(-1));
    u64 t = (u64)(off_type)p;
    if (eback() && t >= base_ && t <= base_ + (u64)(egptr() - eback())) {
      setg(eback(), eback() + (t - base_), egptr());
      return p;
    }
    pos_ = t;
    base_ = t;
    setg(nullptr, nullptr, nullptr);
    return p;
  }

 private:
  const ByteSource& s_;
  std::vector<char> buf_;
  u64 pos_ = 0, base_ = 0;
};

}  // namespace

bool stage_elf(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  ElfModel& m = lc.elf;
  m = ElfModel();
  lc.elf_ok = false;
  const u64 large = cfg.limit("perf.large_file_mb") * 1048576ull;
  lc.large_file = large && lc.size >= large;
  parse_range(rc, lc);

  ParseCtx pc{*lc.src, cfg, *rc.log, *rc.mem, rc.cancel};
  pc.diagnostics = cfg.b("lib.diagnostics") || cfg.b("expert.diagnostics");
  std::string err;
  if (!elf_parse_header(pc, m, err)) {
    rc.error("elf", lc.display + ": not a readable ELF file: " + err);
    rc.ledger.add_gap("unavailable", "ELF structure", err, lc.index);
    return false;
  }
  const bool alt = cfg.b("prot.alt_parse");
  const bool want_seg = cfg.b("lib.parse_segments"), want_sec = cfg.b("lib.parse_sections");

  if (want_seg) {
    elf_parse_segments(pc, m, alt);
  } else {
    rc.ledger.add_gap("skipped", "program headers", "disabled in settings: address translation and segment-based stages are limited", lc.index);
    stage_partial("segments disabled");
  }
  if (rc.cancel->cancelled()) return false;
  if (want_sec) elf_parse_sections(pc, m);
  else rc.ledger.add_gap("skipped", "section table", "disabled in settings", lc.index);
  if (!m.secs_ok && m.segs_ok && (alt || !want_sec)) {
    elf_reconstruct_sections(pc, m);
    if (m.secs_reconstructed) rc.ledger.add_gap("inferred", "sections", "pseudo sections were built from program headers; names and boundaries are approximate", lc.index);
  }
  if (cfg.b("lib.parse_dynamic")) elf_parse_dynamic(pc, m, alt);
  else rc.ledger.add_gap("skipped", "dynamic section", "disabled in settings: imports, exports and dependencies are unavailable", lc.index);
  if (rc.cancel->cancelled()) return false;

  const u64 max_sym = cfg.limit("limits.max_symbols"), max_rel = cfg.limit("limits.max_relocs");
  if (cfg.b("lib.parse_symbols")) {
    elf_parse_symbols(pc, m, alt);
    if (max_sym) {
      for (auto* v : {&m.dynsym, &m.symtab}) {
        if (v->size() > max_sym) {
          v->resize((size_t)max_sym);
          m.symbols_partial = true;
          rc.ledger.add_gap("partial", "symbols", strf("user limit of %llu symbols per table reached", (unsigned long long)max_sym), lc.index);
        }
      }
    }
  } else {
    rc.ledger.add_gap("skipped", "symbol tables", "disabled in settings", lc.index);
  }
  if (rc.cancel->cancelled()) return false;
  if (cfg.b("lib.parse_relocs")) {
    elf_parse_relocs(pc, m, alt);
    if (max_rel && m.relocs.size() > max_rel) {
      m.relocs.resize((size_t)max_rel);
      m.relocs_partial = true;
      rc.ledger.add_gap("partial", "relocations", strf("user limit of %llu relocations reached", (unsigned long long)max_rel), lc.index);
    }
    if (alt && cfg.b("prot.reparse") && cfg.b("lib.parse_symbols")) {
      u64 added = elf_reparse_symbols_from_relocs(pc, m);
      if (added) {
        rc.log->log(LogLevel::Info, "elf", strf("dynamic symbol table extended by %llu entries referenced from relocations", (unsigned long long)added));
        rc.ledger.add_gap("inferred", "dynamic symbols", strf("%llu symbols were added from indices found in relocations", (unsigned long long)added), lc.index);
      }
    }
  } else {
    rc.ledger.add_gap("skipped", "relocations", "disabled in settings: PLT names and relocations.txt are unavailable", lc.index);
  }
  if (cfg.b("lib.parse_notes")) elf_parse_notes(pc, m, alt);
  m.finish_derived();

  lc.arch = effective_arch(lc, cfg);
  lc.elf_ok = true;

  // ---- what was recovered rather than read ----
  if (!m.ident_note.empty()) rc.ledger.add_gap("inferred", "ELF identification", m.ident_note, lc.index);
  if (m.phdr_assumed) rc.ledger.add_gap("inferred", "program headers", "the table position from the header was invalid; the standard position was used", lc.index);
  if (m.dyn_from_segment) rc.ledger.add_gap("inferred", "dynamic section", "read through PT_DYNAMIC because the section table is unusable", lc.index);
  if (m.dynsym_from_dynamic) rc.ledger.add_gap("inferred", "dynamic symbols", "table located through the dynamic section; the entry count is derived from hash tables", lc.index);
  if (m.relocs_from_dynamic) rc.ledger.add_gap("inferred", "relocations", "tables located through the dynamic section", lc.index);
  if (m.symbols_partial) {
    rc.ledger.add_gap("partial", "symbols", "some symbol records are unreadable or over the limit", lc.index);
    stage_partial("symbol tables incomplete");
  }
  if (m.relocs_partial) {
    rc.ledger.add_gap("partial", "relocations", "relocation list is incomplete (damaged data or limit)", lc.index);
    stage_partial("relocations incomplete");
  }
  if (!m.segs_ok && want_seg) {
    rc.ledger.add_gap("unavailable", "program headers", "no valid program header table; address mapping is unavailable", lc.index);
    stage_partial("program headers unreadable");
  }
  if (!m.secs_ok && want_sec && !m.secs_reconstructed) {
    rc.ledger.add_gap("unavailable", "section table", "missing or damaged", lc.index);
    stage_partial("section table unreadable");
  }
  {
    u64 missing = 0;
    int cut = 0;
    for (auto& sg : m.segs)
      if (sg.type == elf::PT_LOAD && sg.filesz && sg.offset + sg.filesz > lc.size) {
        cut++;
        missing += sg.offset + sg.filesz - std::max(lc.size, sg.offset);
        pc.note(m, sg.offset, "PT_LOAD", strf("segment %d needs file bytes up to 0x%llx but the file ends at 0x%llx (truncated or damaged)", sg.index, (unsigned long long)(sg.offset + sg.filesz),
                                              (unsigned long long)lc.size));
      }
    if (cut) {
      rc.ledger.add_gap("partial", "file data", strf("%d loadable segment(s) extend past the end of the file (about %llu bytes missing): the file is truncated or damaged; analysis covers only the bytes present", cut,
                                                      (unsigned long long)missing),
                        lc.index);
      stage_partial("file is shorter than its program headers declare");
    }
  }
  if (!m.anomalies.empty()) {
    rc.log->log(LogLevel::Warning, "elf", strf("%zu format anomalies recorded", m.anomalies.size()));
    if (pc.diagnostics)
      for (size_t i = 0; i < m.anomalies.size() && i < 2000; i++)
        rc.log->log(LogLevel::Debug, "elf", strf("anomaly @0x%llx [%s] %s", (unsigned long long)m.anomalies[i].offset, m.anomalies[i].where.c_str(), m.anomalies[i].text.c_str()));
  }
  if (!arch_supported(lc.arch)) {
    rc.ledger.add_gap("unavailable", "disassembly", strf("architecture %s (machine %u) is not supported by the disassembler", arch_label(m.arch), m.machine), lc.index);
  }
  rc.ledger.add_counter("elf.segments", m.segs.size());
  rc.ledger.add_counter("elf.sections", m.secs.size());
  rc.ledger.add_counter("elf.dynsym", m.dynsym.size());
  rc.ledger.add_counter("elf.symtab", m.symtab.size());
  rc.ledger.add_counter("elf.relocs", m.relocs.size());
  rc.log->log(LogLevel::Ok, "elf",
              strf("%s %s-endian %d-bit: %zu segments, %zu sections%s, %zu dynamic symbols, %zu static symbols, %zu relocations", arch_label(m.arch), m.le ? "little" : "big",
                   m.is64 ? 64 : 32, m.segs.size(), m.secs.size(), m.secs_reconstructed ? " (reconstructed)" : "", m.dynsym.size(), m.symtab.size(), m.relocs.size()));
  return true;
}

bool stage_elfio_check(RunContext& rc, LibContext& lc) {
  ElfioCheck& ec = lc.elfio;
  ec = ElfioCheck();
  ec.ran = true;
  const u64 large = rc.cfg.limit("perf.large_file_mb") * 1048576ull;
  if (lc.large_file || (large && lc.size >= large)) {
    ec.error = "skipped: file is above the large-file threshold";
    rc.ledger.add_gap("skipped", "ELFIO cross-check", "file is above the large-file threshold", lc.index);
    return true;
  }
  SrcBuf sb(*lc.src);
  std::istream is(&sb);
  ELFIO::elfio reader;
  try {
    ec.loaded = reader.load(is, true);
  } catch (const std::exception& e) {
    ec.error = e.what();
  } catch (...) {
    ec.error = "unknown exception";
  }
  if (!ec.loaded) {
    if (ec.error.empty()) ec.error = "ELFIO rejected the file";
    rc.warn("elfio", "ELFIO could not load the file: " + ec.error);
    ec.diffs.push_back("ELFIO could not load the file (" + ec.error + "); the file is damaged or non-standard");
    stage_partial("ELFIO rejected the file");
    return true;
  }
  try {
    ec.sections = (u64)reader.sections.size();
    ec.segments = (u64)reader.segments.size();
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); i++) {
      ELFIO::section* s = reader.sections[i];
      if (!s) continue;
      if (s->get_type() == ELFIO::SHT_SYMTAB || s->get_type() == ELFIO::SHT_DYNSYM) {
        ELFIO::symbol_section_accessor acc(reader, s);
        ec.symbols += (u64)acc.get_symbols_num();
      }
    }
  } catch (const std::exception& e) {
    ec.diffs.push_back(std::string("ELFIO failed while reading tables: ") + e.what());
    stage_partial("ELFIO failed while reading tables");
  }
  const ElfModel& m = lc.elf;
  if (lc.elf_ok) {
    u64 our_secs = m.secs_reconstructed ? 0 : m.secs.size();
    u64 our_segs = m.segs_ok ? m.segs.size() : 0;
    if (m.secs_ok && !m.secs_reconstructed && ec.sections != our_secs) ec.diffs.push_back(strf("section count: parser %llu, ELFIO %llu", (unsigned long long)our_secs, (unsigned long long)ec.sections));
    if (m.segs_ok && !m.phdr_assumed && ec.segments != our_segs) ec.diffs.push_back(strf("segment count: parser %llu, ELFIO %llu", (unsigned long long)our_segs, (unsigned long long)ec.segments));
    u64 our_syms = m.dynsym_declared + m.symtab_declared;
    if (m.secs_ok && !m.secs_reconstructed && !m.dynsym_from_dynamic && ec.symbols != our_syms)
      ec.diffs.push_back(strf("declared symbol count: parser %llu, ELFIO %llu", (unsigned long long)our_syms, (unsigned long long)ec.symbols));
  }
  if (ec.diffs.empty()) {
    rc.log->log(LogLevel::Ok, "elfio", strf("ELFIO agrees: %llu sections, %llu segments, %llu symbol entries", (unsigned long long)ec.sections, (unsigned long long)ec.segments,
                                            (unsigned long long)ec.symbols));
  } else {
    for (auto& d : ec.diffs) rc.warn("elfio", d);
    stage_partial(strf("%zu discrepancies with ELFIO", ec.diffs.size()));
  }
  return true;
}

}  // namespace kratos
