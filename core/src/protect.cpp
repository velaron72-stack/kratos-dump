// Detection of packing / obfuscation indicators. Everything reported here is an indicator, never proof.
#include <cmath>

#include "kratos/stages.h"

namespace kratos {

namespace {

double shannon(const u64* hist, u64 n) {
  if (n == 0) return 0;
  double h = 0;
  for (int i = 0; i < 256; i++) {
    if (!hist[i]) continue;
    double p = (double)hist[i] / (double)n;
    h -= p * std::log2(p);
  }
  return h;
}

struct Marker {
  const char* text;
  const char* title;
  const char* strength;
};
const Marker kMarkers[] = {
    {"UPX!", "UPX signature found in the file", "strong"},
    {"$Info: This file is packed with the UPX", "UPX banner found in the file", "strong"},
    {"Obfuscator-LLVM", "Obfuscator-LLVM compiler string found", "strong"},
};

const char* kProtectorNames[] = {"jiagu", "shella", "dexhelper", "secexe", "secmain", "mobisec", "nqshield", "protectclass", "ijiami", "bangcle"};

bool is_obf_name(const std::string& n) {
  if (n.size() < 4) return false;
  for (char c : n)
    if (c != 'I' && c != 'l' && c != '1' && c != 'O' && c != '0') return false;
  return true;
}

}  // namespace

bool stage_protection(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  ProtectionResult& pr = lc.prot;
  pr.ran = true;
  const ElfModel& m = lc.elf;
  const bool detailed = cfg.s("prot.detail") == "detailed";

  auto add = [&](const char* id, const std::string& title, const std::string& detail, const char* strength) {
    pr.indicators.push_back({id, title, detail, strength});
    rc.log->log(LogLevel::Info, "protect", "indicator: " + title);
  };

  // ---- structural indicators (no file reads) ----
  if (!lc.elf_ok) {
    add("not_elf", "the file is not a readable ELF", "the content does not start with a valid ELF header; only whole-file measurements are available", "strong");
  } else {
    size_t header_anoms = 0, seg_anoms = 0;
    for (auto& a : m.anomalies) {
      if (a.where == "e_ident" || a.where == "e_version" || a.where == "e_ehsize" || a.where == "e_type" || a.where == "e_machine") header_anoms++;
      if (a.where == "PT_LOAD" || a.where == "program headers" || a.where == "e_phnum") seg_anoms++;
    }
    if (header_anoms) add("header_nonstandard", "non-standard values in the ELF header", strf("%zu anomalies (see parser diagnostics)", header_anoms), "weak");
    if (seg_anoms) add("segments_damaged", "damaged or unusual program header table", strf("%zu anomalies in program headers", seg_anoms), "moderate");
    if (m.phdr_assumed) add("phdr_assumed", "program header table located by assumption", "e_phoff/e_phnum are unusable; the table was read from the standard position", "moderate");
    if (!m.secs_ok) {
      add("no_sections", m.shoff == 0 ? "section header table removed" : "section header table unusable",
          strf("e_shoff=0x%llx e_shnum=%u; analysis continues using program headers", (unsigned long long)m.shoff, m.shnum), "moderate");
    }
    if (m.secs_ok && m.symtab.empty() && m.symtab_declared == 0) add("stripped", "no .symtab (symbols stripped)", "common for release builds; function names rely on exports and other sources", "weak");
    if (!m.dyn_ok && m.type == 3) add("no_dynamic", "shared object without a readable dynamic section", "imports, exports and dependencies cannot be read normally", "moderate");
    if (m.entry != 0 && m.segs_ok && !m.is_exec_vaddr(m.entry & ~(u64)1)) add("entry_outside_code", "entry point is outside executable segments", strf("e_entry=0x%llx", (unsigned long long)m.entry), "moderate");
    for (auto& s : m.segs) {
      if (s.type == elf::PT_LOAD && (s.flags & elf::PF_W) && (s.flags & elf::PF_X)) {
        add("wx_segment", "writable and executable segment", strf("PT_LOAD #%d flags %s", s.index, seg_flags_str(s.flags).c_str()), "moderate");
        break;
      }
    }
    // Overlapping loads.
    for (size_t i = 0; i < m.segs.size(); i++) {
      for (size_t j = i + 1; j < m.segs.size(); j++) {
        const auto &a = m.segs[i], &b = m.segs[j];
        if (a.type != elf::PT_LOAD || b.type != elf::PT_LOAD || !a.memsz || !b.memsz) continue;
        if (a.vaddr < b.vaddr + b.memsz && b.vaddr < a.vaddr + a.memsz) {
          add("loads_overlap", "overlapping PT_LOAD segments", strf("segments #%d and #%d overlap in memory", a.index, b.index), "moderate");
          i = m.segs.size();
          break;
        }
      }
    }
    // Symbol names.
    {
      size_t named = 0, obf = 0;
      for (auto* tab : {&m.dynsym, &m.symtab})
        for (auto& s : *tab)
          if (!s.name.empty()) {
            named++;
            obf += is_obf_name(s.name);
          }
      if (named >= 20 && obf * 10 >= named * 3) add("obf_names", "symbol names look obfuscated", strf("%zu of %zu names consist only of I/l/1/O/0", obf, named), "moderate");
    }
    // Non-standard section names.
    if (m.secs_ok) {
      size_t odd = 0, total = 0;
      for (auto& s : m.secs) {
        if (s.index == 0) continue;
        total++;
        if (!s.name.empty() && s.name[0] != '.') odd++;
      }
      if (total >= 8 && odd * 2 > total) add("odd_sections", "most section names are non-standard", strf("%zu of %zu section names do not start with '.'", odd, total), "weak");
    }
    // File shorter than its program headers declare.
    {
      u64 missing = 0;
      int cut = 0;
      for (auto& sg : m.segs)
        if (sg.type == elf::PT_LOAD && sg.filesz && sg.offset + sg.filesz > lc.size) {
          cut++;
          missing += sg.offset + sg.filesz - std::max(lc.size, sg.offset);
        }
      if (cut) add("truncated_file", "the file ends before the data its program headers declare", strf("%d loadable segment(s) extend past the end of the file; about %llu bytes are missing", cut, (unsigned long long)missing), "moderate");
    }
  }
  // Known protector library names (APK mode).
  {
    std::string low = to_lower(base_name(lc.entry_name));
    for (auto n : kProtectorNames) {
      if (low.find(n) != std::string::npos) {
        add("protector_name", "library name resembles a known app protector", "name contains \"" + std::string(n) + "\"", "weak");
        pr.related.push_back({"protector_name", lc.entry_name, std::string("name contains \"") + n + "\""});
        break;
      }
    }
  }

  // ---- content scan: entropy, markers, trailing data ----
  struct SegScan {
    int seg;
    u64 off, size;
    u64 hist[256];
    u64 n = 0;
    u32 flags;
  };
  std::vector<std::unique_ptr<SegScan>> ss;
  for (auto& s : m.segs) {
    if (s.type != elf::PT_LOAD || s.filesz == 0 || s.offset >= lc.size) continue;
    auto p = std::unique_ptr<SegScan>(new SegScan());
    p->seg = s.index;
    p->off = s.offset;
    p->size = std::min(s.filesz, lc.size - s.offset);
    p->flags = s.flags;
    memset(p->hist, 0, sizeof p->hist);
    ss.push_back(std::move(p));
  }
  u64 whole[256];
  memset(whole, 0, sizeof whole);
  u64 whole_n = 0;
  const size_t kChunk = 1u << 20;
  std::vector<u8> buf(kChunk + 64);
  std::vector<bool> marker_hit(sizeof(kMarkers) / sizeof(kMarkers[0]), false);
  size_t carry = 0;
  u64 pos = 0;
  while (pos < lc.size) {
    if (rc.cancel->cancelled()) return false;
    size_t n = (size_t)std::min<u64>(kChunk, lc.size - pos);
    size_t got = lc.src->read_at(pos, buf.data() + carry, n);
    if (got == 0) break;
    const u8* d = buf.data() + carry;
    for (size_t i = 0; i < got; i++) whole[d[i]]++;
    whole_n += got;
    for (auto& s : ss) {
      u64 a = std::max(pos, s->off), b = std::min(pos + got, s->off + s->size);
      if (a >= b) continue;
      for (u64 k = a; k < b; k++) s->hist[d[k - pos]]++;
      s->n += b - a;
    }
    // Marker search over carry + chunk.
    size_t total = carry + got;
    for (size_t mi = 0; mi < marker_hit.size(); mi++) {
      if (marker_hit[mi]) continue;
      size_t ml = strlen(kMarkers[mi].text);
      if (total >= ml && memmem(buf.data(), total, kMarkers[mi].text, ml)) marker_hit[mi] = true;
    }
    carry = std::min<size_t>(total, 63);
    memmove(buf.data(), buf.data() + total - carry, carry);
    pos += got;
    rc.prog("protect", pos, lc.size, "entropy scan");
  }
  pr.file_entropy = shannon(whole, whole_n);
  for (size_t i = 0; i < marker_hit.size(); i++)
    if (marker_hit[i]) add("marker", kMarkers[i].title, std::string("marker \"") + kMarkers[i].text + "\"", kMarkers[i].strength);

  for (auto& s : ss) {
    EntropyRec e;
    e.seg = s->seg;
    e.off = s->off;
    e.size = s->size;
    e.entropy = shannon(s->hist, s->n);
    e.flags = s->flags;
    pr.entropy.push_back(e);
    const bool exec = (s->flags & elf::PF_X) != 0;
    if (s->size >= 4096) {
      if (exec && e.entropy >= 7.2) add("exec_entropy", "executable segment has very high entropy", strf("segment #%d entropy %.3f bits/byte (typical machine code is below 6.8)", s->seg, e.entropy), "strong");
      else if (exec && e.entropy >= 6.9) add("exec_entropy", "executable segment has high entropy", strf("segment #%d entropy %.3f bits/byte", s->seg, e.entropy), "moderate");
      else if (!exec && s->size >= 65536 && e.entropy >= 7.5) add("data_entropy", "large high-entropy data segment", strf("segment #%d entropy %.3f bits/byte; may hold compressed or encrypted data", s->seg, e.entropy), "weak");
    }
  }

  // Windowed entropy of executable segments (detailed mode only, extra pass).
  if (detailed) {
    for (auto& e : pr.entropy) {
      if (!(e.flags & elf::PF_X) || e.size < 131072) continue;
      double lo = 8, hi = 0;
      u64 w = 65536, windows = 0, high = 0;
      for (u64 o = 0; o + w <= e.size && windows < 4096; o += w) {
        std::vector<u8> b;
        if (!lc.src->read_vec(e.off + o, w, b, w)) break;
        u64 h[256];
        memset(h, 0, sizeof h);
        for (u8 c : b) h[c]++;
        double en = shannon(h, w);
        lo = std::min(lo, en);
        hi = std::max(hi, en);
        windows++;
        high += en >= 7.2;
      }
      if (windows) {
        rc.log->log(LogLevel::Info, "protect", strf("segment #%d 64 KiB windows: min %.3f max %.3f, %llu of %llu above 7.2", e.seg, lo, hi, (unsigned long long)high, (unsigned long long)windows));
        if (high > 0 && high * 2 < windows) add("partial_entropy", "part of the executable segment has very high entropy", strf("segment #%d: %llu of %llu windows exceed 7.2 bits/byte", e.seg, (unsigned long long)high, (unsigned long long)windows), "moderate");
      }
    }
  }

  // Trailing data after the last structure.
  {
    u64 end = 0;
    for (auto& s : m.segs) end = std::max(end, s.offset + (s.type == elf::PT_NULL ? 0 : s.filesz));
    for (auto& s : m.secs)
      if (s.has_file_data() && !s.synthetic) end = std::max(end, s.offset + s.size);
    if (m.shoff && m.secs_ok) end = std::max(end, m.shoff + (u64)m.shnum * m.shentsize);
    if (m.phoff) end = std::max(end, m.phoff + (u64)m.phnum * m.phentsize);
    if (end && end < lc.size) {
      pr.trailing_bytes = lc.size - end;
      if (pr.trailing_bytes > 1024) {
        add("appended_data", "data after the last ELF structure", strf("%llu bytes after offset 0x%llx", (unsigned long long)pr.trailing_bytes, (unsigned long long)end), "moderate");
        if (cfg.b("prot.find_related")) {
          std::vector<u8> head;
          u64 n = std::min<u64>(16, lc.size - end);
          std::string kind = "appended_data";
          std::string detail = strf("%llu bytes at 0x%llx", (unsigned long long)pr.trailing_bytes, (unsigned long long)end);
          if (lc.src->read_vec(end, n, head, 16) && head.size() >= 4) {
            if (head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') { kind = "embedded_elf"; detail += ", starts with an ELF header"; }
            else if (head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) { kind = "embedded_zip"; detail += ", starts with a ZIP local header"; }
            else if (head[0] == 'd' && head[1] == 'e' && head[2] == 'x' && head[3] == '\n') { kind = "embedded_dex"; detail += ", starts with a DEX header"; }
          }
          pr.related.push_back({kind, lc.entry_name, detail});
        }
      }
    }
  }

  rc.ledger.add_counter("prot.indicators", pr.indicators.size());
  rc.log->log(LogLevel::Ok, "protect",
              strf("%zu indicator(s); file entropy %.3f bits/byte", pr.indicators.size(), pr.file_entropy));
  return true;
}

}  // namespace kratos
