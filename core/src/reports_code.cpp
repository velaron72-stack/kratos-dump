// disassembly.txt, cross_references.txt and hex_dump.txt
#include "kratos/disasm.h"
#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

std::string printable(const u8* p, size_t n) {
  std::string r;
  for (size_t i = 0; i < n; i++) {
    u8 c = p[i];
    if (c == '"' || c == '\\') { r += '\\'; r += (char)c; }
    else if (c >= 32 && c < 127) r += (char)c;
    else if (c == '\n') r += "\\n";
    else if (c == '\t') r += "\\t";
    else if (c >= 0x80) r += (char)c;  // UTF-8 bytes are passed through
    else r += strf("\\x%02x", c);
  }
  return r;
}

// Describes an address: function name (+offset), PLT import or section.
class Namer {
 public:
  Namer(const LibContext& lc) : lc_(lc), m_(lc.elf), fr_(lc.funcs) {}
  std::string name_at(u64 a, bool allow_inside) const {
    u64 key = lc_.arch == Arch::Arm ? (a & ~(u64)1) : a;
    const auto& v = fr_.list;
    size_t lo = 0, hi = v.size();
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (v[mid].vaddr <= key) lo = mid + 1;
      else hi = mid;
    }
    if (lo > 0) {
      const FuncRec& f = v[lo - 1];
      if (f.vaddr == key) return f.name;
      if (allow_inside && f.size && key < f.vaddr + f.size) return strf("%s+0x%llx", f.name.c_str(), (unsigned long long)(key - f.vaddr));
    }
    return "";
  }
  std::string describe(u64 a) const {
    std::string n = name_at(a, true);
    if (!n.empty()) return n;
    int si = m_.section_for_vaddr(a);
    if (si >= 0) return strf("[%s+0x%llx]", m_.secs[(size_t)si].name.c_str(), (unsigned long long)(a - m_.secs[(size_t)si].addr));
    return "";
  }
  std::string string_at(u64 va) const {
    u64 off;
    if (!m_.vaddr_to_off(va, off)) return "";
    u8 buf[72];
    size_t n = lc_.src->read_at(off, buf, sizeof buf);
    size_t len = 0;
    while (len < n && buf[len] != 0 && (buf[len] >= 32 || buf[len] == '\n' || buf[len] == '\t' || buf[len] >= 0x80)) len++;
    if (len < 2) return "";
    std::string s = "\"" + printable(buf, std::min<size_t>(len, 60)) + (len > 60 || len == n ? "..." : "") + "\"";
    return s;
  }

 private:
  const LibContext& lc_;
  const ElfModel& m_;
  const FunctionsResult& fr_;
};

std::string hex_word_line(const u8* p, size_t n, bool le) {
  std::string s;
  for (size_t i = 0; i + 4 <= n; i += 4) s += strf("%s0x%08x", i ? ", " : "", rd32(p + i, le));
  return s;
}

}  // namespace

// ---------------------------------------------------------------- disassembly.txt
bool stage_report_disasm(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  if (!report_wanted(rc, "out.disassembly")) return true;
  const ElfModel& m = lc.elf;
  if (!lc.elf_ok) {
    report_unavailable(rc, lc.index, "disassembly.txt", "the library is not a readable ELF file");
    return true;
  }
  if (!arch_supported(lc.arch)) {
    report_unavailable(rc, lc.index, "disassembly.txt", std::string("architecture ") + arch_label(m.arch) + " (machine " + std::to_string(m.machine) + ") is not supported by the disassembler");
    return true;
  }
  const std::string dl = cfg.s("disasm.detail");
  const bool normal = dl != "minimal", full = dl == "full";
  const bool show_addr = cfg.b("disasm.show_address"), show_bytes = cfg.b("disasm.show_bytes");
  const bool show_syms = normal && cfg.b("disasm.show_symbols"), show_comments = full && cfg.b("disasm.show_comments"), show_refs = full && cfg.b("disasm.show_refs");
  Cs cs(lc.arch, cfg, show_syms || show_comments || show_refs);
  if (!cs.ok()) {
    report_failed(rc, lc.index, "disassembly.txt", "Capstone: " + cs.error());
    return false;
  }
  compute_code_regions(rc, lc, true);
  if (lc.regions.empty()) {
    report_unavailable(rc, lc.index, "disassembly.txt", "no executable code was located (no executable sections or segments, or the range is empty)");
    return true;
  }
  if (lc.arch == Arch::Arm && !lc.spans_ready) compute_arm_spans(rc, lc, cs);
  auto rf = open_report(rc, lc, "disassembly.txt", "disassembly", cfg.limit("limits.max_instructions"));
  if (!rf) return true;
  OutFile& f = rf->f();
  const bool arm32 = lc.arch == Arch::Arm;
  f.line(strf("# architecture: %s; scope: %s; addresses are virtual addresses (RVA = address - 0x%llx)", arch_label(lc.arch), cfg.s("disasm.scope").c_str(), (unsigned long long)m.load_base_rel));
  if (arm32) f.line("# ARM and Thumb code are separated by mapping symbols when present, otherwise by symbol parity and trial decoding (guessed spans may be wrong)");
  if (show_refs && lc.scan.xrefs.empty()) f.line("# references are shown only when cross-reference collection ran (analysis depth 4)");
  f.line("");

  Namer namer(lc);
  // Reference indexes
  std::vector<const XrefRec*> by_from;
  std::vector<std::pair<u64, u64>> by_to;
  if (show_comments || show_refs) {
    for (auto& x : lc.scan.xrefs) {
      if (show_comments && (x.type == XR_PCREL || x.type == XR_LITERAL || x.type == XR_STRING)) by_from.push_back(&x);
      if (show_refs && (x.type == XR_CALL || x.type == XR_JUMP) && x.confirmed) by_to.push_back({x.to, x.from});
    }
    std::stable_sort(by_from.begin(), by_from.end(), [](const XrefRec* a, const XrefRec* b) { return a->from < b->from; });
    std::sort(by_to.begin(), by_to.end());
  }
  size_t fi = 0;           // next function header
  size_t xf = 0;           // pointer into by_from
  u8 last_mode = 255;
  const CodeRegion* cur = nullptr;
  SweepStats st;
  u64 done = 0, total = 0;
  for (auto& r : lc.regions) total += r.size;
  std::string line;
  const u64 max_func_hdr = 0;
  (void)max_func_hdr;

  auto func_header = [&](u64 a) {
    while (fi < lc.funcs.list.size() && lc.funcs.list[fi].vaddr < a) fi++;
    while (fi < lc.funcs.list.size() && lc.funcs.list[fi].vaddr == a) {
      const FuncRec& fn = lc.funcs.list[fi];
      std::string srcs;
      func_src_names(fn.sources, srcs);
      f.line("");
      f.line(strf("; ---- %s%s  (%s confidence; %s%s) ----", fn.name.c_str(), fn.generated ? " [generated name]" : "", fn.conf >= 2 ? "high" : (fn.conf == 1 ? "medium" : "low"),
                  srcs.c_str(), fn.size ? strf("; size %s0x%llx", fn.size_known && !fn.size_est ? "" : "~", (unsigned long long)fn.size).c_str() : ""));
      fi++;
    }
  };

  for (auto& rg : lc.regions) {
    cur = &rg;
    if (normal) {
      f.line("");
      f.line(strf("; ======== %s  0x%llx - 0x%llx ========", rg.name.c_str(), (unsigned long long)rg.vaddr, (unsigned long long)(rg.vaddr + rg.size)));
    }
    // Skip function headers before this region
    while (fi < lc.funcs.list.size() && lc.funcs.list[fi].vaddr < rg.vaddr) fi++;
    bool ok = sweep_region(
        rc, lc, cs, rg, cfg.b("disasm.skipdata"),
        [&](const cs_insn& in, u8 mode) {
          if (!f.object()) {
            st.stop = true;
            return;
          }
          if (arm32 && mode != last_mode) {
            f.line(mode == MODE_THUMB ? "; -- thumb --" : "; -- arm --");
            last_mode = mode;
          }
          if (normal) func_header(in.address);
          if (show_refs && !by_to.empty()) {
            auto it = std::lower_bound(by_to.begin(), by_to.end(), std::make_pair((u64)in.address, (u64)0));
            if (it != by_to.end() && it->first == in.address) {
              std::string s = "; <- ";
              int k = 0;
              for (; it != by_to.end() && it->first == in.address && k < 4; ++it, ++k) s += (k ? ", " : "") + strf("0x%llx", (unsigned long long)it->second);
              if (it != by_to.end() && it->first == in.address) s += ", ...";
              f.line(s);
            }
          }
          line.clear();
          if (show_addr) line += strf("0x%08llx  ", (unsigned long long)in.address);
          if (show_bytes) {
            std::string b = bytes_hex(in.bytes, in.size);
            line += strf("%-*s  ", lc.arch == Arch::X86 || lc.arch == Arch::X86_64 ? 24 : 12, b.c_str());
          }
          line += in.mnemonic;
          if (in.op_str[0]) {
            line += ' ';
            line += in.op_str;
          }
          if (show_syms) {
            u64 t;
            bool call;
            if (direct_branch_target(lc.arch, in, t, call)) {
              std::string n = namer.name_at(t, true);
              if (!n.empty()) line += "  <" + n + ">";
            }
          }
          if (show_comments) {
            while (xf < by_from.size() && by_from[xf]->from < in.address) xf++;
            size_t k = xf;
            int shown = 0;
            while (k < by_from.size() && by_from[k]->from == in.address && shown < 2) {
              const XrefRec& x = *by_from[k];
              std::string note;
              if (x.type == XR_STRING) note = namer.string_at(x.to);
              else {
                std::string d = namer.describe(x.to);
                note = strf("0x%llx", (unsigned long long)x.to) + (d.empty() ? "" : " " + d);
              }
              if (!note.empty()) {
                line += (shown ? "  " : "  ; ") + std::string(x.confirmed ? "" : "(?) ") + note;
                shown++;
              }
              k++;
            }
          }
          f.line(line);
        },
        [&](u64 a, u32 sz, u8 mode) {
          if (st.stop) return;
          if (arm32 && mode == MODE_DATA && last_mode != MODE_DATA) {
            f.line("; -- data --");
            last_mode = MODE_DATA;
          }
          u64 shown = std::min<u64>(sz, 64);
          u8 buf[64];
          u64 off = cur->foff + (a - cur->vaddr);
          size_t got = lc.src->read_at(off, buf, (size_t)shown);
          if (!f.object()) {
            st.stop = true;
            return;
          }
          std::string s = strf("0x%08llx  ; data %u bytes: ", (unsigned long long)a, sz);
          if (lc.arch == Arch::X86 || lc.arch == Arch::X86_64) s += bytes_hex(buf, got);
          else if (got >= 4) s += hex_word_line(buf, got, m.le) + (got % 4 ? " +" + bytes_hex(buf + got - got % 4, got % 4) : "");
          else s += bytes_hex(buf, got);
          if (sz > shown) s += " ...";
          f.line(s);
          if (arm32) last_mode = MODE_DATA;
        },
        st);
    done += rg.size;
    rc.prog("disasm", done, total, "disassembly");
    if (!ok) {
      rf->abandon();
      return false;
    }
    if (st.stop) break;
  }
  f.line("");
  f.line(strf("# %llu instructions, %llu bytes decoded, %llu bytes shown as data, %llu undecodable positions", (unsigned long long)st.insns, (unsigned long long)st.bytes_decoded,
              (unsigned long long)st.bytes_data, (unsigned long long)st.undecodable));
  if (f.truncated()) rc.ledger.add_gap("partial", "disassembly.txt", "instruction/size limit reached; code after the cut is not listed", lc.index);
  rc.ledger.add_counter("disasm.insns", st.insns);
  close_report(rc, *rf);
  return true;
}

// ---------------------------------------------------------------- cross_references.txt
bool stage_report_xrefs(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  if (!report_wanted(rc, "out.cross_references")) return true;
  const ElfModel& m = lc.elf;
  if (cfg.i("general.depth") < 4) {
    report_skipped(rc, lc.index, "cross_references.txt", "cross references need analysis depth 4");
    return true;
  }
  if (!lc.elf_ok || !lc.scan.ran) {
    report_unavailable(rc, lc.index, "cross_references.txt", "the code scan did not run, so no references were collected");
    return true;
  }
  if (!arch_supported(lc.arch)) {
    report_unavailable(rc, lc.index, "cross_references.txt", "architecture is not supported by the disassembler");
    return true;
  }
  const AddrCols ac = AddrCols::from(cfg);
  const bool resolve = cfg.b("xref.resolve_plt");
  const bool heur = cfg.b("xref.include_heuristic");
  const int depth = (int)cfg.i("xref.depth");
  auto rf = open_report(rc, lc, "cross_references.txt", "cross references", cfg.limit("limits.max_xrefs"));
  if (!rf) return true;
  OutFile& f = rf->f();
  Namer namer(lc);
  std::unordered_map<u64, const PltStub*> plt;
  for (auto& s : lc.scan.plt) plt[s.addr] = &s;

  f.line("# CONFIRMED: computed from the explicit operands of decoded instructions (direct branches, ADR, RIP-relative operands, literal-pool slots, ADRP+ADD/LDR on one register).");
  f.line("# HEURISTIC:  depends on extra assumptions (literal-pool values, MOVW/MOVT chains, long register tracking, pointer tables in data). Treat as hints.");
  f.line("# Linear-sweep decoding cannot prove that a location is code: a reference found in data decoded as code is possible.");
  if (lc.scan.xref_partial) f.line("# PARTIAL: the reference limit was reached during the scan; code after the cut-off has no references.");
  if (!resolve) f.line("# PLT resolution is off (xref.resolve_plt).");

  // Resolve through stubs / thunks.
  auto resolve_target = [&](const XrefRec& x, std::string& extra) {
    u64 t = x.to;
    if (!resolve) return;
    int hops = 0;
    u64 key = lc.arch == Arch::Arm ? (t & ~(u64)1) : t;
    while (hops < depth) {
      auto p = plt.find(key);
      if (p != plt.end()) {
        extra = strf(" => %s (PLT stub 0x%llx%s)", p->second->name.empty() ? "<import>" : p->second->name.c_str(), (unsigned long long)p->second->addr,
                     hops ? strf(", %d hop%s", hops, hops > 1 ? "s" : "").c_str() : "");
        return;
      }
      auto th = lc.scan.thunks.find(key);
      if (th == lc.scan.thunks.end()) break;
      key = lc.arch == Arch::Arm ? (th->second & ~(u64)1) : th->second;
      hops++;
    }
    if (hops) {
      std::string n = namer.name_at(key, false);
      extra = strf(" => 0x%llx%s (through %d thunk hop%s)", (unsigned long long)key, n.empty() ? "" : (" " + n).c_str(), hops, hops > 1 ? "s" : "");
    }
  };

  std::vector<const XrefRec*> conf, hv;
  for (auto& x : lc.scan.xrefs) (x.confirmed ? conf : hv).push_back(&x);
  auto cmp = [](const XrefRec* a, const XrefRec* b) { return a->from != b->from ? a->from < b->from : (a->to != b->to ? a->to < b->to : a->type < b->type); };
  std::stable_sort(conf.begin(), conf.end(), cmp);
  std::stable_sort(hv.begin(), hv.end(), cmp);

  auto write = [&](const std::vector<const XrefRec*>& v, const char* title) {
    f.line("");
    f.line(std::string("== ") + title + " ==");
    f.line("# columns: " + ac.header() + "type -> target   description");
    for (const XrefRec* x : v) {
      u64 off = 0;
      bool ho = m.vaddr_to_off(x->from, off);
      std::string line = ac.fmt(m, ho, off, true, x->from);
      line += strf("%-8s -> 0x%08llx", xref_type_name(x->type), (unsigned long long)x->to);
      if (x->thumb_target) line += " (thumb)";
      std::string d;
      if (x->type == XR_STRING) d = namer.string_at(x->to);
      else d = namer.describe(x->to);
      if (!d.empty()) line += "  " + d;
      std::string extra;
      if (x->type == XR_CALL || x->type == XR_JUMP) resolve_target(*x, extra);
      line += extra;
      if (x->note == 3) line += "  [indirect through a pointer slot]";
      if (!f.object()) return false;
      if (!f.line(line)) return false;
    }
    return true;
  };
  bool more = write(conf, "CONFIRMED");
  if (more && heur) write(hv, "HEURISTIC");
  else if (!heur && !hv.empty()) f.line(strf("# %zu heuristic references omitted (xref.include_heuristic is off)", hv.size()));
  f.line("");
  f.line(strf("# %zu confirmed and %zu heuristic references collected", conf.size(), hv.size()));
  rc.ledger.add_counter("xrefs.confirmed", conf.size());
  rc.ledger.add_counter("xrefs.heuristic", hv.size());
  close_report(rc, *rf);
  return true;
}

// ---------------------------------------------------------------- hex_dump.txt
bool stage_report_hex(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  if (!report_wanted(rc, "out.hex_dump")) return true;
  const int per = (int)std::max<i64>(4, std::min<i64>(64, cfg.i("out.hex_bytes_per_line")));
  const bool ascii = cfg.b("out.hex_ascii"), collapse = cfg.b("out.hex_collapse");
  u64 start = 0, len = lc.size;
  std::string scope_note = "whole file";
  if (cfg.s("out.hex_scope") == "range") {
    if (lc.range.active) {
      if (!lc.range.clip_file(lc.elf, start, len)) {
        report_unavailable(rc, lc.index, "hex_dump.txt", "the analysis range does not overlap the file");
        return true;
      }
      scope_note = "analysis range";
    } else {
      rc.warn("hex", "hex scope is 'range' but no range is set: the whole file is dumped");
      stage_note("range not set; whole file dumped");
    }
  }
  const u64 cap = cfg.limit("limits.max_hex_mb") * 1048576ull;
  bool cut = false;
  if (cap && len > cap) {
    len = cap;
    cut = true;
  }
  auto rf = open_report(rc, lc, "hex_dump.txt", "hex dump", 0);
  if (!rf) return true;
  OutFile& f = rf->f();
  f.line(strf("# scope: %s; offsets %llu..%llu of %llu bytes; %d bytes per line%s", scope_note.c_str(), (unsigned long long)start, (unsigned long long)(start + len),
              (unsigned long long)lc.size, per, collapse ? "; identical lines are collapsed to '*'" : ""));
  if (cut) f.line(strf("# source data limited to %llu MiB by the setting; the rest of the range is not dumped", (unsigned long long)(cap >> 20)));
  f.line("");
  std::vector<u8> buf((size_t)std::min<u64>(std::max<u64>(io_buffer_kb(cfg) * 1024ull, 4096), 4u << 20) / (size_t)per * (size_t)per);
  std::vector<u8> prev((size_t)per);
  bool have_prev = false, in_run = false;
  u64 pos = start, end = start + len, done = 0;
  const int wide = (start + len) > 0xffffffffull ? 16 : 8;
  while (pos < end && f.open_for_more()) {
    if (rc.cancel->cancelled()) {
      rf->abandon();
      return false;
    }
    size_t want = (size_t)std::min<u64>(buf.size(), end - pos);
    size_t got = lc.src->read_at(pos, buf.data(), want);
    if (got == 0) {
      rc.warn("hex", strf("read error at offset 0x%llx; the rest is not dumped", (unsigned long long)pos));
      rc.ledger.add_gap("partial", "hex_dump.txt", strf("read error at offset 0x%llx", (unsigned long long)pos), lc.index);
      break;
    }
    for (size_t i = 0; i < got && f.open_for_more(); i += (size_t)per) {
      size_t n = std::min<size_t>((size_t)per, got - i);
      const u8* p = buf.data() + i;
      if (collapse && n == (size_t)per && have_prev && memcmp(p, prev.data(), (size_t)per) == 0) {
        if (!in_run) {
          f.line("*");
          in_run = true;
        }
        continue;
      }
      in_run = false;
      std::string s = strf("%0*llx  ", wide, (unsigned long long)(pos + i));
      for (int k = 0; k < per; k++) {
        if ((size_t)k < n) s += strf("%02x ", p[k]);
        else s += "   ";
        if (k == per / 2 - 1) s += " ";
      }
      if (ascii) {
        s += " |";
        for (size_t k = 0; k < n; k++) s += (p[k] >= 32 && p[k] < 127) ? (char)p[k] : '.';
        s += "|";
      }
      f.line(s);
      if (n == (size_t)per) {
        memcpy(prev.data(), p, (size_t)per);
        have_prev = true;
      }
    }
    pos += got;
    done += got;
    rc.prog("hex", done, len, "hex dump");
  }
  f.line(strf("%0*llx", wide, (unsigned long long)end));
  if (cut) rc.ledger.add_gap("partial", "hex_dump.txt", "limited by the hex_dump source-size limit", lc.index);
  close_report(rc, *rf);
  return true;
}

}  // namespace kratos
