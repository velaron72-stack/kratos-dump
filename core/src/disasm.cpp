#include "kratos/disasm.h"

namespace kratos {

// ---------------------------------------------------------------- Cs
Cs::Cs(Arch arch, const Config& cfg, bool detail) : arch_(arch), detail_(detail) {
  cs_arch ca;
  int modes[2] = {0, 0};
  int n = 1;
  switch (arch) {
    case Arch::Arm64: ca = CS_ARCH_ARM64; modes[0] = CS_MODE_ARM; break;
    case Arch::Arm: ca = CS_ARCH_ARM; modes[0] = CS_MODE_ARM | CS_MODE_V8; modes[1] = CS_MODE_THUMB | CS_MODE_V8; n = 2; break;
    case Arch::X86_64: ca = CS_ARCH_X86; modes[0] = CS_MODE_64; break;
    case Arch::X86: ca = CS_ARCH_X86; modes[0] = CS_MODE_32; break;
    default: err_ = "architecture is not supported by the built-in disassembler"; return;
  }
  for (int i = 0; i < n; i++) {
    cs_err e = cs_open(ca, (cs_mode)modes[i], &h_[i]);
    if (e != CS_ERR_OK) {
      err_ = std::string("cs_open failed: ") + cs_strerror(e);
      return;
    }
    if (detail) cs_option(h_[i], CS_OPT_DETAIL, CS_OPT_ON);
    if (arch == Arch::X86_64 || arch == Arch::X86) cs_option(h_[i], CS_OPT_SYNTAX, cfg.s("disasm.x86_syntax") == "att" ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
    if (cfg.b("disasm.unsigned_imm")) cs_option(h_[i], CS_OPT_UNSIGNED, CS_OPT_ON);
    ins_[i] = cs_malloc(h_[i]);
    if (!ins_[i]) {
      err_ = "cs_malloc failed";
      return;
    }
  }
  if (n == 1) {
    h_[1] = h_[0];
    ins_[1] = ins_[0];
  }
  ok_ = true;
}

Cs::~Cs() {
  bool shared = (h_[0] == h_[1]);
  for (int i = 0; i < 2; i++) {
    if (shared && i == 1) break;
    if (ins_[i]) cs_free(ins_[i], 1);
    if (h_[i]) cs_close(&h_[i]);
  }
}

u32 Cs::unit(u8 mode) const {
  switch (arch_) {
    case Arch::Arm64: return 4;
    case Arch::Arm: return mode == MODE_THUMB ? 2 : 4;
    default: return 1;
  }
}
u32 Cs::refill(u8 mode) const {
  (void)mode;
  return (arch_ == Arch::X86 || arch_ == Arch::X86_64) ? 16 : 4;
}

bool arch_supported(Arch a) { return a == Arch::Arm64 || a == Arch::Arm || a == Arch::X86_64 || a == Arch::X86; }

Arch effective_arch(const LibContext& lc, const Config& cfg) {
  std::string o = cfg.s("disasm.arch");
  if (o == "arm64") return Arch::Arm64;
  if (o == "arm") return Arch::Arm;
  if (o == "x86_64") return Arch::X86_64;
  if (o == "x86") return Arch::X86;
  return lc.elf.arch;
}

bool direct_branch_target(Arch a, const cs_insn& in, u64& target, bool& is_call) {
  if (!in.detail) return false;
  bool call = false, jump = false;
  for (int i = 0; i < in.detail->groups_count; i++) {
    if (in.detail->groups[i] == CS_GRP_CALL) call = true;
    if (in.detail->groups[i] == CS_GRP_JUMP) jump = true;
  }
  if (!call && !jump) return false;
  is_call = call;
  bool found = false;
  if (a == Arch::Arm64) {
    const cs_arm64& d = in.detail->arm64;
    for (int i = 0; i < d.op_count; i++)
      if (d.operands[i].type == ARM64_OP_IMM) { target = (u64)d.operands[i].imm; found = true; }
  } else if (a == Arch::Arm) {
    const cs_arm& d = in.detail->arm;
    for (int i = 0; i < d.op_count; i++)
      if (d.operands[i].type == ARM_OP_IMM) { target = (u64)d.operands[i].imm; found = true; }
  } else {
    const cs_x86& d = in.detail->x86;
    for (int i = 0; i < d.op_count; i++)
      if (d.operands[i].type == X86_OP_IMM) { target = (u64)d.operands[i].imm; found = true; }
  }
  return found;
}

bool read_vaddr(const LibContext& lc, u64 vaddr, void* dst, size_t n) {
  u64 off;
  if (!lc.elf.vaddr_to_off(vaddr, off)) return false;
  return lc.src->read_exact(off, dst, n);
}

bool read_ptr(const LibContext& lc, u64 vaddr, u64& out) {
  u8 b[8];
  size_t n = (size_t)lc.elf.ptr_size();
  if (!read_vaddr(lc, vaddr, b, n)) return false;
  out = n == 8 ? rd64(b, lc.elf.le) : rd32(b, lc.elf.le);
  return true;
}

u8 mode_at(const LibContext& lc, u64 vaddr) {
  if (lc.arch != Arch::Arm || lc.spans.empty()) return MODE_ARM;
  size_t lo = 0, hi = lc.spans.size();
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (lc.spans[mid].start <= vaddr) lo = mid + 1;
    else hi = mid;
  }
  if (lo == 0) return MODE_ARM;
  const ModeSpan& s = lc.spans[lo - 1];
  return (vaddr < s.end) ? s.mode : (u8)MODE_ARM;
}

// ---------------------------------------------------------------- regions
void compute_code_regions(RunContext& rc, LibContext& lc, bool for_listing) {
  const Config& cfg = rc.cfg;
  const ElfModel& m = lc.elf;
  std::string scope = for_listing ? cfg.s("disasm.scope") : "exec_sections";
  std::vector<CodeRegion> out;

  auto add = [&](u64 va, u64 off, u64 size, int sec, const std::string& name) {
    if (off >= lc.size || size == 0) return;
    size = std::min(size, lc.size - off);
    u64 o2 = off, l2 = size;
    if (!lc.range.clip_file(m, o2, l2)) return;
    CodeRegion r;
    r.vaddr = va + (o2 - off);
    r.foff = o2;
    r.size = l2;
    r.sec = sec;
    r.name = name;
    out.push_back(r);
  };

  if (scope == "functions" && for_listing) {
    std::vector<const FuncRec*> fs;
    for (auto& f : lc.funcs.list)
      if (f.size > 0) fs.push_back(&f);
    u64 last_end = 0;
    for (auto* f : fs) {
      u64 off;
      if (!m.vaddr_to_off(f->vaddr, off)) continue;
      u64 va = f->vaddr, sz = f->size;
      if (va < last_end) {
        if (va + sz <= last_end) continue;
        sz -= last_end - va;
        off += last_end - va;
        va = last_end;
      }
      add(va, off, sz, f->sec, f->name);
      last_end = va + sz;
    }
    if (out.empty()) rc.warn("disasm", "scope=functions selected but no functions with known size exist; falling back to executable sections");
    else {
      lc.regions = out;
      return;
    }
    scope = "exec_sections";
  }

  if (scope == "exec_sections") {
    for (auto& s : m.secs)
      if (s.exec() && s.has_file_data() && s.size && s.addr) add(s.addr, s.offset, s.size, s.index, s.name);
    if (out.empty()) {
      if (!m.secs_ok && !m.secs_reconstructed) rc.log->log(LogLevel::Info, "disasm", "no section table: using executable segments");
      scope = "exec_segments";
    }
  }
  if (scope == "exec_segments") {
    for (auto& s : m.segs)
      if (s.type == elf::PT_LOAD && (s.flags & elf::PF_X) && s.filesz) add(s.vaddr, s.offset, s.filesz, m.section_for_vaddr(s.vaddr), strf("seg%d", s.index));
  }
  std::sort(out.begin(), out.end(), [](const CodeRegion& a, const CodeRegion& b) { return a.vaddr < b.vaddr; });
  lc.regions = out;
}

// ---------------------------------------------------------------- ARM mode spans
u8 guess_arm_mode(const LibContext& lc, Cs& cs, u64 vaddr) {
  if (vaddr & 1) return MODE_THUMB;
  if (vaddr & 2) return MODE_THUMB;  // not 4-byte aligned: cannot be an ARM-mode function start
  u8 buf[160];
  u64 off;
  if (!lc.elf.vaddr_to_off(vaddr, off)) return MODE_ARM;
  size_t n = lc.src->read_at(off, buf, sizeof buf);
  if (n < 8) return MODE_ARM;
  int score[2] = {0, 0};
  for (int mode = 0; mode < 2; mode++) {
    const u8* code = buf;
    size_t size = n;
    u64 addr = vaddr;
    cs_insn* in = cs.insn(mode == 0 ? MODE_ARM : MODE_THUMB);
    csh h = cs.handle(mode == 0 ? MODE_ARM : MODE_THUMB);
    int count = 0;
    while (size >= 4 && count < 24) {
      const u8* c0 = code;
      if (!cs_disasm_iter(h, &code, &size, &addr, in)) {
        score[mode] -= 2;
        code = c0 + (mode == 0 ? 4 : 2);
        size = size >= (mode == 0 ? 4u : 2u) ? size - (mode == 0 ? 4 : 2) : 0;
        addr += mode == 0 ? 4 : 2;
      } else {
        if (mode == 0) {
          u32 w = rd32(c0, lc.elf.le);
          u32 cond = w >> 28;
          score[0] += (cond == 0xE) ? 1 : (cond == 0xF ? 0 : -1);
          if (w == 0) score[0] -= 2;
          // Words that are typical of ARM-mode code and PLT stubs (push/pop of lr, bx lr, add ip,pc / ldr pc,[ip,#d]!).
          if ((w & 0xffff0000u) == 0xe92d0000u || (w & 0xffff0000u) == 0xe8bd0000u || w == 0xe12fff1eu || w == 0xe52de004u || w == 0xe49de004u ||
              (w & 0xfffff000u) == 0xe28fc000u || (w & 0xfffff000u) == 0xe5bcf000u || (w & 0xfffff000u) == 0xe5bef000u)
            score[0] += 3;
        } else {
          score[1] += 1;
          if (in->size == 2 && in->bytes[0] == 0 && in->bytes[1] == 0) score[1] -= 2;
          // Typical Thumb markers: push {..,lr}, pop {..,pc}, bx lr, push.w/pop.w.
          if (in->size == 2) {
            u32 hw = lc.elf.le ? (u32)(in->bytes[0] | (in->bytes[1] << 8)) : (u32)((in->bytes[0] << 8) | in->bytes[1]);
            if ((hw & 0xff00u) == 0xb500u || (hw & 0xff00u) == 0xbd00u || hw == 0x4770u) score[1] += 3;
          } else if (in->size == 4) {
            u32 hw = lc.elf.le ? (u32)(in->bytes[0] | (in->bytes[1] << 8)) : (u32)((in->bytes[0] << 8) | in->bytes[1]);
            if (hw == 0xe92du || hw == 0xe8bdu) score[1] += 3;
          }
        }
      }
      count++;
    }
  }
  return score[1] > score[0] ? MODE_THUMB : MODE_ARM;
}

namespace {
struct SpanMap {
  std::map<u64, ModeSpan> m;
  // Adds the part of [a,b) not yet covered.
  void add_uncovered(u64 a, u64 b, u8 mode, u8 conf) {
    if (a >= b) return;
    u64 cur = a;
    auto it = m.upper_bound(a);
    if (it != m.begin()) {
      auto p = std::prev(it);
      if (p->second.end > cur) cur = p->second.end;
    }
    while (cur < b) {
      auto nx = m.lower_bound(cur);
      u64 stop = (nx == m.end()) ? b : std::min(b, nx->first);
      if (stop > cur) m[cur] = ModeSpan{cur, stop, mode, conf};
      if (nx == m.end()) break;
      cur = std::max(stop, nx->second.end);
    }
  }
};
}  // namespace


// ARM-mode PLT blocks are recognised by their header (str lr,[sp,#-4]! ...) and the typical stub words, so they stay ARM even when
// the library has no section headers and no mapping symbols. Returns the number of blocks found.
static bool arm_plt_word(u32 w) {
  const u32 hi = w & 0xfffff000u;
  return w == 0xe52de004u || w == 0xe59fe004u || w == 0xe08fe00eu || hi == 0xe28fe000u || hi == 0xe28ee000u || hi == 0xe5bef000u || hi == 0xe28fc000u ||
         hi == 0xe28cc000u || hi == 0xe5bcf000u;
}

static size_t mark_arm_plt(LibContext& lc, SpanMap& sm, const CodeRegion& rg) {
  size_t found = 0;
  const size_t kChunk = 1u << 20;
  std::vector<u8> buf(kChunk + 4096);
  u64 va = rg.vaddr;
  const u64 end = rg.vaddr + rg.size;
  while (va + 20 <= end) {
    size_t want = (size_t)std::min<u64>(end - va, kChunk + 4096);
    size_t got = lc.src->read_at(rg.foff + (va - rg.vaddr), buf.data(), want);
    if (got < 20) break;
    const size_t limit = got >= kChunk + 4096 ? kChunk : got;  // the last 4 KiB overlaps the next chunk
    for (size_t i = 0; i + 20 <= got && i < limit; i += 4) {
      u64 a = va + i;
      if (a & 3) continue;
      if (rd32(&buf[i], lc.elf.le) != 0xe52de004u) continue;
      u32 w2 = rd32(&buf[i + 4], lc.elf.le);
      if (w2 != 0xe59fe004u && (w2 & 0xfffff000u) != 0xe28fe000u) continue;
      bool ldr_pc = false;
      for (int k = 2; k <= 4; k++) ldr_pc |= (rd32(&buf[i + 4 * (size_t)k], lc.elf.le) & 0xfffff000u) == 0xe5bef000u;
      if (!ldr_pc) continue;
      // Extend over the stubs: only PLT words and one repeated filler word are allowed.
      size_t j = i + 4, last = i;
      u32 filler = 0;
      bool have_filler = false;
      size_t stubs = 0;
      while (j + 4 <= got) {
        u32 w = rd32(&buf[j], lc.elf.le);
        if (arm_plt_word(w)) {
          if ((w & 0xfffff000u) == 0xe28fc000u) stubs++;
          last = j;
        } else if (!have_filler && w != 0) {
          filler = w;
          have_filler = true;
        } else if (!(have_filler ? w == filler : w == 0)) {
          break;
        }
        j += 4;
      }
      if (stubs == 0) continue;
      u64 e = va + last + 4;
      for (int k = 0; k < 4 && va + (last + 4 + 4 * (size_t)k) + 4 <= va + got; k++) {
        u32 w = rd32(&buf[last + 4 + 4 * (size_t)k], lc.elf.le);
        if (!(have_filler ? w == filler : w == 0)) break;
        e += 4;
      }
      sm.add_uncovered(a, e, MODE_ARM, 2);
      found++;
      i = (size_t)(e - va) - 4;
    }
    if (got < kChunk + 4096) break;
    va += kChunk;
  }
  return found;
}

void compute_arm_spans(RunContext& rc, LibContext& lc, Cs& cs) {
  lc.spans.clear();
  lc.spans_ready = true;
  if (lc.arch != Arch::Arm) return;
  const ElfModel& m = lc.elf;
  SpanMap sm;
  // disasm.arm_mode = arm or thumb forces one mode for all code. Data markers ($d) are still honoured.
  const std::string forced_name = rc.cfg.s("disasm.arm_mode");
  const bool force = forced_name == "arm" || forced_name == "thumb";
  const u8 fmode = forced_name == "thumb" ? (u8)MODE_THUMB : (u8)MODE_ARM;

  // 1. Mapping symbols ($a, $t, $d) from .symtab: the most reliable evidence.
  std::vector<std::pair<u64, u8>> marks;
  for (auto& s : m.symtab) {
    if (s.name.size() >= 2 && s.name[0] == '$' && (s.name[1] == 'a' || s.name[1] == 't' || s.name[1] == 'd') && (s.name.size() == 2 || s.name[2] == '.')) {
      marks.push_back({s.value, s.name[1] == 'a' ? (u8)MODE_ARM : (s.name[1] == 't' ? (u8)MODE_THUMB : (u8)MODE_DATA)});
    }
  }
  std::sort(marks.begin(), marks.end());
  size_t from_marks = 0;
  for (size_t i = 0; i < marks.size(); i++) {
    u64 a = marks[i].first, b = i + 1 < marks.size() ? marks[i + 1].first : 0;
    if (b == 0 || b <= a) {
      // Extend the last marker to the end of its section/segment.
      int si = m.section_for_vaddr(a);
      b = (si >= 0) ? m.secs[(size_t)si].addr + m.secs[(size_t)si].size : a;
    }
    if (force && marks[i].second != MODE_DATA) continue;
    sm.add_uncovered(a, b, marks[i].second, 2);
    from_marks++;
  }

  // 2. Function symbols: low bit tells Thumb.
  size_t from_syms = 0;
  for (auto* tab : {&m.symtab, &m.dynsym}) {
    if (force) break;
    for (auto& s : *tab) {
      if ((s.type() != elf::STT_FUNC && s.type() != elf::STT_GNU_IFUNC) || s.undefined() || s.size == 0) continue;
      bool thumb = (s.value & 1) != 0;
      u64 a = s.value & ~(u64)1;
      sm.add_uncovered(a, a + s.size, thumb ? MODE_THUMB : MODE_ARM, 1);
      from_syms++;
    }
  }

  // 3. Functions found by static sources (thumb flag known for symbol-derived ones).
  for (auto& f : lc.funcs.list) {
    if (f.size == 0 || force) continue;
    if (f.sources & (FS_SYMTAB | FS_DYNSYM)) sm.add_uncovered(f.vaddr, f.vaddr + f.size, f.thumb ? MODE_THUMB : MODE_ARM, 1);
  }

  // 3b. ARM PLT blocks recognised by their words.
  size_t from_plt = 0;
  if (!force)
    for (auto& rg : lc.regions) from_plt += mark_arm_plt(lc, sm, rg);

  // 4. Remaining executable bytes: guess per function-sized piece.
  std::vector<u64> starts;
  for (auto& f : lc.funcs.list) starts.push_back(f.vaddr);
  std::sort(starts.begin(), starts.end());
  size_t guessed = 0;
  for (auto& rg : lc.regions) {
    u64 pos = rg.vaddr, end = rg.vaddr + rg.size;
    while (pos < end) {
      auto it = sm.m.upper_bound(pos);
      if (it != sm.m.begin()) {
        auto p = std::prev(it);
        if (p->second.end > pos) {
          pos = p->second.end;
          continue;
        }
      }
      u64 gap_end = (it == sm.m.end()) ? end : std::min(end, it->first);
      // Split the gap at known function starts (or 4 KiB pieces).
      u64 a = pos;
      while (a < gap_end) {
        auto ns = std::upper_bound(starts.begin(), starts.end(), a);
        u64 b = gap_end;
        if (ns != starts.end()) b = std::min(b, *ns);
        if (b - a > 4096) b = a + 4096;
        if (b <= a) b = std::min(gap_end, a + 4);
        u8 md = force ? fmode : guess_arm_mode(lc, cs, a);
        sm.add_uncovered(a, b, md, force ? 3 : 0);
        guessed++;
        a = b;
      }
      pos = gap_end;
    }
  }
  // Merge neighbours with identical mode and confidence.
  for (auto& kv : sm.m) {
    if (!lc.spans.empty() && lc.spans.back().end == kv.second.start && lc.spans.back().mode == kv.second.mode && lc.spans.back().conf == kv.second.conf)
      lc.spans.back().end = kv.second.end;
    else lc.spans.push_back(kv.second);
  }
  rc.log->log(LogLevel::Info, "disasm", strf("ARM/Thumb spans: %zu (mapping symbols %zu, function symbols %zu, PLT blocks %zu, %s pieces %zu)", lc.spans.size(), from_marks, from_syms, from_plt, force ? "forced-mode" : "guessed", guessed));
}

// ---------------------------------------------------------------- sweep
bool sweep_region(RunContext& rc, LibContext& lc, Cs& cs, const CodeRegion& rg, bool skipdata, const InsnFn& on_insn, const DataFn& on_data, SweepStats& st) {
  const bool arm32 = cs.arch() == Arch::Arm && lc.spans_ready;
  u64 va = rg.vaddr;
  const u64 end = rg.vaddr + rg.size;
  std::vector<u8> buf((1u << 20) + 32);
  size_t si = 0;
  if (arm32) {
    size_t lo = 0, hi = lc.spans.size();
    while (lo < hi) {
      size_t mid = (lo + hi) / 2;
      if (lc.spans[mid].end <= va) lo = mid + 1;
      else hi = mid;
    }
    si = lo;
  }
  while (va < end) {
    if (rc.cancel->cancelled()) return false;
    if (st.stop) return true;
    u8 mode = MODE_ARM;
    u64 limit = end;
    if (arm32) {
      while (si < lc.spans.size() && lc.spans[si].end <= va) si++;
      if (si < lc.spans.size() && lc.spans[si].start <= va) {
        mode = lc.spans[si].mode;
        limit = std::min(end, lc.spans[si].end);
      } else {
        limit = std::min(end, si < lc.spans.size() ? lc.spans[si].start : end);
      }
    }
    if (mode == MODE_DATA) {
      on_data(va, (u32)std::min<u64>(limit - va, 0xFFFFFFFFu), MODE_DATA);
      st.bytes_data += limit - va;
      va = limit;
      continue;
    }
    size_t n = (size_t)std::min<u64>(limit - va, 1u << 20);
    size_t got = lc.src->read_at(rg.foff + (va - rg.vaddr), buf.data(), n);
    if (got == 0) {
      rc.warn("disasm", strf("read error at 0x%llx; rest of region skipped", (unsigned long long)va));
      return true;
    }
    n = got;
    const u8* code = buf.data();
    size_t size = n;
    u64 addr = va;
    cs_insn* in = cs.insn(mode);
    csh h = cs.handle(mode);
    while (size > 0) {
      if (st.stop) return true;
      const u8* c0 = code;
      size_t s0 = size;
      u64 a0 = addr;
      if (cs_disasm_iter(h, &code, &size, &addr, in)) {
        st.insns++;
        st.bytes_decoded += in->size;
        on_insn(*in, mode);
        continue;
      }
      if (size < cs.refill(mode) && a0 + size < limit && n == (size_t)std::min<u64>(limit - va, 1u << 20)) break;  // need more input
      u32 u = std::min<u32>(cs.unit(mode), (u32)size);
      st.undecodable++;
      if (!skipdata) {
        // Stop decoding this span at the first undecodable byte sequence.
        st.bytes_data += end - a0;
        on_data(a0, (u32)std::min<u64>(end - a0, 0xFFFFFFFFu), mode);
        return true;
      }
      on_data(a0, u, mode);
      st.bytes_data += u;
      code = c0 + u;
      size = s0 - u;
      addr = a0 + u;
    }
    if (addr == va) {  // no progress: avoid an endless loop
      st.bytes_data += 1;
      addr = va + 1;
    }
    va = addr;
  }
  return true;
}

}  // namespace kratos
