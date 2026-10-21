// Code scan: one streaming linear sweep over executable regions that collects call targets, function prologues, PLT stubs,
// thunks and cross references for ARM64, ARM32 (ARM + Thumb), x86-64 and x86.
//
// Cross references are split into two classes:
//   confirmed - computed from the explicit operands of decoded instructions (direct branches, ADR, RIP-relative operands,
//               literal-pool slots, ADRP+ADD/LDR on the same register within a short window);
//   heuristic - depend on additional assumptions (values of literal pools, MOVW/MOVT chains, longer register tracking,
//               pointer tables found in data).
#include "kratos/disasm.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

struct Op {
  u8 t = 0;  // 0 none, 1 reg, 2 imm, 3 mem
  int reg = 0;
  i64 imm = 0;
  int base = 0, index = 0;
  i64 disp = 0;
  int sh_type = 0;
  unsigned sh_val = 0;
};

struct W {
  u64 addr = 0;
  u32 size = 0;
  unsigned id = 0;
  u8 mode = 0, n = 0;
  int cc = 0;
  bool wb = false, call = false, jump = false, ret = false, rel = false;
  Op o[6];
};

bool has_group(const cs_insn& in, int g) {
  for (int i = 0; i < in.detail->groups_count; i++)
    if (in.detail->groups[i] == g) return true;
  return false;
}

void summarize(Arch a, const cs_insn& in, u8 mode, W& w) {
  w = W();
  w.addr = in.address;
  w.size = in.size;
  w.id = in.id;
  w.mode = mode;
  w.call = has_group(in, CS_GRP_CALL);
  w.jump = has_group(in, CS_GRP_JUMP);
  w.ret = has_group(in, CS_GRP_RET);
  w.rel = has_group(in, CS_GRP_BRANCH_RELATIVE);
  auto put = [&](int i, Op& o, int type, int reg, i64 imm, int base, int index, i64 disp) {
    (void)i;
    o.t = (type == 1) ? 1 : (type == 2) ? 2 : (type == 3) ? 3 : 0;
    o.reg = reg;
    o.imm = imm;
    o.base = base;
    o.index = index;
    o.disp = disp;
  };
  if (a == Arch::Arm64) {
    const cs_arm64& d = in.detail->arm64;
    w.cc = d.cc;
    w.wb = d.writeback;
    w.n = (u8)std::min<int>(d.op_count, 6);
    for (int i = 0; i < w.n; i++) {
      const cs_arm64_op& o = d.operands[i];
      if (o.type == ARM64_OP_REG) put(i, w.o[i], 1, o.reg, 0, 0, 0, 0);
      else if (o.type == ARM64_OP_IMM) put(i, w.o[i], 2, 0, o.imm, 0, 0, 0);
      else if (o.type == ARM64_OP_MEM) put(i, w.o[i], 3, 0, 0, o.mem.base, o.mem.index, o.mem.disp);
      w.o[i].sh_type = o.shift.type;
      w.o[i].sh_val = o.shift.value;
    }
  } else if (a == Arch::Arm) {
    const cs_arm& d = in.detail->arm;
    w.cc = d.cc;
    w.wb = d.writeback;
    w.n = (u8)std::min<int>(d.op_count, 6);
    for (int i = 0; i < w.n; i++) {
      const cs_arm_op& o = d.operands[i];
      if (o.type == ARM_OP_REG) put(i, w.o[i], 1, o.reg, 0, 0, 0, 0);
      else if (o.type == ARM_OP_IMM) put(i, w.o[i], 2, 0, o.imm, 0, 0, 0);
      else if (o.type == ARM_OP_MEM) put(i, w.o[i], 3, 0, 0, o.mem.base, o.mem.index, o.mem.disp);
    }
  } else {
    const cs_x86& d = in.detail->x86;
    w.n = (u8)std::min<int>(d.op_count, 6);
    for (int i = 0; i < w.n; i++) {
      const cs_x86_op& o = d.operands[i];
      if (o.type == X86_OP_REG) put(i, w.o[i], 1, o.reg, 0, 0, 0, 0);
      else if (o.type == X86_OP_IMM) put(i, w.o[i], 2, 0, o.imm, 0, 0, 0);
      else if (o.type == X86_OP_MEM) put(i, w.o[i], 3, 0, 0, o.mem.base, o.mem.index, o.mem.disp);
    }
  }
}

u32 ror32(u32 v, unsigned r) {
  r &= 31;
  return r ? (v >> r) | (v << (32 - r)) : v;
}

class Scan {
 public:
  Scan(RunContext& rc, LibContext& lc, Cs& cs, bool xrefs_on)
      : rc_(rc), lc_(lc), m_(lc.elf), cs_(cs), r_(lc.scan), arch_(lc.arch), want_x_(xrefs_on) {
    const Config& cfg = rc.cfg;
    xt_call_ = cfg.flag("xref.types", "call");
    xt_jump_ = cfg.flag("xref.types", "jump");
    xt_pcrel_ = cfg.flag("xref.types", "pcrel");
    xt_lit_ = cfg.flag("xref.types", "literal");
    xt_str_ = cfg.flag("xref.types", "string") && !lc.strings.index.empty();
    u64 lim = cfg.limit("limits.max_xrefs");
    xcap_ = lim ? std::min<u64>(lim, syscap::kMaxObjects) : syscap::kMaxObjects;
    for (auto& s : m_.secs)
      if (!s.synthetic && s.name.find("plt") != std::string::npos && s.size) plt_ranges_.push_back({s.addr, s.addr + s.size});
    // Section headers count only when they describe executable allocated code; zeroed or junk tables do not.
    bool exec_sec = false;
    for (auto& sec : m_.secs)
      if (!sec.synthetic && sec.exec() && sec.alloc() && sec.size) exec_sec = true;
    have_secs_ = m_.secs_ok && !m_.secs_reconstructed && exec_sec;
    // GOT slot -> symbol index (jump slots, global data, absolute)
    for (auto& rl : m_.relocs) {
      if (rl.sym == 0 && !(rl.type && (reloc_is_jump_slot(m_, rl.type)))) continue;
      if (reloc_is_jump_slot(m_, rl.type) || reloc_is_glob_dat(m_, rl.type) || reloc_is_abs(m_, rl.type)) {
        if (got_sym_.size() < 4'000'000) got_sym_[rl.offset] = {rl.sym, rl.table};
      }
    }
    for (auto& d : m_.dyn)
      if (d.tag == elf::DT_PLTGOT) pltgot_ = d.val;
    if (!pltgot_) {
      const ElfSection* s = m_.section_by_name(".got.plt");
      if (s) pltgot_ = s->addr;
    }
  }

  void region_start() {
    boundary_ = true;
    rn_ = 0;
    clear_state();
  }
  void on_data(u64, u32, u8) {
    boundary_ = true;
    rn_ = 0;
    clear_state();
  }

  void on_insn(const cs_insn& in, u8 mode) {
    seq_++;
    W w;
    summarize(arch_, in, mode, w);
    bool in_plt = in_plt_range(w.addr);
    bool first = boundary_;
    bool terminator = false, nop = false;
    switch (arch_) {
      case Arch::Arm64: arm64(in, w, in_plt, first, terminator, nop); break;
      case Arch::Arm: arm32(in, w, in_plt, first, terminator, nop); break;
      default: x86(in, w, in_plt, first, terminator, nop); break;
    }
    if (terminator) {
      boundary_ = true;
      clear_state_pages_only();
    } else if (!nop) {
      boundary_ = false;
    }
    ring_[rn_ % kRing] = w;
    rn_++;
  }

  void finish() {
    // Resolve PLT stub names through relocations.
    for (auto& s : r_.plt) {
      auto it = got_sym_.find(s.got);
      if (it == got_sym_.end()) continue;
      const auto& tab = it->second.second == 1 ? m_.symtab : m_.dynsym;
      if (it->second.first < tab.size()) s.name = tab[it->second.first].name;
    }
    std::sort(r_.call_targets.begin(), r_.call_targets.end());
    r_.call_targets.erase(std::unique(r_.call_targets.begin(), r_.call_targets.end()), r_.call_targets.end());
    std::sort(r_.prologues.begin(), r_.prologues.end());
    std::vector<std::pair<u64, u8>> pr;
    for (auto& p : r_.prologues) {
      if (!pr.empty() && pr.back().first == p.first) pr.back().second = std::max(pr.back().second, p.second);
      else pr.push_back(p);
    }
    r_.prologues.swap(pr);
    std::sort(r_.plt.begin(), r_.plt.end(), [](const PltStub& a, const PltStub& b) { return a.addr < b.addr; });
    r_.plt.erase(std::unique(r_.plt.begin(), r_.plt.end(), [](const PltStub& a, const PltStub& b) { return a.addr == b.addr; }), r_.plt.end());
  }

 private:
  static constexpr int kRing = 8;
  RunContext& rc_;
  LibContext& lc_;
  const ElfModel& m_;
  Cs& cs_;
  CodeScanResult& r_;
  Arch arch_;
  bool want_x_;
  bool xt_call_ = true, xt_jump_ = true, xt_pcrel_ = true, xt_lit_ = true, xt_str_ = false;
  u64 xcap_ = 0;
  u64 seq_ = 0;
  bool boundary_ = true;
  bool have_secs_ = false;
  W ring_[kRing];
  u64 rn_ = 0;
  std::vector<std::pair<u64, u64>> plt_ranges_;
  std::unordered_map<u64, std::pair<u32, u8>> got_sym_;
  u64 pltgot_ = 0;

  // ARM64 state
  struct Page {
    bool v = false;
    u64 val = 0, seq = 0, at = 0;
  };
  Page pages_[32];
  struct Got {
    bool v = false;
    u64 got = 0, start = 0, seq = 0;
  };
  Got ldr_got_[32];
  u64 pending_prol_seq_ = 0;  // weak prologue waiting for confirmation
  size_t pending_prol_idx_ = ~(size_t)0;

  // ARM32 state
  struct Lit {
    bool v = false;
    u32 val = 0;
    u64 seq = 0, from = 0;
  };
  Lit lit_[16];
  struct Mov16 {
    int state = 0;  // 1 movw seen, 2 movt seen
    u32 lo = 0, hi = 0;
    u64 seq = 0, at = 0;
  };
  Mov16 mv_[16];
  struct Veneer {
    bool v = false;
    int reg = 0;
    u64 target = 0, start = 0, seq = 0;
  } ven_;

  bool in_plt_range(u64 a) const {
    for (auto& r : plt_ranges_)
      if (a >= r.first && a < r.second) return true;
    return false;
  }
  void clear_state() {
    for (auto& p : pages_) p.v = false;
    for (auto& g : ldr_got_) g.v = false;
    for (auto& l : lit_) l.v = false;
    for (auto& v : mv_) v.state = 0;
    ven_.v = false;
    pending_prol_idx_ = ~(size_t)0;
  }
  void clear_state_pages_only() { clear_state(); }
  const W* back(int k) const { return (rn_ >= (u64)k) ? &ring_[(rn_ - (u64)k) % kRing] : nullptr; }

  // ------------------------------------------------------------ output helpers
  void xref(u64 from, u64 to, u8 type, bool confirmed, bool thumb_target = false, u32 note = 0) {
    if (!want_x_) return;
    if (type == XR_CALL && !xt_call_) return;
    if (type == XR_JUMP && !xt_jump_) return;
    if (type == XR_PCREL && !xt_pcrel_) return;
    if (type == XR_LITERAL && !xt_lit_) return;
    if (!lc_.range.ok_va(m_, from)) return;
    if (r_.xrefs.size() >= xcap_) {
      r_.xref_partial = true;
      return;
    }
    if (!rc_.mem->try_reserve(sizeof(XrefRec))) {
      r_.xref_partial = true;
      return;
    }
    XrefRec x;
    x.from = from;
    x.to = to;
    x.type = type;
    x.confirmed = confirmed;
    x.thumb_target = thumb_target;
    x.note = note;
    r_.xrefs.push_back(x);
    if (xt_str_ && (type == XR_PCREL || type == XR_LITERAL)) string_ref(from, to, confirmed);
  }
  void string_ref(u64 from, u64 to, bool confirmed) {
    u64 off;
    if (!m_.vaddr_to_off(to, off)) return;
    const auto& idx = lc_.strings.index;
    auto it = std::upper_bound(idx.begin(), idx.end(), std::make_pair(off, (u32)0xffffffffu));
    if (it == idx.begin()) return;
    --it;
    if (off >= it->first && off <= it->first + it->second) {
      if (r_.xrefs.size() >= xcap_ || !rc_.mem->try_reserve(sizeof(XrefRec))) {
        r_.xref_partial = true;
        return;
      }
      XrefRec x;
      x.from = from;
      x.to = to;
      x.type = XR_STRING;
      x.confirmed = confirmed;
      r_.xrefs.push_back(x);
    }
  }
  void add_call_target(u64 t, bool thumb) {
    if (!m_.is_exec_vaddr(t)) return;
    if (r_.call_targets.size() < syscap::kMaxObjects && rc_.mem->try_reserve(8)) r_.call_targets.push_back(arch_ == Arch::Arm ? (t | (thumb ? 1 : 0)) : t);
  }
  void add_prologue(u64 a, u8 strength) {
    if (r_.prologues.size() >= syscap::kMaxObjects || !rc_.mem->try_reserve(16)) return;
    r_.prologues.push_back({a, strength});
    pending_prol_idx_ = strength < 2 ? r_.prologues.size() - 1 : ~(size_t)0;
    pending_prol_seq_ = seq_;
  }
  void upgrade_prologue() {
    if (pending_prol_idx_ != ~(size_t)0 && seq_ - pending_prol_seq_ <= 5 && pending_prol_idx_ < r_.prologues.size()) r_.prologues[pending_prol_idx_].second = 2;
    pending_prol_idx_ = ~(size_t)0;
  }
  void add_plt(u64 start, u64 got, u32 size, bool header = false) {
    if (r_.plt.size() >= 1'000'000) return;
    PltStub s;
    s.addr = start;
    s.got = got;
    s.size = size;
    s.header = header;
    r_.plt.push_back(s);
  }
  static int xr(int reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return reg - ARM64_REG_X0;
    if (reg == ARM64_REG_FP) return 29;
    if (reg == ARM64_REG_LR) return 30;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return reg - ARM64_REG_W0;
    return -1;
  }
  bool plt_like(u64 start) const { return in_plt_range(start) || (!have_secs_ && (start % 16) == 0); }

  // ------------------------------------------------------------ ARM64
  void arm64_clear_written(const cs_insn& in, u8 mode) {
    uint16_t rr[64], wr[64];
    uint8_t rc = 0, wc = 0;
    if (cs_regs_access(cs_.handle(mode), &in, rr, &rc, wr, &wc) != CS_ERR_OK) {
      for (auto& p : pages_) p.v = false;
      return;
    }
    for (int i = 0; i < wc; i++) {
      int x = xr(wr[i]);
      if (x >= 0 && x < 32) {
        pages_[x].v = false;
        if (ldr_got_[x].seq != seq_) ldr_got_[x].v = false;  // keep the load recorded by this very instruction
      }
    }
  }

  void arm64(const cs_insn& in, const W& w, bool in_plt, bool first, bool& terminator, bool& nop) {
    const u64 a = w.addr;
    nop = w.id == ARM64_INS_NOP;
    bool any_page = false;
    for (auto& p : pages_) any_page |= p.v;
    const bool emit = !in_plt;

    // 1. Use of tracked pages
    if (any_page) {
      for (int i = 0; i < w.n; i++) {
        const Op& o = w.o[i];
        if (o.t == 3 && o.index == 0) {
          int x = xr(o.base);
          if (x >= 0 && pages_[x].v && seq_ - pages_[x].seq <= 24) {
            u64 tgt = pages_[x].val + (u64)(i64)o.disp;
            if (emit) xref(a, tgt, XR_PCREL, seq_ - pages_[x].seq <= 8);
            if (w.id == ARM64_INS_LDR && w.n >= 1 && w.o[0].t == 1) {
              int dst = xr(w.o[0].reg);
              if (dst >= 0 && dst < 32) {
                ldr_got_[dst].v = true;
                ldr_got_[dst].got = tgt;
                ldr_got_[dst].start = pages_[x].at;
                ldr_got_[dst].seq = seq_;
              }
            }
          }
        }
      }
      if (w.id == ARM64_INS_ADD && w.n == 3 && w.o[0].t == 1 && w.o[1].t == 1 && w.o[2].t == 2) {
        int x = xr(w.o[1].reg);
        if (x >= 0 && pages_[x].v && seq_ - pages_[x].seq <= 24) {
          u64 imm = (u64)w.o[2].imm;
          if (w.o[2].sh_type == ARM64_SFT_LSL) imm <<= w.o[2].sh_val;
          u64 tgt = pages_[x].val + imm;
          if (emit) xref(a, tgt, XR_PCREL, seq_ - pages_[x].seq <= 8);
        }
      }
    }
    // PLT stub: adrp x16; ldr x17,[x16,#d]; add x16,x16,#d; br x17
    if (w.id == ARM64_INS_BR && w.n == 1 && w.o[0].t == 1) {
      int x = xr(w.o[0].reg);
      if (x == 17 && ldr_got_[17].v && seq_ - ldr_got_[17].seq <= 4) {
        u64 start = ldr_got_[17].start;
        const W* pb = nullptr;
        for (int k = 1; k <= 5; k++) {
          const W* p = back(k);
          if (p && p->addr + 4 == start) {
            pb = p;
            break;
          }
        }
        bool header = false;
        if (pb && (pb->id == ARM64_INS_BTI || pb->id == ARM64_INS_HINT || pb->id == ARM64_INS_PACIASP)) start = pb->addr;
        // PLT0 starts with "stp x16, x30, [sp, #-16]!" and jumps to the dynamic linker's resolver; it does not belong to one symbol.
        if (pb && pb->id == ARM64_INS_STP && pb->n >= 2 && pb->o[0].t == 1 && pb->o[1].t == 1 && xr(pb->o[0].reg) == 16 && xr(pb->o[1].reg) == 30) {
          start = pb->addr;
          header = true;
        }
        if (plt_like(start) && (in_plt || !have_secs_)) add_plt(start, ldr_got_[17].got, (u32)(a + 4 - start), header);
      }
    }
    // 2. Writes invalidate tracked registers
    if (any_page) arm64_clear_written(in, w.mode);
    for (int i = 0; i < 32; i++)
      if (ldr_got_[i].v && seq_ - ldr_got_[i].seq > 6) ldr_got_[i].v = false;

    // 3. Effects of this instruction
    if (w.id == ARM64_INS_ADRP && w.n == 2 && w.o[0].t == 1 && w.o[1].t == 2) {
      int x = xr(w.o[0].reg);
      if (x >= 0 && x < 32) {
        pages_[x].v = true;
        pages_[x].val = (u64)w.o[1].imm;
        pages_[x].seq = seq_;
        pages_[x].at = a;
      }
    } else if (w.id == ARM64_INS_ADR && w.n == 2 && w.o[1].t == 2) {
      if (emit) xref(a, (u64)w.o[1].imm, XR_PCREL, true);
    } else if ((w.id == ARM64_INS_LDR || w.id == ARM64_INS_LDRSW) && w.n == 2 && w.o[1].t == 2) {
      if (emit) xref(a, (u64)w.o[1].imm, XR_LITERAL, true);
    }

    // 4. Branches
    if (w.call) {
      u64 t = 0;
      bool has = false;
      for (int i = 0; i < w.n; i++)
        if (w.o[i].t == 2) {
          t = (u64)w.o[i].imm;
          has = true;
        }
      if (has && w.rel) {
        add_call_target(t, false);
        if (emit) xref(a, t, XR_CALL, true);
      }
      for (int i = 0; i < 19; i++) pages_[i].v = false;
    } else if (w.jump) {
      u64 t = 0;
      bool has = false;
      for (int i = 0; i < w.n; i++)
        if (w.o[i].t == 2) {
          t = (u64)w.o[i].imm;
          has = true;
        }
      bool uncond_direct = (w.id == ARM64_INS_B) && (w.cc == ARM64_CC_INVALID || w.cc == ARM64_CC_AL || w.cc == ARM64_CC_NV);
      if (has && w.rel) {
        if (emit) xref(a, t, XR_JUMP, true);
        if (uncond_direct && first && m_.is_exec_vaddr(t) && r_.thunks.size() < 1'000'000) r_.thunks[a] = t;
      }
      if (uncond_direct || w.id == ARM64_INS_BR) terminator = true;
    } else if (w.ret || w.id == ARM64_INS_BRK || w.id == ARM64_INS_HLT || w.id == ARM64_INS_UDF) {
      terminator = true;
    }

    // 5. Prologues (only right after a function boundary)
    if (first && !nop) {
      u8 st = 0;
      bool sp_base = w.n >= 3 && w.o[2].t == 3 && w.o[2].base == ARM64_REG_SP;
      if (w.id == ARM64_INS_STP && sp_base && w.wb && w.o[0].t == 1 && w.o[1].t == 1 && w.o[0].reg == ARM64_REG_FP && w.o[1].reg == ARM64_REG_LR) st = 2;
      else if (w.id == ARM64_INS_PACIASP || w.id == ARM64_INS_BTI) st = 2;
      else if (w.id == ARM64_INS_STR && w.n >= 2 && w.o[1].t == 3 && w.o[1].base == ARM64_REG_SP && w.wb && w.o[0].t == 1 && w.o[0].reg == ARM64_REG_LR) st = 2;
      else if (w.id == ARM64_INS_SUB && w.n >= 3 && w.o[0].t == 1 && w.o[0].reg == ARM64_REG_SP && w.o[1].t == 1 && w.o[1].reg == ARM64_REG_SP && w.o[2].t == 2) st = 1;
      else if (w.id == ARM64_INS_STP && sp_base && w.wb) st = 1;
      if (st) add_prologue(a, st);
    } else if (!first && pending_prol_idx_ != ~(size_t)0) {
      bool sp_base = w.n >= 3 && w.o[2].t == 3 && w.o[2].base == ARM64_REG_SP;
      if (w.id == ARM64_INS_STP && sp_base && w.o[0].t == 1 && w.o[0].reg == ARM64_REG_FP) upgrade_prologue();
      else if (w.id == ARM64_INS_STR && w.n >= 2 && w.o[0].t == 1 && w.o[0].reg == ARM64_REG_LR) upgrade_prologue();
    }
  }

  // ------------------------------------------------------------ ARM32
  static int lr(int reg) { return (reg >= ARM_REG_R0 && reg <= ARM_REG_R12) ? reg - ARM_REG_R0 : -1; }

  void arm32(const cs_insn& in, const W& w, bool in_plt, bool first, bool& terminator, bool& nop) {
    (void)in;
    const u64 a = w.addr;
    const bool thumb = w.mode == MODE_THUMB;
    const u64 pc_off = thumb ? 4 : 8;
    const bool emit = !in_plt;
    nop = w.id == ARM_INS_NOP || (w.id == ARM_INS_MOV && w.n == 2 && w.o[0].t == 1 && w.o[1].t == 1 && w.o[0].reg == w.o[1].reg && w.o[0].reg != ARM_REG_PC);
    const bool uncond = (w.cc == ARM_CC_AL || w.cc == ARM_CC_INVALID);

    // veneer completion: movw/movt/add ip, pc; bx ip
    if (ven_.v && seq_ - ven_.seq <= 2 && w.id == ARM_INS_BX && w.n == 1 && w.o[0].t == 1 && lr(w.o[0].reg) == ven_.reg) {
      if (r_.thunks.size() < 1'000'000) r_.thunks[ven_.start] = ven_.target;
      if (emit) xref(a, ven_.target, XR_JUMP, false, false);
      ven_.v = false;
    }

    // calls / jumps
    if (w.call && w.rel) {
      u64 t = 0;
      bool has = false;
      for (int i = 0; i < w.n; i++)
        if (w.o[i].t == 2) {
          t = (u64)w.o[i].imm;
          has = true;
        }
      if (has) {
        bool tgt_thumb = (w.id == ARM_INS_BLX) ? !thumb : thumb;
        add_call_target(t, tgt_thumb);
        if (emit) xref(a, t, XR_CALL, true, tgt_thumb);
      }
      for (int i = 0; i < 4; i++) {
        lit_[i].v = false;
        mv_[i].state = 0;
      }
    } else if (w.jump && w.rel && w.id == ARM_INS_B) {
      for (int i = 0; i < w.n; i++)
        if (w.o[i].t == 2) {
          u64 t = (u64)w.o[i].imm;
          if (emit) xref(a, t, XR_JUMP, true, thumb);
          if (uncond && first && m_.is_exec_vaddr(t) && r_.thunks.size() < 1'000'000) r_.thunks[a] = t;
          break;
        }
      if (uncond) terminator = true;
    }
    // returns and other ends of control flow
    if (w.id == ARM_INS_BX && w.n == 1 && w.o[0].t == 1 && uncond) terminator = true;
    if ((w.id == ARM_INS_POP || w.id == ARM_INS_LDM) && uncond) {
      for (int i = 0; i < w.n; i++)
        if (w.o[i].t == 1 && w.o[i].reg == ARM_REG_PC) terminator = true;
    }
    if (w.id == ARM_INS_LDR && w.n >= 1 && w.o[0].t == 1 && w.o[0].reg == ARM_REG_PC) terminator = true;
    if (w.id == ARM_INS_MOV && w.n == 2 && w.o[0].t == 1 && w.o[0].reg == ARM_REG_PC) terminator = true;
    if (w.id == ARM_INS_UDF || w.id == ARM_INS_BKPT) terminator = true;

    // literal pool load: ldr rt, [pc, #d]
    if (w.id == ARM_INS_LDR && w.n >= 2 && w.o[1].t == 3 && w.o[1].base == ARM_REG_PC && w.o[1].index == 0) {
      u64 base = thumb ? ((a + 4) & ~(u64)3) : a + 8;
      u64 slot = base + (u64)(i64)w.o[1].disp;
      if (emit) xref(a, slot, XR_LITERAL, true);
      int rt = w.o[0].t == 1 ? lr(w.o[0].reg) : -1;
      u8 b4[4];
      if (rt >= 0 && read_vaddr(lc_, slot, b4, 4)) {
        lit_[rt].v = true;
        lit_[rt].val = rd32(b4, m_.le);
        lit_[rt].seq = seq_;
        lit_[rt].from = a;
      }
    }
    // movw / movt
    if ((w.id == ARM_INS_MOVW || w.id == ARM_INS_MOVT) && w.n == 2 && w.o[0].t == 1 && w.o[1].t == 2) {
      int rd = lr(w.o[0].reg);
      if (rd >= 0) {
        Mov16& v = mv_[rd];
        if (w.id == ARM_INS_MOVW) {
          v.state = 1;
          v.lo = (u32)w.o[1].imm & 0xffff;
          v.hi = 0;
          v.seq = seq_;
          v.at = a;
        } else if (v.state == 1 && seq_ - v.seq <= 3) {
          v.state = 2;
          v.hi = (u32)w.o[1].imm & 0xffff;
        }
        lit_[rd].v = false;
      }
    }
    // add rd, pc  /  add rd, rd, pc  /  add rd, pc, rd
    if (w.id == ARM_INS_ADD && w.n >= 2 && w.o[0].t == 1) {
      int rd = lr(w.o[0].reg);
      bool has_pc = false;
      int other = -1;
      for (int i = 1; i < w.n; i++) {
        if (w.o[i].t == 1 && w.o[i].reg == ARM_REG_PC) has_pc = true;
        else if (w.o[i].t == 1) other = lr(w.o[i].reg);
      }
      if (has_pc && w.n <= 3 && w.o[w.n - 1].t != 2) {
        int src = other >= 0 ? other : rd;
        if (src >= 0 && src < 16) {
          u64 pcv = a + pc_off;
          if (lit_[src].v && seq_ - lit_[src].seq <= 6) {
            u64 tgt = (u64)(u32)(lit_[src].val + (u32)pcv);
            if (emit) xref(lit_[src].from, tgt, XR_PCREL, false);
          } else if (mv_[src].state == 2 && seq_ - mv_[src].seq <= 6) {
            u64 tgt = (u64)(u32)(((mv_[src].hi << 16) | mv_[src].lo) + (u32)pcv);
            if (emit) xref(mv_[src].at, tgt, XR_PCREL, false);
            if (rd == src && !in_plt) {
              ven_.v = true;
              ven_.reg = rd;
              ven_.target = tgt;
              ven_.start = mv_[src].at;
              ven_.seq = seq_;
            }
          }
        }
      } else if (w.n >= 3 && w.o[1].t == 1 && w.o[1].reg == ARM_REG_PC && w.o[w.n - 1].t == 2 && !in_plt) {
        // add rd, pc, #imm (address of a nearby object)
        u32 imm = (u32)w.o[2].imm;
        if (w.n == 4 && w.o[3].t == 2) imm = ror32((u32)w.o[2].imm & 0xff, (unsigned)w.o[3].imm);
        if (emit) xref(a, (a + pc_off) + imm, XR_PCREL, true);
      }
      if (rd >= 0 && rd < 16 && !has_pc) {
        lit_[rd].v = false;
        mv_[rd].state = 0;
      }
    }
    if (w.id == ARM_INS_ADR && w.n == 2 && w.o[1].t == 2 && emit) xref(a, (u64)w.o[1].imm, XR_PCREL, true);

    // PLT stub: add ip, pc, #i1; [add ip, ip, #i2]*; ldr pc, [ip, #d]!
    // PLT0 (the lazy-binding resolver) is the same sequence on lr, preceded by "str lr, [sp, #-4]!".
    if (w.id == ARM_INS_LDR && w.wb && w.n >= 2 && w.o[0].t == 1 && w.o[0].reg == ARM_REG_PC && w.o[1].t == 3 && !thumb) {
      auto ri = [](int reg) {
        if (reg >= ARM_REG_R0 && reg <= ARM_REG_R12) return reg - ARM_REG_R0;
        return reg == ARM_REG_LR ? 14 : -1;
      };
      int rd = ri(w.o[1].base);
      u64 sum = 0;
      const W* st = nullptr;
      for (int k = 1; rd >= 0 && k <= 3; k++) {
        const W* p = back(k);
        if (!p || p->mode != MODE_ARM || p->id != ARM_INS_ADD || p->n < 3 || p->o[0].t != 1 || ri(p->o[0].reg) != rd) break;
        u32 imm = (u32)p->o[2].imm;
        if (p->n == 4 && p->o[3].t == 2) imm = ror32((u32)p->o[2].imm & 0xff, (unsigned)p->o[3].imm);
        if (p->o[1].t == 1 && p->o[1].reg == ARM_REG_PC) {
          sum += (p->addr + 8) + imm;
          st = p;
          break;
        }
        if (p->o[1].t == 1 && ri(p->o[1].reg) == rd) sum += imm;
        else break;
      }
      if (st) {
        u64 start = st->addr;
        const bool header = rd == 14;
        if (header) {
          for (int k = 1; k <= 6; k++) {
            const W* p = back(k);
            if (p && p->mode == MODE_ARM && p->addr + 4 == start) {
              if (p->id == ARM_INS_STR && p->o[0].t == 1 && p->o[0].reg == ARM_REG_LR) start = p->addr;
              break;
            }
          }
        }
        if (plt_like(start)) add_plt(start, sum + (u64)(i64)w.o[1].disp, (u32)(a + 4 - start + (header ? 0 : 4)), header);
      }
    }

    // prologues
    if (first && !nop) {
      u8 s = 0;
      bool has_lr = false;
      if (w.id == ARM_INS_PUSH || w.id == ARM_INS_STMDB) {
        for (int i = 0; i < w.n; i++)
          if (w.o[i].t == 1 && w.o[i].reg == ARM_REG_LR) has_lr = true;
        s = has_lr ? 2 : 1;
      } else if (w.id == ARM_INS_SUB && w.n >= 3 && w.o[0].t == 1 && w.o[0].reg == ARM_REG_SP) {
        s = 1;
      }
      if (s) add_prologue(a, s);
    }
  }

  // ------------------------------------------------------------ x86 / x86-64
  void x86(const cs_insn& in, const W& w, bool in_plt, bool first, bool& terminator, bool& nop) {
    (void)in;
    const u64 a = w.addr;
    const bool is64 = arch_ == Arch::X86_64;
    nop = w.id == X86_INS_NOP || w.id == X86_INS_INT3;
    const bool emit = !in_plt;
    const int RIP = X86_REG_RIP;
    bool branch_mem = false;

    if (w.call || w.jump) {
      u64 t = 0;
      bool imm = false, mem = false;
      Op mo;
      for (int i = 0; i < w.n; i++) {
        if (w.o[i].t == 2) {
          t = (u64)w.o[i].imm;
          imm = true;
        } else if (w.o[i].t == 3) {
          mem = true;
          mo = w.o[i];
        }
      }
      if (w.call && imm) {
        add_call_target(t, false);
        if (emit) xref(a, t, XR_CALL, true);
      } else if (w.jump && imm) {
        if (emit) xref(a, t, XR_JUMP, true);
        if (w.id == X86_INS_JMP && first && m_.is_exec_vaddr(t) && r_.thunks.size() < 1'000'000) r_.thunks[a] = t;
      } else if (mem) {
        branch_mem = true;
        u64 slot = 0;
        bool known = false;
        if (is64 && mo.base == RIP) {
          slot = a + w.size + (u64)mo.disp;
          known = true;
        } else if (!is64 && mo.base == 0 && mo.index == 0) {
          slot = (u64)(u32)mo.disp;
          known = true;
        } else if (!is64 && mo.base == X86_REG_EBX && mo.index == 0 && pltgot_) {
          slot = pltgot_ + (u64)(i64)mo.disp;
          known = true;
        }
        if (known) {
          if (w.id == X86_INS_JMP && (in_plt || (!have_secs_ && got_sym_.count(slot)))) {
            u64 start = a;
            bool header = false;
            const W* p = back(1);
            if (p && (p->id == X86_INS_ENDBR64 || p->id == X86_INS_ENDBR32) && p->addr + p->size == a) start = p->addr;
            // PLT0 is "push [GOT+8]; jmp [GOT+16]": the jump directly follows a push of a memory operand.
            if (p && p->id == X86_INS_PUSH && p->addr + p->size == a) {
              for (int i = 0; i < p->n; i++)
                if (p->o[i].t == 3) header = true;
              if (header) start = p->addr;
            }
            add_plt(start, slot, 16, header);
          } else if (emit) {
            xref(a, slot, w.call ? XR_CALL : XR_JUMP, true, false, 3);
          }
        }
      }
      if (w.id == X86_INS_JMP) terminator = true;
    }
    if (w.ret || w.id == X86_INS_UD2 || w.id == X86_INS_HLT) terminator = true;

    // RIP-relative data operands
    if (is64 && !branch_mem && emit) {
      for (int i = 0; i < w.n; i++) {
        if (w.o[i].t == 3 && w.o[i].base == RIP) {
          u64 tgt = a + w.size + (u64)w.o[i].disp;
          xref(a, tgt, XR_PCREL, true);
        }
      }
    }

    // prologues
    if (first && !nop) {
      u8 s = 0;
      if (w.id == X86_INS_ENDBR64 || w.id == X86_INS_ENDBR32) s = 2;
      else if (w.id == X86_INS_PUSH && w.n == 1 && w.o[0].t == 1) {
        int r = w.o[0].reg;
        if (r == X86_REG_RBP || r == X86_REG_EBP) s = 1;
        else if (r == X86_REG_R15 || r == X86_REG_R14 || r == X86_REG_R13 || r == X86_REG_R12 || r == X86_REG_RBX || r == X86_REG_EBX || r == X86_REG_ESI ||
                 r == X86_REG_EDI)
          s = 1;
      } else if (w.id == X86_INS_SUB && w.n == 2 && w.o[0].t == 1 && (w.o[0].reg == X86_REG_RSP || w.o[0].reg == X86_REG_ESP) && w.o[1].t == 2) {
        s = 1;
      }
      if (s) add_prologue(a, s);
    } else if (!first && pending_prol_idx_ != ~(size_t)0) {
      // push rbp ; mov rbp, rsp
      if (w.id == X86_INS_MOV && w.n == 2 && w.o[0].t == 1 && w.o[1].t == 1 &&
          ((w.o[0].reg == X86_REG_RBP && w.o[1].reg == X86_REG_RSP) || (w.o[0].reg == X86_REG_EBP && w.o[1].reg == X86_REG_ESP)))
        upgrade_prologue();
    }
  }
};

}  // namespace

bool stage_codescan(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  lc.scan = CodeScanResult();
  CodeScanResult& sr = lc.scan;
  sr.ran = true;
  if (!arch_supported(lc.arch)) {
    sr.arch_note = std::string("architecture ") + arch_label(lc.elf.arch) + " is not supported by the disassembler";
    rc.ledger.add_gap("unavailable", "code scan", sr.arch_note, lc.index);
    stage_partial(sr.arch_note);
    return true;
  }
  if (!lc.elf.segs_ok && !lc.elf.secs_ok) {
    rc.ledger.add_gap("unavailable", "code scan", "no program headers or sections: executable code cannot be located", lc.index);
    stage_partial("no code locations");
    return true;
  }
  Cs cs(lc.arch, cfg, true);
  if (!cs.ok()) {
    rc.error("codescan", "Capstone: " + cs.error());
    return false;
  }
  compute_code_regions(rc, lc, false);
  if (lc.regions.empty()) {
    rc.ledger.add_gap("unavailable", "code scan", "no executable regions found", lc.index);
    stage_partial("no executable regions");
    return true;
  }
  if (lc.arch == Arch::Arm) compute_arm_spans(rc, lc, cs);
  const bool xrefs_on = cfg.i("general.depth") >= 4;
  Scan sc(rc, lc, cs, xrefs_on);
  SweepStats st;
  u64 total = 0, done = 0;
  for (auto& r : lc.regions) total += r.size;
  sr.bytes_total = total;
  const bool skipdata = true;  // the scan always continues past undecodable bytes
  for (auto& rg : lc.regions) {
    sc.region_start();
    SweepStats rs;
    bool ok = sweep_region(
        rc, lc, cs, rg, skipdata, [&](const cs_insn& in, u8 mode) { sc.on_insn(in, mode); }, [&](u64 a, u32 sz, u8 mode) { sc.on_data(a, sz, mode); }, rs);
    st.insns += rs.insns;
    st.bytes_decoded += rs.bytes_decoded;
    st.bytes_data += rs.bytes_data;
    st.undecodable += rs.undecodable;
    done += rg.size;
    rc.prog("codescan", done, total, "code scan");
    if (!ok) return false;  // cancelled
  }
  sc.finish();
  sr.insns = st.insns;
  sr.bytes_decoded = st.bytes_decoded;
  sr.bytes_data = st.bytes_data;
  sr.undecodable = st.undecodable;
  sr.regions = lc.regions.size();
  if (sr.xref_partial) {
    rc.ledger.add_gap("partial", "cross references", "the reference limit was reached; later code has no references", lc.index);
    stage_partial("reference limit reached");
  }
  rc.ledger.add_counter("scan.insns", st.insns);
  rc.log->log(LogLevel::Ok, "codescan",
              strf("%llu instructions, %llu call targets, %llu prologues, %zu PLT stubs, %zu thunks, %zu references (%s)", (unsigned long long)st.insns,
                   (unsigned long long)sr.call_targets.size(), (unsigned long long)sr.prologues.size(), sr.plt.size(), sr.thunks.size(), sr.xrefs.size(),
                   xrefs_on ? "reference collection on" : "references need depth 4"));
  return true;
}

}  // namespace kratos
