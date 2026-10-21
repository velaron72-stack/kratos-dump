// Capstone wrapper: handles per mode, code regions, ARM/Thumb spans and a streaming linear sweep.
#pragma once

#include <capstone/capstone.h>

#include "kratos/analysis.h"

namespace kratos {

enum { MODE_ARM = 0, MODE_THUMB = 1, MODE_DATA = 2 };

class Cs {
 public:
  Cs(Arch arch, const Config& cfg, bool detail);
  ~Cs();
  Cs(const Cs&) = delete;
  Cs& operator=(const Cs&) = delete;
  bool ok() const { return ok_; }
  const std::string& error() const { return err_; }
  Arch arch() const { return arch_; }
  csh handle(u8 mode) const { return h_[mode == MODE_THUMB ? 1 : 0]; }
  cs_insn* insn(u8 mode) const { return ins_[mode == MODE_THUMB ? 1 : 0]; }
  // Smallest decodable unit and the number of bytes below which a decode failure may just mean "need more input".
  u32 unit(u8 mode) const;
  u32 refill(u8 mode) const;
  bool detail() const { return detail_; }

 private:
  Arch arch_;
  bool ok_ = false, detail_ = false;
  std::string err_;
  csh h_[2] = {0, 0};
  cs_insn* ins_[2] = {nullptr, nullptr};
};

// Effective architecture: honours disasm.arch when it is not "auto".
Arch effective_arch(const LibContext& lc, const Config& cfg);
bool arch_supported(Arch a);

// Builds lc.regions according to disasm.scope and the range filter. `need_funcs` is used for scope=functions.
void compute_code_regions(RunContext& rc, LibContext& lc, bool for_listing);
// ARM32: instruction-set spans from mapping symbols, symbol parity and trial decoding.
void compute_arm_spans(RunContext& rc, LibContext& lc, Cs& cs);
// Trial decode: returns the best guess for the instruction set at a vaddr. conf out: 0 guessed.
u8 guess_arm_mode(const LibContext& lc, Cs& cs, u64 vaddr);
u8 mode_at(const LibContext& lc, u64 vaddr);  // MODE_ARM for non-ARM32 architectures

struct SweepStats {
  u64 insns = 0, bytes_decoded = 0, bytes_data = 0, undecodable = 0;
  bool stop = false;  // set by a callback to end the sweep early (output limit reached)
};
using InsnFn = std::function<void(const cs_insn&, u8 mode)>;
using DataFn = std::function<void(u64 addr, u32 size, u8 mode)>;

// Decodes the region sequentially. Returns false when cancelled.
bool sweep_region(RunContext& rc, LibContext& lc, Cs& cs, const CodeRegion& rg, bool skipdata, const InsnFn& on_insn, const DataFn& on_data, SweepStats& st);

// Absolute target of a direct (immediate) call or jump; false for everything else. Needs detail mode.
bool direct_branch_target(Arch a, const cs_insn& in, u64& target, bool& is_call);

// Reads `n` bytes at a vaddr (file-backed only).
bool read_vaddr(const LibContext& lc, u64 vaddr, void* dst, size_t n);
// Reads a pointer-sized little/big endian value.
bool read_ptr(const LibContext& lc, u64 vaddr, u64& out);

}  // namespace kratos
