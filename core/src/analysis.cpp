#include "kratos/analysis.h"

namespace kratos {

void Ledger::add_stage(const StageRec& s) {
  std::lock_guard<std::mutex> g(mu_);
  stages_.push_back(s);
}
void Ledger::update_stage(const std::string& id, int lib, const std::function<void(StageRec&)>& fn) {
  std::lock_guard<std::mutex> g(mu_);
  for (auto& s : stages_)
    if (s.id == id && s.lib == lib) {
      fn(s);
      return;
    }
}
void Ledger::add_file(const FileRec& f) {
  std::lock_guard<std::mutex> g(mu_);
  files_.push_back(f);
}
void Ledger::add_gap(const std::string& kind, const std::string& what, const std::string& why, int lib) {
  std::lock_guard<std::mutex> g(mu_);
  gaps_.push_back({kind, what, why, lib});
}
void Ledger::add_counter(const std::string& key, u64 v) {
  std::lock_guard<std::mutex> g(mu_);
  counters_[key] += v;
}
void Ledger::set_counter(const std::string& key, u64 v) {
  std::lock_guard<std::mutex> g(mu_);
  counters_[key] = v;
}
u64 Ledger::counter(const std::string& key) const {
  std::lock_guard<std::mutex> g(mu_);
  auto it = counters_.find(key);
  return it == counters_.end() ? 0 : it->second;
}
std::vector<StageRec> Ledger::stages() const {
  std::lock_guard<std::mutex> g(mu_);
  return stages_;
}
std::vector<FileRec> Ledger::files() const {
  std::lock_guard<std::mutex> g(mu_);
  return files_;
}
std::vector<Gap> Ledger::gaps() const {
  std::lock_guard<std::mutex> g(mu_);
  return gaps_;
}
std::map<std::string, u64> Ledger::counters() const {
  std::lock_guard<std::mutex> g(mu_);
  return counters_;
}

namespace {
thread_local StageRec* tl_stage = nullptr;
}
StageScope::StageScope(StageRec* s) { tl_stage = s; }
StageScope::~StageScope() { tl_stage = nullptr; }
void stage_partial(const std::string& why) {
  if (!tl_stage) return;
  if (tl_stage->status == StageStatus::Ok) tl_stage->status = StageStatus::Partial;
  if (!why.empty()) {
    if (!tl_stage->reason.empty()) tl_stage->reason += "; ";
    tl_stage->reason += why;
  }
}
void stage_note(const std::string& note) {
  if (tl_stage && tl_stage->notes.size() < 64) tl_stage->notes.push_back(note);
}

const char* func_src_names(u32 mask, std::string& out) {
  out.clear();
  auto add = [&](u32 f, const char* n) {
    if (mask & f) {
      if (!out.empty()) out += ",";
      out += n;
    }
  };
  add(FS_SYMTAB, "symtab");
  add(FS_DYNSYM, "dynsym");
  add(FS_INIT, "init");
  add(FS_ENTRY, "entry");
  add(FS_UNWIND, "unwind");
  add(FS_PLT, "plt");
  add(FS_CALL, "call");
  add(FS_PROLOGUE, "prologue");
  add(FS_PTRTAB, "ptrtable");
  return out.c_str();
}

const char* xref_type_name(u8 t) {
  switch (t) {
    case XR_CALL: return "call";
    case XR_JUMP: return "jump";
    case XR_PCREL: return "pcrel";
    case XR_LITERAL: return "literal";
    case XR_DATA: return "data_ptr";
    case XR_STRING: return "string";
  }
  return "?";
}

bool RangeFilter::clip_file(const ElfModel& m, u64& off, u64& len) const {
  if (!active) return true;
  u64 lo_f = 0, hi_f = ~(u64)0;
  if (!vaddr_space) {
    lo_f = lo;
    hi_f = hi;
  } else {
    bool any = false;
    u64 a = ~(u64)0, b = 0;
    for (auto& s : m.segs) {
      if (s.type != elf::PT_LOAD || s.filesz == 0) continue;
      u64 sa = std::max(lo, s.vaddr), sb = std::min(hi, s.vaddr + s.filesz);
      if (sa >= sb) continue;
      a = std::min(a, s.offset + (sa - s.vaddr));
      b = std::max(b, s.offset + (sb - s.vaddr));
      any = true;
    }
    if (!any) {
      len = 0;
      return false;
    }
    lo_f = a;
    hi_f = b;
  }
  u64 s = std::max(off, lo_f), e = std::min(off + len, hi_f);
  if (s >= e) {
    len = 0;
    return false;
  }
  off = s;
  len = e - s;
  return true;
}

OutLimits make_out_limits(const Config& cfg, u64 max_objects) {
  OutLimits l;
  l.max_bytes = cfg.limit("limits.max_file_mb") * 1048576ull;
  l.max_lines = cfg.limit("limits.max_lines");
  l.max_objects = max_objects;
  return l;
}

size_t io_buffer_kb(const Config& cfg) { return (size_t)std::max<i64>(16, std::min<i64>(16384, cfg.i("perf.buffer_kb"))); }

}  // namespace kratos
