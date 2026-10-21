// Function discovery: symbols, init arrays, entry point, unwind tables, call targets, prologues, PLT stubs and pointer tables.
// Every record keeps the sources it came from and a confidence level; nothing is presented as more certain than its evidence.
#include <cxxabi.h>

#include <cstdlib>

#include "kratos/disasm.h"
#include "kratos/stages.h"
#include "kratos/unwind.h"

namespace kratos {

namespace {

std::string demangle_name(const std::string& n) {
  if (n.size() < 3 || n.size() > 4096 || n[0] != '_' || n[1] != 'Z') return "";
  int st = 0;
  char* d = abi::__cxa_demangle(n.c_str(), nullptr, nullptr, &st);
  std::string r;
  if (st == 0 && d) r = d;
  std::free(d);
  return r;
}

// Decodes the JNI escapes of the part after "Java_". Returns false when the name is not a valid JNI export name.
bool jni_signature(const std::string& sym, std::string& out) {
  if (sym.compare(0, 5, "Java_") != 0 || sym.size() < 8) return false;
  std::string body = sym.substr(5), args;
  size_t sep = body.find("__");
  bool has_args = false;
  if (sep != std::string::npos && sep > 0) {
    args = body.substr(sep + 2);
    body = body.substr(0, sep);
    has_args = true;
  }
  auto decode = [](const std::string& s, bool slash_to_dot) {
    std::string r;
    for (size_t i = 0; i < s.size(); i++) {
      char c = s[i];
      if (c != '_') { r.push_back(c); continue; }
      if (i + 1 < s.size()) {
        char n = s[i + 1];
        if (n == '1') { r.push_back('_'); i++; continue; }
        if (n == '2') { r.push_back(';'); i++; continue; }
        if (n == '3') { r.push_back('['); i++; continue; }
        if (n == '0' && i + 5 < s.size()) {
          unsigned v = 0;
          bool ok = true;
          for (int k = 0; k < 4; k++) {
            char h = s[i + 2 + (size_t)k];
            v <<= 4;
            if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
            else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
            else ok = false;
          }
          if (ok) {
            if (v < 0x80) r.push_back((char)v);
            else if (v < 0x800) { r.push_back((char)(0xC0 | (v >> 6))); r.push_back((char)(0x80 | (v & 0x3F))); }
            else { r.push_back((char)(0xE0 | (v >> 12))); r.push_back((char)(0x80 | ((v >> 6) & 0x3F))); r.push_back((char)(0x80 | (v & 0x3F))); }
            i += 5;
            continue;
          }
        }
      }
      r.push_back(slash_to_dot ? '.' : '/');
    }
    return r;
  };
  std::string full = decode(body, true);
  if (full.empty() || full.find('.') == std::string::npos) return false;
  std::string sig = full;
  if (has_args) {
    std::string a = decode(args, false);  // '_' separators become '/' inside class names
    std::string types;
    size_t i = 0;
    auto prim = [](char c) -> const char* {
      switch (c) {
        case 'Z': return "boolean"; case 'B': return "byte"; case 'C': return "char"; case 'S': return "short";
        case 'I': return "int"; case 'J': return "long"; case 'F': return "float"; case 'D': return "double"; case 'V': return "void";
      }
      return nullptr;
    };
    bool good = true;
    while (i < a.size() && good) {
      std::string t;
      int dims = 0;
      while (i < a.size() && a[i] == '[') { dims++; i++; }
      if (i >= a.size()) { good = false; break; }
      if (a[i] == 'L') {
        size_t e = a.find(';', i);
        if (e == std::string::npos) { good = false; break; }
        t = a.substr(i + 1, e - i - 1);
        for (auto& ch : t) if (ch == '/') ch = '.';
        i = e + 1;
      } else if (const char* p = prim(a[i])) {
        t = p;
        i++;
      } else { good = false; break; }
      for (int d = 0; d < dims; d++) t += "[]";
      if (!types.empty()) types += ", ";
      types += t;
    }
    sig += good ? "(" + types + ")" : "(?)";
  } else {
    sig += "(...)";
  }
  out = sig;
  return true;
}

std::string gen_name(const Config& cfg, const LibContext& lc, u64 vaddr) {
  std::string prefix = cfg.s("func.name_prefix");
  if (prefix.empty()) prefix = "sub_";
  u64 v = vaddr;
  if (cfg.s("func.name_basis") == "file_offset") {
    u64 off;
    if (lc.elf.vaddr_to_off(vaddr, off)) v = off;
  }
  return prefix + hex(v, 6);
}

struct Cands {
  std::map<u64, FuncRec> m;
  RunContext& rc;
  bool capped = false;
  explicit Cands(RunContext& r) : rc(r) {}
  FuncRec* add(u64 addr, u32 src, u8 conf) {
    auto it = m.find(addr);
    if (it == m.end()) {
      if (m.size() >= syscap::kMaxObjects || !rc.mem->try_reserve(192)) {
        capped = true;
        return nullptr;
      }
      FuncRec f;
      f.vaddr = addr;
      f.sources = src;
      f.conf = conf;
      it = m.emplace(addr, std::move(f)).first;
    } else {
      it->second.sources |= src;
      it->second.conf = std::max(it->second.conf, conf);
    }
    return &it->second;
  }
};

bool is_code_addr(const LibContext& lc, u64 va) { return lc.elf.is_exec_vaddr(va); }

}  // namespace

// ---------------------------------------------------------------- static sources
bool stage_functions_static(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  FunctionsResult& fr = lc.funcs;
  fr = FunctionsResult();
  fr.ran = true;
  const ElfModel& m = lc.elf;
  const bool arm32 = lc.arch == Arch::Arm;
  const bool f_symtab = cfg.flag("func.sources", "symtab"), f_dynsym = cfg.flag("func.sources", "dynsym"), f_init = cfg.flag("func.sources", "init_fini"),
             f_entry = cfg.flag("func.sources", "entry"), f_unwind = cfg.flag("func.sources", "unwind") && cfg.b("lib.parse_unwind");
  const bool demangle = cfg.b("func.demangle");
  Cands cands(rc);
  u64 mem_methods = 0;
  std::set<std::pair<u64, std::string>> jni_seen;  // a JNI export is usually present in .dynsym and in .symtab: list it once

  auto add_symbols = [&](const std::vector<ElfSymbol>& tab, u32 src) {
    u64 n = 0;
    for (auto& s : tab) {
      if ((++n & 0x3fff) == 0 && rc.cancel->cancelled()) return;
      if (s.undefined() || s.value == 0) continue;
      u8 t = s.type();
      bool func = (t == elf::STT_FUNC || t == elf::STT_GNU_IFUNC);
      bool label = false;
      if (!func && t == elf::STT_NOTYPE && s.bind() != elf::STB_LOCAL && !s.name.empty() && s.name[0] != '$') {
        int si = m.section_for_vaddr(s.value & ~(u64)1);
        label = si >= 0 && m.secs[(size_t)si].exec();
      }
      if (!func && !label) continue;
      bool thumb = arm32 && (s.value & 1);
      u64 addr = arm32 ? (s.value & ~(u64)1) : s.value;
      u64 tmp_off;
      if (!m.vaddr_to_off(addr, tmp_off)) continue;
      FuncRec* f = cands.add(addr, src, func ? 2 : 1);
      if (!f) return;
      if (f->name.empty()) f->name = s.name;
      if (thumb) f->thumb = true;
      if (s.size > 0 && (!f->size_known)) {
        f->size = s.size;
        f->size_known = true;
      }
      // Methods: JNI exports and C++ symbols
      if (func && !s.name.empty()) {
        std::string sig;
        if (jni_signature(s.name, sig) || s.name == "JNI_OnLoad" || s.name == "JNI_OnUnload") {
          if (s.name.compare(0, 5, "Java_") != 0) sig = s.name;
          if (jni_seen.insert({addr, s.name}).second && mem_methods < (1u << 20) && rc.mem->try_reserve(160 + s.name.size() + sig.size())) {
            fr.methods.push_back({"jni", s.name, sig, addr});
            mem_methods++;
          }
          f->kind = "jni";
        }
      }
    }
  };
  if (f_dynsym) add_symbols(m.dynsym, FS_DYNSYM);
  if (f_symtab) add_symbols(m.symtab, FS_SYMTAB);
  // C++ methods: take them from whichever table has names (dynsym preferred, symtab adds the non-exported ones)
  if (demangle) {
    std::set<u64> seen;
    for (auto* tab : {&m.dynsym, &m.symtab}) {
      for (auto& s : *tab) {
        if (s.undefined() || s.value == 0 || s.type() != elf::STT_FUNC) continue;
        if (s.name.size() < 3 || s.name[0] != '_' || s.name[1] != 'Z') continue;
        u64 addr = arm32 ? (s.value & ~(u64)1) : s.value;
        if (!seen.insert(addr).second) continue;
        if (mem_methods >= (1u << 20) || !rc.mem->try_reserve(200 + s.name.size() * 2)) break;
        std::string d = demangle_name(s.name);
        if (d.empty()) continue;
        fr.methods.push_back({"cxx", s.name, d, addr});
        mem_methods++;
      }
    }
  }
  if (rc.cancel->cancelled()) return false;

  // ---- init / fini ----
  if (f_init) {
    auto dyn_val = [&](i64 tag, u64& v) {
      for (auto& d : m.dyn)
        if (d.tag == tag) { v = d.val; return true; }
      return false;
    };
    u64 v;
    if (m.dyn_ok) {
      if (dyn_val(elf::DT_INIT, v) && is_code_addr(lc, arm32 ? (v & ~(u64)1) : v)) {
        if (FuncRec* f = cands.add(arm32 ? (v & ~(u64)1) : v, FS_INIT, 2)) {
          if (f->name.empty()) f->name = "DT_INIT";
          f->kind = f->kind.empty() ? "init" : f->kind;
          if (arm32 && (v & 1)) f->thumb = true;
        }
      }
      if (dyn_val(elf::DT_FINI, v) && is_code_addr(lc, arm32 ? (v & ~(u64)1) : v)) {
        if (FuncRec* f = cands.add(arm32 ? (v & ~(u64)1) : v, FS_INIT, 2)) {
          if (f->name.empty()) f->name = "DT_FINI";
          f->kind = f->kind.empty() ? "init" : f->kind;
          if (arm32 && (v & 1)) f->thumb = true;
        }
      }
    }
    struct Arr { const char* name; i64 tag, sz_tag; };
    const Arr arrs[] = {{"preinit_array", elf::DT_PREINIT_ARRAY, elf::DT_PREINIT_ARRAYSZ}, {"init_array", elf::DT_INIT_ARRAY, elf::DT_INIT_ARRAYSZ},
                        {"fini_array", elf::DT_FINI_ARRAY, elf::DT_FINI_ARRAYSZ}};
    struct Range { const char* name; u64 va, size; };
    std::vector<Range> ranges;
    for (auto& a : arrs) {
      u64 va, sz;
      if (m.dyn_ok && dyn_val(a.tag, va) && dyn_val(a.sz_tag, sz) && sz) ranges.push_back({a.name, va, sz});
    }
    if (ranges.empty()) {
      for (auto& s : m.secs) {
        if (s.synthetic || !s.size) continue;
        if (s.type == elf::SHT_INIT_ARRAY) ranges.push_back({"init_array", s.addr, s.size});
        else if (s.type == elf::SHT_FINI_ARRAY) ranges.push_back({"fini_array", s.addr, s.size});
        else if (s.type == elf::SHT_PREINIT_ARRAY) ranges.push_back({"preinit_array", s.addr, s.size});
      }
    }
    if (!ranges.empty()) {
      std::unordered_map<u64, u64> rel;
      for (auto& r : m.relocs) {
        if (!reloc_is_relative(m, r.type) && !(reloc_is_abs(m, r.type) && r.sym == 0)) continue;
        for (auto& g : ranges)
          if (r.offset >= g.va && r.offset < g.va + g.size) {
            if (r.has_addend) rel[r.offset] = (u64)r.addend;
            else {
              u64 val;
              if (read_ptr(lc, r.offset, val)) rel[r.offset] = val;
            }
            break;
          }
      }
      const u64 ps = m.ptr_size();
      for (auto& g : ranges) {
        u64 cnt = std::min<u64>(g.size / ps, 100000);
        for (u64 i = 0; i < cnt; i++) {
          u64 slot = g.va + i * ps, val = 0;
          auto it = rel.find(slot);
          if (it != rel.end()) val = it->second;
          else if (!read_ptr(lc, slot, val)) continue;
          if (val == 0 || val == ~(u64)0) continue;
          u64 a = arm32 ? (val & ~(u64)1) : val;
          if (!is_code_addr(lc, a)) continue;
          FuncRec* f = cands.add(a, FS_INIT, 2);
          if (!f) break;
          if (f->name.empty()) f->name = strf("%s[%llu]", g.name, (unsigned long long)i);
          if (f->kind.empty()) f->kind = "init";
          if (arm32 && (val & 1)) f->thumb = true;
        }
      }
    }
  }

  // ---- entry point ----
  if (f_entry && m.entry) {
    u64 a = arm32 ? (m.entry & ~(u64)1) : m.entry;
    if (is_code_addr(lc, a)) {
      if (FuncRec* f = cands.add(a, FS_ENTRY, 2)) {
        if (f->name.empty()) f->name = "entry_point";
        if (arm32 && (m.entry & 1)) f->thumb = true;
      }
    }
  }

  // ---- unwind tables ----
  if (f_unwind) {
    UnwindResult ur = read_unwind_tables(rc, lc);
    for (auto& u : ur.funcs) {
      if (!is_code_addr(lc, u.start)) continue;
      FuncRec* f = cands.add(u.start, FS_UNWIND, 2);
      if (!f) break;
      if (u.size && !f->size_known && u.exact) {
        f->size = u.size;
        f->size_known = true;
      } else if (u.size && !f->size_known && f->size == 0) {
        f->size = u.size;
        f->size_est = true;
      }
    }
    if (ur.eh_frame_found || ur.exidx_found)
      rc.log->log(LogLevel::Info, "functions",
                  strf("unwind tables (%s): %llu FDE, %llu exidx entries, %llu damaged/unsupported entries", ur.source.c_str(), (unsigned long long)ur.fde_count,
                       (unsigned long long)ur.exidx_entries, (unsigned long long)ur.skipped_entries));
    else
      rc.ledger.add_gap("unavailable", "unwind tables", "neither .eh_frame nor .ARM.exidx found", lc.index);
    if (ur.partial || ur.skipped_entries) {
      rc.ledger.add_gap("partial", "unwind tables", strf("%llu entries damaged or unsupported; the table may be cut off", (unsigned long long)ur.skipped_entries), lc.index);
      stage_partial("unwind tables partly unreadable");
    }
  } else if (cfg.flag("func.sources", "unwind")) {
    rc.ledger.add_gap("skipped", "unwind tables", "unwind parsing is disabled in the library settings", lc.index);
  }

  if (cands.capped) {
    rc.ledger.add_gap("partial", "function list", "memory or object limit reached while collecting functions", lc.index);
    stage_partial("function list capped");
  }

  fr.list.reserve(cands.m.size());
  for (auto& kv : cands.m) fr.list.push_back(std::move(kv.second));
  rc.log->log(LogLevel::Ok, "functions", strf("%zu function candidates from static sources, %zu named methods", fr.list.size(), fr.methods.size()));
  return true;
}

// ---------------------------------------------------------------- pointer tables
bool stage_unknown_structures(RunContext& rc, LibContext& lc) {
  const ElfModel& m = lc.elf;
  FunctionsResult& fr = lc.funcs;
  const bool arm32 = lc.arch == Arch::Arm;
  const u64 ps = m.ptr_size();
  if (!m.segs_ok) {
    rc.ledger.add_gap("unavailable", "pointer tables", "program headers are required to locate data segments", lc.index);
    return true;
  }
  // slot -> target, from relative relocations (the in-file value is not reliable with RELA) and raw pointer values.
  std::vector<std::pair<u64, u64>> slots;
  auto in_data = [&](u64 va) {
    const ElfSegment* s = m.seg_for_vaddr(va);
    return s && !(s->flags & elf::PF_X);
  };
  for (auto& r : m.relocs) {
    if (!reloc_is_relative(m, r.type)) continue;
    if (!in_data(r.offset)) continue;
    u64 tgt = 0;
    if (r.has_addend) tgt = (u64)r.addend;
    else if (!read_ptr(lc, r.offset, tgt)) continue;
    if (!lc.range.ok_va(m, r.offset)) continue;
    if (slots.size() < 20'000'000) slots.push_back({r.offset, tgt});
  }
  // Raw values (non-PIE images or already-applied relocations)
  std::vector<u8> buf;
  for (auto& s : m.segs) {
    if (s.type != elf::PT_LOAD || (s.flags & elf::PF_X) || !s.filesz) continue;
    if (rc.cancel->cancelled()) return false;
    u64 off = s.offset, len = std::min<u64>(s.filesz, lc.size > s.offset ? lc.size - s.offset : 0);
    if (!lc.range.clip_file(m, off, len)) continue;
    u64 cap = std::min<u64>(len, 256ull << 20);
    if (!rc.mem->try_reserve(cap)) {
      rc.ledger.add_gap("partial", "pointer tables", "memory limit reached while scanning data segment", lc.index);
      continue;
    }
    buf.resize((size_t)cap);
    size_t got = lc.src->read_at(off, buf.data(), (size_t)cap);
    u64 va0 = s.vaddr + (off - s.offset);
    for (size_t i = 0; i + ps <= got; i += (size_t)ps) {
      if (((va0 + i) & (ps - 1)) != 0) continue;
      u64 v = ps == 8 ? rd64(buf.data() + i, m.le) : rd32(buf.data() + i, m.le);
      u64 a = arm32 ? (v & ~(u64)1) : v;
      if (v && m.is_exec_vaddr(a) && slots.size() < 20'000'000) slots.push_back({va0 + i, v});
    }
    rc.mem->release(cap);
  }
  std::sort(slots.begin(), slots.end());
  slots.erase(std::unique(slots.begin(), slots.end(), [](const auto& a, const auto& b) { return a.first == b.first; }), slots.end());

  u64 found = 0;
  const bool heur = rc.cfg.b("xref.include_heuristic");
  auto exec_target = [&](size_t k) {
    u64 a = arm32 ? (slots[k].second & ~(u64)1) : slots[k].second;
    return m.is_exec_vaddr(a);
  };
  size_t i = 0;
  while (i < slots.size()) {
    size_t j = i;
    while (j + 1 < slots.size() && slots[j + 1].first == slots[j].first + ps) j++;
    size_t k = i;
    while (k <= j) {
      if (!exec_target(k)) {
        k++;
        continue;
      }
      size_t s0 = k;
      while (k <= j && exec_target(k)) k++;
      if (k - s0 < 3) continue;
      PointerTable t;
      t.vaddr = slots[s0].first;
      t.count = (u32)(k - s0);
      t.sec = m.section_for_vaddr(t.vaddr);
      if (fr.tables.size() < 1'000'000) fr.tables.push_back(t);
      found++;
      for (size_t idx = s0; idx < k; idx++) {
        u64 tv = slots[idx].second;
        u64 a = arm32 ? (tv & ~(u64)1) : tv;
        FuncRec f;
        f.vaddr = a;
        f.sources = FS_PTRTAB;
        f.conf = 0;
        f.thumb = arm32 && (tv & 1);
        if (fr.list.size() < syscap::kMaxObjects && rc.mem->try_reserve(192)) fr.list.push_back(std::move(f));
        if (heur && lc.scan.xrefs.size() < syscap::kMaxObjects && rc.mem->try_reserve(sizeof(XrefRec))) {
          XrefRec x;
          x.from = slots[idx].first;
          x.to = a;
          x.type = XR_DATA;
          x.confirmed = false;
          x.thumb_target = arm32 && (tv & 1);
          lc.scan.xrefs.push_back(x);
        }
      }
    }
    i = j + 1;
  }
  rc.log->log(LogLevel::Ok, "unknown", strf("%llu pointer tables to executable code (heuristic)", (unsigned long long)found));
  rc.ledger.add_counter("tables.found", found);
  return true;
}

// ---------------------------------------------------------------- final merge
bool stage_functions_final(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  FunctionsResult& fr = lc.funcs;
  const ElfModel& m = lc.elf;
  const bool arm32 = lc.arch == Arch::Arm;
  const bool f_call = cfg.flag("func.sources", "call_targets"), f_prol = cfg.flag("func.sources", "prologue"), f_plt = cfg.flag("func.sources", "plt");
  const bool demangle = cfg.b("func.demangle");
  const bool bounds = cfg.b("func.guess_bounds");

  // Rebuild the candidate map from the static list.
  std::map<u64, FuncRec> mp;
  for (auto& f : fr.list) {
    auto it = mp.find(f.vaddr);
    if (it == mp.end()) {
      mp.emplace(f.vaddr, std::move(f));
    } else {
      FuncRec& d = it->second;
      d.sources |= f.sources;
      d.conf = std::max(d.conf, f.conf);
      if (d.name.empty()) d.name = f.name;
      if (d.kind.empty()) d.kind = f.kind;
      if (f.thumb) d.thumb = true;
      if (!d.size_known && f.size_known) { d.size = f.size; d.size_known = true; d.size_est = false; }
      else if (!d.size_known && d.size == 0 && f.size) { d.size = f.size; d.size_est = f.size_est; }
    }
  }
  fr.list.clear();

  auto inside_known = [&](u64 a) {
    auto it = mp.upper_bound(a);
    if (it == mp.begin()) return false;
    --it;
    const FuncRec& f = it->second;
    return f.vaddr < a && f.size_known && a < f.vaddr + f.size;
  };
  auto add = [&](u64 a, u32 src, u8 conf, bool thumb) -> FuncRec* {
    auto it = mp.find(a);
    if (it == mp.end()) {
      if (mp.size() >= syscap::kMaxObjects || !rc.mem->try_reserve(192)) return nullptr;
      FuncRec f;
      f.vaddr = a;
      it = mp.emplace(a, std::move(f)).first;
    }
    it->second.sources |= src;
    it->second.conf = std::max(it->second.conf, conf);
    if (thumb) it->second.thumb = true;
    return &it->second;
  };

  if (lc.scan.ran) {
    if (f_call) {
      for (u64 t : lc.scan.call_targets) {
        u64 a = arm32 ? (t & ~(u64)1) : t;
        if (!lc.range.ok_va(m, a) || inside_known(a)) continue;
        add(a, FS_CALL, 1, arm32 && (t & 1));
      }
    }
    if (f_prol) {
      for (auto& p : lc.scan.prologues) {
        u64 a = p.first;
        if (!lc.range.ok_va(m, a) || inside_known(a)) continue;
        add(a, FS_PROLOGUE, p.second >= 2 ? 1 : 0, false);
      }
    }
    if (f_plt) {
      fr.plt = lc.scan.plt;
      for (auto& s : lc.scan.plt) {
        FuncRec* f = add(s.addr, FS_PLT, 2, false);
        if (!f) continue;
        if (f->name.empty() && !s.name.empty() && !s.header) f->name = s.name + "@plt";
        f->kind = s.header ? "plt-header" : "plt";
        if (!f->size_known) { f->size = s.size; f->size_known = true; f->size_est = false; }
      }
      // The second half of a stub (the lazy-binding path that .got.plt points at) is not a function of its own.
      const u32 strong = FS_SYMTAB | FS_DYNSYM | FS_INIT | FS_ENTRY | FS_UNWIND | FS_PLT;
      u64 inside = 0;
      for (auto& s : lc.scan.plt) {
        for (auto it = mp.upper_bound(s.addr); s.size && it != mp.end() && it->first < s.addr + s.size;) {
          if (!(it->second.sources & strong)) {
            it = mp.erase(it);
            inside++;
          } else {
            ++it;
          }
        }
      }
      if (inside) rc.log->log(LogLevel::Debug, "functions", strf("%llu weak candidates inside PLT stubs were dropped", (unsigned long long)inside));
    }
  } else if (f_call || f_prol || f_plt) {
    rc.ledger.add_gap("unavailable", "functions from code scan", "the code scan did not run (depth, architecture or settings)", lc.index);
  }

  // Ordered list
  std::vector<FuncRec> v;
  v.reserve(mp.size());
  for (auto& kv : mp) v.push_back(std::move(kv.second));
  mp.clear();

  // End of the executable area that contains an address (for the last function of a region).
  auto area_end = [&](u64 a) -> u64 {
    int si = m.section_for_vaddr(a);
    if (si >= 0 && m.secs[(size_t)si].exec()) return m.secs[(size_t)si].addr + m.secs[(size_t)si].size;
    const ElfSegment* s = m.seg_for_vaddr(a);
    return s ? s->vaddr + s->filesz : a;
  };

  u64 dropped_range = 0;
  std::vector<FuncRec> out;
  out.reserve(v.size());
  for (size_t i = 0; i < v.size(); i++) {
    FuncRec& f = v[i];
    if (!lc.range.ok_va(m, f.vaddr)) {
      dropped_range++;
      continue;
    }
    // Estimated bounds
    if (!f.size_known && bounds) {
      u64 end = area_end(f.vaddr);
      if (i + 1 < v.size() && v[i + 1].vaddr < end) end = v[i + 1].vaddr;
      if (end > f.vaddr && f.size == 0) {
        f.size = end - f.vaddr;
        f.size_est = true;
      }
    }
    if (arm32 && !f.thumb && lc.spans_ready) f.thumb = mode_at(lc, f.vaddr) == MODE_THUMB;
    f.sec = m.section_for_vaddr(f.vaddr);
    // Name
    if (f.name.empty()) {
      f.name = gen_name(cfg, lc, f.vaddr);
      f.generated = true;
    } else {
      f.generated = false;
    }
    if (f.kind.empty() && f.name.compare(0, 5, "Java_") == 0) f.kind = "jni";
    if (demangle && f.name.size() > 2 && f.name[0] == '_' && f.name[1] == 'Z') {
      f.demangled = demangle_name(f.name);
      if (f.kind.empty() && !f.demangled.empty()) f.kind = "cxx";
    }
    // Confidence: several independent heuristic sources raise it
    u32 weak = 0;
    for (u32 b : {(u32)FS_CALL, (u32)FS_PROLOGUE, (u32)FS_PTRTAB})
      if (f.sources & b) weak++;
    if (f.conf < 1 && weak >= 2) f.conf = 1;
    out.push_back(std::move(f));
  }
  fr.list = std::move(out);
  if (dropped_range) rc.log->log(LogLevel::Info, "functions", strf("%llu candidates outside the analysis range were dropped", (unsigned long long)dropped_range));

  fr.from_symbols = fr.from_unwind = fr.from_init = fr.from_calls = fr.from_prologue = fr.from_plt = 0;
  for (auto& f : fr.list) {
    if (f.sources & (FS_SYMTAB | FS_DYNSYM)) fr.from_symbols++;
    if (f.sources & FS_UNWIND) fr.from_unwind++;
    if (f.sources & (FS_INIT | FS_ENTRY)) fr.from_init++;
    if (f.sources & FS_CALL) fr.from_calls++;
    if (f.sources & FS_PROLOGUE) fr.from_prologue++;
    if (f.sources & FS_PLT) fr.from_plt++;
  }
  fr.finalized = true;
  rc.ledger.add_counter("functions.total", fr.list.size());
  rc.ledger.add_counter("functions.symbols", fr.from_symbols);
  rc.ledger.add_counter("functions.unwind", fr.from_unwind);
  rc.log->log(LogLevel::Ok, "functions",
              strf("%zu functions: symbols %llu, unwind %llu, init/entry %llu, call targets %llu, prologues %llu, PLT %llu", fr.list.size(), (unsigned long long)fr.from_symbols,
                   (unsigned long long)fr.from_unwind, (unsigned long long)fr.from_init, (unsigned long long)fr.from_calls, (unsigned long long)fr.from_prologue,
                   (unsigned long long)fr.from_plt));
  if (fr.list.empty()) rc.ledger.add_gap("unavailable", "functions", "no function could be identified from the enabled sources", lc.index);
  return true;
}

}  // namespace kratos
