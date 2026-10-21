// functions.txt, methods.txt and offsets.h
#include "kratos/report_util.h"
#include "kratos/stages.h"

namespace kratos {

namespace {

const char* conf_name(u8 c) { return c >= 2 ? "high" : (c == 1 ? "medium" : "low"); }

bool matches_any(const std::string& hay, const std::vector<std::string>& needles) {
  for (auto& n : needles)
    if (!n.empty() && contains_ci(hay, n)) return true;
  return false;
}

std::string size_text(const FuncRec& f) {
  if (f.size == 0) return "?";
  return strf("%s0x%llx", f.size_est || !f.size_known ? "~" : "", (unsigned long long)f.size);
}

std::string demangled_or_empty(const FuncRec& f) { return f.demangled; }

}  // namespace

bool stage_report_functions(RunContext& rc, LibContext& lc) {
  const Config& cfg = rc.cfg;
  const ElfModel& m = lc.elf;
  FunctionsResult& fr = lc.funcs;
  const AddrCols ac = AddrCols::from(cfg);
  const bool arm32 = lc.arch == Arch::Arm;

  // ---------------------------------------------------------------- functions.txt
  if (report_wanted(rc, "out.functions")) {
    if (!fr.ran || !fr.finalized) {
      report_unavailable(rc, lc.index, "functions.txt", "function discovery did not complete");
    } else if (fr.list.empty()) {
      report_unavailable(rc, lc.index, "functions.txt", "no functions were found with the enabled sources");
    } else if (auto rf = open_report(rc, lc, "functions.txt", "functions", cfg.limit("limits.max_functions"))) {
      OutFile& f = rf->f();
      const bool c_size = cfg.flag("func.columns", "size"), c_src = cfg.flag("func.columns", "source"), c_conf = cfg.flag("func.columns", "confidence"),
                 c_sec = cfg.flag("func.columns", "section");
      const std::vector<std::string> inc = split(cfg.s("func.filter"), ',');
      const u64 min_size = (u64)std::max<i64>(0, cfg.i("func.min_size"));
      const std::string mc = cfg.s("func.min_confidence");
      const u8 min_conf = mc == "high" ? 2 : (mc == "medium" ? 1 : 0);
      const bool unnamed = cfg.b("func.include_unnamed");
      const std::string sort = cfg.s("func.sort");

      std::vector<const FuncRec*> v;
      v.reserve(fr.list.size());
      u64 filtered = 0;
      for (auto& fn : fr.list) {
        if (fn.conf < min_conf || fn.size < min_size || (!unnamed && fn.generated) || (!inc.empty() && !matches_any(fn.name + " " + fn.demangled, inc))) {
          filtered++;
          continue;
        }
        v.push_back(&fn);
      }
      if (sort == "name") std::stable_sort(v.begin(), v.end(), [](const FuncRec* a, const FuncRec* b) { return a->name < b->name; });
      else if (sort == "size") std::stable_sort(v.begin(), v.end(), [](const FuncRec* a, const FuncRec* b) { return a->size > b->size; });
      else if (sort == "source") std::stable_sort(v.begin(), v.end(), [](const FuncRec* a, const FuncRec* b) { return a->sources < b->sources; });

      f.line("# Names like " + cfg.s("func.name_prefix") + "xxxxxx are generated from the address; they are not original names and are marked [generated].");
      f.line("# size: ~N is an estimate (distance to the next function); ? is unknown. confidence: high = symbol/unwind/init/entry/PLT, medium = several heuristics agree,");
      f.line("#         low = a single heuristic (prologue pattern or pointer table).");
      if (arm32) f.line("# isa: thumb/arm. Add 1 to a Thumb address when it is used as a call target.");
      std::string cols = "# columns: " + ac.header();
      if (arm32) cols += "isa ";
      if (c_size) cols += "size ";
      if (c_conf) cols += "confidence ";
      if (c_src) cols += "source ";
      if (c_sec) cols += "section ";
      cols += "name";
      f.line(cols);
      u64 written = 0;
      std::string srcs;
      for (const FuncRec* fn : v) {
        u64 off = 0;
        bool ho = m.vaddr_to_off(fn->vaddr, off);
        std::string line = ac.fmt(m, ho, off, true, fn->vaddr);
        if (arm32) line += strf("%-5s ", fn->thumb ? "thumb" : "arm");
        if (c_size) line += strf("%-9s ", size_text(*fn).c_str());
        if (c_conf) line += strf("%-6s ", conf_name(fn->conf));
        if (c_src) {
          func_src_names(fn->sources, srcs);
          line += strf("%-22s ", srcs.c_str());
        }
        if (c_sec) line += strf("%-12s ", fn->sec >= 0 && fn->sec < (int)m.secs.size() ? m.secs[(size_t)fn->sec].name.c_str() : "-");
        line += fn->name;
        if (fn->generated) line += "  [generated]";
        if (!fn->kind.empty() && fn->kind != "init") line += "  {" + fn->kind + "}";
        if (!fn->demangled.empty()) line += "  // " + demangled_or_empty(*fn);
        if (!f.object()) break;
        if (!f.line(line)) break;
        written++;
      }
      f.line("");
      f.line(strf("# %llu functions written (%zu found, %llu excluded by filters)", (unsigned long long)written, fr.list.size(), (unsigned long long)filtered));
      f.line(strf("# sources: symbols %llu, unwind %llu, init/entry %llu, call targets %llu, prologues %llu, PLT %llu", (unsigned long long)fr.from_symbols,
                  (unsigned long long)fr.from_unwind, (unsigned long long)fr.from_init, (unsigned long long)fr.from_calls, (unsigned long long)fr.from_prologue,
                  (unsigned long long)fr.from_plt));
      if (!fr.tables.empty()) f.line(strf("# %zu pointer tables to code were found; their targets are listed with source ptrtable", fr.tables.size()));
      close_report(rc, *rf);
    }
  }

  // ---------------------------------------------------------------- methods.txt
  if (report_wanted(rc, "out.methods")) {
    if (!fr.ran) {
      report_unavailable(rc, lc.index, "methods.txt", "function discovery did not run");
    } else if (fr.methods.empty()) {
      report_unavailable(rc, lc.index, "methods.txt", "no JNI exports or demangled C++ symbols with names were found (the library may be stripped)");
    } else if (auto rf = open_report(rc, lc, "methods.txt", "named methods", 0)) {
      OutFile& f = rf->f();
      f.line("# Only methods with real names in the symbol tables are listed: JNI exports (Java_*, JNI_OnLoad) and C++ symbols (demangled).");
      if (rc.meta.found && rc.meta.handler == "il2cpp")
        f.line("# IL2CPP managed method names are NOT reconstructed: that needs the code registration structures, which this version does not parse.");
      f.line("# columns: " + ac.header() + "kind signature   [raw symbol]");
      std::vector<const MethodRec*> v;
      for (auto& mr : fr.methods) v.push_back(&mr);
      std::stable_sort(v.begin(), v.end(), [](const MethodRec* a, const MethodRec* b) { return a->vaddr < b->vaddr; });
      u64 n = 0;
      for (const MethodRec* mr : v) {
        u64 off = 0;
        bool ho = m.vaddr_to_off(mr->vaddr, off);
        if (!f.object()) break;
        if (!f.line(ac.fmt(m, ho, off, true, mr->vaddr) + strf("%-4s ", mr->kind.c_str()) + mr->signature + (mr->signature == mr->symbol ? "" : "   [" + mr->symbol + "]"))) break;
        n++;
      }
      f.line("");
      f.line(strf("# %llu methods", (unsigned long long)n));
      close_report(rc, *rf);
    }
  }

  // ---------------------------------------------------------------- offsets.h
  if (report_wanted(rc, "out.offsets")) {
    if (!lc.elf_ok || !m.segs_ok) {
      report_unavailable(rc, lc.index, "offsets.h", "program headers are required to compute RVAs and file offsets");
    } else {
      const bool inc_exports = cfg.flag("out.offsets_include", "exports"), inc_symbols = cfg.flag("out.offsets_include", "symbols"),
                 inc_generated = cfg.flag("out.offsets_include", "generated"), inc_secs = cfg.flag("out.offsets_include", "sections"),
                 inc_segs = cfg.flag("out.offsets_include", "segments");
      const bool k_rva = cfg.flag("out.offsets_columns", "rva"), k_va = cfg.flag("out.offsets_columns", "vaddr"), k_off = cfg.flag("out.offsets_columns", "file_offset");
      const bool as_define = cfg.s("out.offsets_style") == "define";
      struct Entry {
        std::string name, note;
        u64 va = 0;
        bool has_va = false, has_off = false;
        u64 off = 0;
      };
      std::vector<Entry> ents;
      std::set<std::string> used;
      auto uniq = [&](std::string base) {
        base = sanitize_ident(base);
        if (base.empty()) base = "_";
        std::string n = base;
        for (int i = 2; used.count(n); i++) n = base + "_" + std::to_string(i);
        used.insert(n);
        return n;
      };
      std::map<std::pair<std::string, u64>, size_t> by_name_addr;  // the same symbol in .dynsym and .symtab is one entry
      auto push = [&](const std::string& name, u64 va, bool has_va, const std::string& note, bool has_off_direct = false, u64 off_direct = 0) {
        if (has_va) {
          auto ins = by_name_addr.emplace(std::make_pair(name, va), ents.size());
          if (!ins.second) {
            std::string& prev = ents[ins.first->second].note;
            const size_t cut = note.rfind("; ");  // the origin ("export", "symbol") is the last part of the note
            const std::string origin = cut == std::string::npos ? note : note.substr(cut + 2);
            if (prev.find(origin) == std::string::npos) prev += "; also " + origin;
            return;
          }
        }
        Entry e;
        e.name = uniq(name);
        e.va = va;
        e.has_va = has_va;
        e.note = note;
        if (has_off_direct) {
          e.has_off = true;
          e.off = off_direct;
        } else if (has_va) {
          e.has_off = m.vaddr_to_off(va, e.off);
        }
        ents.push_back(std::move(e));
      };
      if (inc_exports) {
        for (auto& s : m.dynsym) {
          if (s.undefined() || s.index == 0 || s.bind() == elf::STB_LOCAL || s.name.empty() || s.shndx == elf::SHN_ABS) continue;
          if (s.type() != elf::STT_FUNC && s.type() != elf::STT_OBJECT && s.type() != elf::STT_GNU_IFUNC) continue;
          u64 va = arm32 ? (s.value & ~(u64)1) : s.value;
          push(s.name, va, true, std::string(arm32 && (s.value & 1) ? "thumb function; " : "") + "export");
        }
      }
      if (inc_symbols) {
        for (auto& s : m.symtab) {
          if (s.undefined() || s.index == 0 || s.name.empty() || s.shndx == elf::SHN_ABS || s.name[0] == '$') continue;
          if (s.type() != elf::STT_FUNC && s.type() != elf::STT_OBJECT) continue;
          u64 va = arm32 ? (s.value & ~(u64)1) : s.value;
          push(s.name, va, true, std::string(arm32 && (s.value & 1) ? "thumb function; " : "") + "symbol");
        }
      }
      if (inc_generated) {
        for (auto& fn : fr.list)
          if (fn.generated) push(fn.name, fn.vaddr, true, std::string("generated name; ") + conf_name(fn.conf) + " confidence" + (fn.thumb ? "; thumb function" : ""));
      }
      if (inc_secs) {
        for (auto& s : m.secs) {
          if (s.index == 0 || !s.alloc() || s.name.empty()) continue;
          push("sec_" + s.name, s.addr, true, s.synthetic ? "section (reconstructed)" : "section", s.has_file_data(), s.offset);
        }
      }
      if (inc_segs) {
        for (auto& s : m.segs)
          if (s.type == elf::PT_LOAD) push(strf("seg%d_%s", s.index, seg_flags_str(s.flags).c_str()), s.vaddr, true, "PT_LOAD segment", true, s.offset);
      }
      if (ents.empty()) {
        report_unavailable(rc, lc.index, "offsets.h", "nothing selected for offsets.h exists in this library (try enabling symbols or generated names)");
      } else if (auto rf = open_report(rc, lc, "offsets.h", "offsets", cfg.limit("limits.max_functions"), "// ")) {
        // The file is C++; use // comments instead of the default '#'.
        OutFile& f = rf->f();
        f.line("// Meaning of the values:");
        f.line("//   _RVA  = virtual address minus the image base (0x" + hex(m.load_base_rel) + "); this is the offset from the module base in memory.");
        f.line("//   _VA   = virtual address as stored in the ELF file (before the library is relocated).");
        f.line("//   _FOFF = offset of the same bytes inside the file on disk.");
        f.line("// RVA, VA and file offset differ whenever segments are not mapped 1:1 to the file; do not mix them.");
        f.line("// Every entry comes from a real symbol, section, segment or discovered function; entries marked 'generated' have invented names, not original ones.");
        f.line("#pragma once");
        if (!as_define) {
          f.line("#include <cstdint>");
          f.line("namespace kratos_offsets {");
        }
        std::stable_sort(ents.begin(), ents.end(), [](const Entry& a, const Entry& b) { return a.va < b.va; });
        u64 n = 0;
        for (auto& e : ents) {
          if (!f.object()) break;
          bool wrote = false;
          auto emit = [&](const char* suffix, u64 val, const std::string& note) {
            std::string nm = e.name + suffix;
            std::string line = as_define ? strf("#define %s 0x%llxull", nm.c_str(), (unsigned long long)val) : strf("constexpr uintptr_t %s = 0x%llx;", nm.c_str(), (unsigned long long)val);
            if (!note.empty()) line += "  // " + note;
            f.line(line);
            wrote = true;
          };
          if (k_rva && e.has_va) emit("_RVA", m.rva(e.va), e.note);
          if (k_va && e.has_va) emit("_VA", e.va, k_rva ? "" : e.note);
          if (k_off && e.has_off) emit("_FOFF", e.off, (k_rva && e.has_va) || (k_va && e.has_va) ? "" : e.note);
          if (wrote) n++;
        }
        if (!as_define) f.line("}  // namespace kratos_offsets");
        f.line(strf("// %llu objects", (unsigned long long)n));
        close_report(rc, *rf);
      }
    }
  }
  return true;
}

}  // namespace kratos
