#include "kratos/elf.h"

#include <zlib.h>
#include <zstd.h>

namespace kratos {

// ---------------------------------------------------------------- names
const char* arch_name(Arch a) {
  switch (a) {
    case Arch::Arm64: return "arm64";
    case Arch::Arm: return "arm";
    case Arch::X86_64: return "x86_64";
    case Arch::X86: return "x86";
    case Arch::Other: return "other";
    default: return "unknown";
  }
}
const char* arch_label(Arch a) {
  switch (a) {
    case Arch::Arm64: return "ARM64 (AArch64)";
    case Arch::Arm: return "ARM32";
    case Arch::X86_64: return "x86-64";
    case Arch::X86: return "x86 (32-bit)";
    case Arch::Other: return "other";
    default: return "unknown";
  }
}
const char* abi_for_arch(Arch a) {
  switch (a) {
    case Arch::Arm64: return "arm64-v8a";
    case Arch::Arm: return "armeabi-v7a";
    case Arch::X86_64: return "x86_64";
    case Arch::X86: return "x86";
    default: return "";
  }
}

const char* machine_name(u16 m) {
  switch (m) {
    case 0: return "none";
    case 3: return "Intel 80386";
    case 8: return "MIPS";
    case 40: return "ARM";
    case 62: return "x86-64";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    default: return "other";
  }
}
const char* elf_type_name(u16 t) {
  switch (t) {
    case 0: return "NONE";
    case 1: return "REL (relocatable)";
    case 2: return "EXEC (executable)";
    case 3: return "DYN (shared object)";
    case 4: return "CORE";
    default: return "unknown";
  }
}
const char* seg_type_name(u32 t) {
  switch (t) {
    case elf::PT_NULL: return "NULL";
    case elf::PT_LOAD: return "LOAD";
    case elf::PT_DYNAMIC: return "DYNAMIC";
    case elf::PT_INTERP: return "INTERP";
    case elf::PT_NOTE: return "NOTE";
    case elf::PT_SHLIB: return "SHLIB";
    case elf::PT_PHDR: return "PHDR";
    case elf::PT_TLS: return "TLS";
    case elf::PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case elf::PT_GNU_STACK: return "GNU_STACK";
    case elf::PT_GNU_RELRO: return "GNU_RELRO";
    case elf::PT_ARM_EXIDX: return "ARM_EXIDX";
    default: return "OTHER";
  }
}
const char* sec_type_name(u32 t) {
  switch (t) {
    case elf::SHT_NULL: return "NULL";
    case elf::SHT_PROGBITS: return "PROGBITS";
    case elf::SHT_SYMTAB: return "SYMTAB";
    case elf::SHT_STRTAB: return "STRTAB";
    case elf::SHT_RELA: return "RELA";
    case elf::SHT_HASH: return "HASH";
    case elf::SHT_DYNAMIC: return "DYNAMIC";
    case elf::SHT_NOTE: return "NOTE";
    case elf::SHT_NOBITS: return "NOBITS";
    case elf::SHT_REL: return "REL";
    case elf::SHT_DYNSYM: return "DYNSYM";
    case elf::SHT_INIT_ARRAY: return "INIT_ARRAY";
    case elf::SHT_FINI_ARRAY: return "FINI_ARRAY";
    case elf::SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
    case elf::SHT_GROUP: return "GROUP";
    case elf::SHT_RELR: return "RELR";
    case elf::SHT_ANDROID_REL: return "ANDROID_REL";
    case elf::SHT_ANDROID_RELA: return "ANDROID_RELA";
    case elf::SHT_ANDROID_RELR: return "ANDROID_RELR";
    case elf::SHT_GNU_HASH: return "GNU_HASH";
    case elf::SHT_GNU_VERSYM: return "GNU_VERSYM";
    case elf::SHT_ARM_EXIDX: return "ARM_EXIDX";
    case elf::SHT_ARM_ATTRIBUTES: return "ARM_ATTRIBUTES";
    default: return "OTHER";
  }
}
std::string seg_flags_str(u32 f) {
  std::string s = "---";
  if (f & elf::PF_R) s[0] = 'R';
  if (f & elf::PF_W) s[1] = 'W';
  if (f & elf::PF_X) s[2] = 'X';
  return s;
}
std::string sec_flags_str(u64 f) {
  std::string s;
  if (f & elf::SHF_WRITE) s += 'W';
  if (f & elf::SHF_ALLOC) s += 'A';
  if (f & elf::SHF_EXECINSTR) s += 'X';
  if (f & elf::SHF_MERGE) s += 'M';
  if (f & elf::SHF_STRINGS) s += 'S';
  if (f & 0x400) s += 'T';
  if (f & elf::SHF_COMPRESSED) s += 'C';
  return s.empty() ? "-" : s;
}
const char* sym_type_name(u8 t) {
  switch (t) {
    case elf::STT_NOTYPE: return "NOTYPE";
    case elf::STT_OBJECT: return "OBJECT";
    case elf::STT_FUNC: return "FUNC";
    case elf::STT_SECTION: return "SECTION";
    case elf::STT_FILE: return "FILE";
    case elf::STT_COMMON: return "COMMON";
    case elf::STT_TLS: return "TLS";
    case elf::STT_GNU_IFUNC: return "IFUNC";
    default: return "OTHER";
  }
}
const char* sym_bind_name(u8 b) {
  switch (b) {
    case elf::STB_LOCAL: return "LOCAL";
    case elf::STB_GLOBAL: return "GLOBAL";
    case elf::STB_WEAK: return "WEAK";
    default: return "OTHER";
  }
}
const char* sym_vis_name(u8 v) {
  switch (v) {
    case 0: return "DEFAULT";
    case 1: return "INTERNAL";
    case 2: return "HIDDEN";
    case 3: return "PROTECTED";
    default: return "?";
  }
}
const char* dyn_tag_name(i64 t) {
  switch (t) {
    case elf::DT_NULL: return "NULL";
    case elf::DT_NEEDED: return "NEEDED";
    case elf::DT_PLTRELSZ: return "PLTRELSZ";
    case elf::DT_PLTGOT: return "PLTGOT";
    case elf::DT_HASH: return "HASH";
    case elf::DT_STRTAB: return "STRTAB";
    case elf::DT_SYMTAB: return "SYMTAB";
    case elf::DT_RELA: return "RELA";
    case elf::DT_RELASZ: return "RELASZ";
    case elf::DT_RELAENT: return "RELAENT";
    case elf::DT_STRSZ: return "STRSZ";
    case elf::DT_SYMENT: return "SYMENT";
    case elf::DT_INIT: return "INIT";
    case elf::DT_FINI: return "FINI";
    case elf::DT_SONAME: return "SONAME";
    case elf::DT_RPATH: return "RPATH";
    case elf::DT_REL: return "REL";
    case elf::DT_RELSZ: return "RELSZ";
    case elf::DT_RELENT: return "RELENT";
    case elf::DT_PLTREL: return "PLTREL";
    case elf::DT_JMPREL: return "JMPREL";
    case elf::DT_INIT_ARRAY: return "INIT_ARRAY";
    case elf::DT_FINI_ARRAY: return "FINI_ARRAY";
    case elf::DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ";
    case elf::DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
    case elf::DT_RUNPATH: return "RUNPATH";
    case elf::DT_PREINIT_ARRAY: return "PREINIT_ARRAY";
    case elf::DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ";
    case elf::DT_RELRSZ: return "RELRSZ";
    case elf::DT_RELR: return "RELR";
    case elf::DT_RELRENT: return "RELRENT";
    case elf::DT_ANDROID_REL: return "ANDROID_REL";
    case elf::DT_ANDROID_RELSZ: return "ANDROID_RELSZ";
    case elf::DT_ANDROID_RELA: return "ANDROID_RELA";
    case elf::DT_ANDROID_RELASZ: return "ANDROID_RELASZ";
    case elf::DT_ANDROID_RELR: return "ANDROID_RELR";
    case elf::DT_ANDROID_RELRSZ: return "ANDROID_RELRSZ";
    case elf::DT_ANDROID_RELRENT: return "ANDROID_RELRENT";
    case elf::DT_GNU_HASH: return "GNU_HASH";
    case 0x6ffffff0: return "VERSYM";
    case 0x6ffffffe: return "VERNEED";
    case 0x6fffffff: return "VERNEEDNUM";
    case 30: return "FLAGS";
    case 0x6ffffffb: return "FLAGS_1";
    case 0x70000001: return "ARM_RESERVED1";
    default: return "OTHER";
  }
}

std::string sym_shndx_name(const ElfModel& m, u16 shndx) {
  if (shndx == elf::SHN_UNDEF) return "UND";
  if (shndx == elf::SHN_ABS) return "ABS";
  if (shndx == elf::SHN_COMMON) return "COM";
  if (shndx >= elf::SHN_LORESERVE) return strf("RSV%04x", shndx);
  if (shndx < m.secs.size() && !m.secs[shndx].name.empty()) return m.secs[shndx].name;
  return std::to_string(shndx);
}

// Relocation names ------------------------------------------------------------
std::string reloc_type_name(const ElfModel& m, u32 t) {
  switch (m.arch) {
    case Arch::Arm64:
      switch (t) {
        case 0: return "R_AARCH64_NONE";
        case 257: return "R_AARCH64_ABS64";
        case 258: return "R_AARCH64_ABS32";
        case 1024: return "R_AARCH64_COPY";
        case 1025: return "R_AARCH64_GLOB_DAT";
        case 1026: return "R_AARCH64_JUMP_SLOT";
        case 1027: return "R_AARCH64_RELATIVE";
        case 1028: return "R_AARCH64_TLS_DTPMOD";
        case 1029: return "R_AARCH64_TLS_DTPREL";
        case 1030: return "R_AARCH64_TLS_TPREL";
        case 1031: return "R_AARCH64_TLSDESC";
        case 1032: return "R_AARCH64_IRELATIVE";
        default: break;
      }
      break;
    case Arch::Arm:
      switch (t) {
        case 0: return "R_ARM_NONE";
        case 2: return "R_ARM_ABS32";
        case 17: return "R_ARM_TLS_DTPMOD32";
        case 18: return "R_ARM_TLS_DTPOFF32";
        case 19: return "R_ARM_TLS_TPOFF32";
        case 20: return "R_ARM_COPY";
        case 21: return "R_ARM_GLOB_DAT";
        case 22: return "R_ARM_JUMP_SLOT";
        case 23: return "R_ARM_RELATIVE";
        case 160: return "R_ARM_IRELATIVE";
        default: break;
      }
      break;
    case Arch::X86_64:
      switch (t) {
        case 0: return "R_X86_64_NONE";
        case 1: return "R_X86_64_64";
        case 5: return "R_X86_64_COPY";
        case 6: return "R_X86_64_GLOB_DAT";
        case 7: return "R_X86_64_JUMP_SLOT";
        case 8: return "R_X86_64_RELATIVE";
        case 16: return "R_X86_64_DTPMOD64";
        case 17: return "R_X86_64_DTPOFF64";
        case 18: return "R_X86_64_TPOFF64";
        case 37: return "R_X86_64_IRELATIVE";
        default: break;
      }
      break;
    case Arch::X86:
      switch (t) {
        case 0: return "R_386_NONE";
        case 1: return "R_386_32";
        case 5: return "R_386_COPY";
        case 6: return "R_386_GLOB_DAT";
        case 7: return "R_386_JMP_SLOT";
        case 8: return "R_386_RELATIVE";
        case 14: return "R_386_TLS_TPOFF";
        case 35: return "R_386_TLS_DTPMOD32";
        case 36: return "R_386_TLS_DTPOFF32";
        case 42: return "R_386_IRELATIVE";
        default: break;
      }
      break;
    default: break;
  }
  return strf("R_%u", t);
}
bool reloc_is_relative(const ElfModel& m, u32 t) {
  switch (m.arch) {
    case Arch::Arm64: return t == 1027;
    case Arch::Arm: return t == 23;
    case Arch::X86_64: case Arch::X86: return t == 8;
    default: return false;
  }
}
bool reloc_is_jump_slot(const ElfModel& m, u32 t) {
  switch (m.arch) {
    case Arch::Arm64: return t == 1026;
    case Arch::Arm: return t == 22;
    case Arch::X86_64: case Arch::X86: return t == 7;
    default: return false;
  }
}
bool reloc_is_glob_dat(const ElfModel& m, u32 t) {
  switch (m.arch) {
    case Arch::Arm64: return t == 1025;
    case Arch::Arm: return t == 21;
    case Arch::X86_64: case Arch::X86: return t == 6;
    default: return false;
  }
}
bool reloc_is_abs(const ElfModel& m, u32 t) {
  switch (m.arch) {
    case Arch::Arm64: return t == 257;
    case Arch::Arm: return t == 2;
    case Arch::X86_64: return t == 1;
    case Arch::X86: return t == 1;
    default: return false;
  }
}

// ---------------------------------------------------------------- model helpers
bool ElfModel::has_loads() const {
  for (auto& s : segs)
    if (s.type == elf::PT_LOAD) return true;
  return false;
}

const ElfSegment* ElfModel::seg_for_vaddr(u64 va) const {
  for (auto& s : segs)
    if (s.type == elf::PT_LOAD && va >= s.vaddr && va - s.vaddr < s.memsz) return &s;
  return nullptr;
}
const ElfSegment* ElfModel::seg_for_offset(u64 off) const {
  for (auto& s : segs)
    if (s.type == elf::PT_LOAD && off >= s.offset && off - s.offset < s.filesz) return &s;
  return nullptr;
}
bool ElfModel::vaddr_to_off(u64 va, u64& off) const {
  for (auto& s : segs) {
    if (s.type != elf::PT_LOAD) continue;
    if (va >= s.vaddr && va - s.vaddr < s.filesz) {
      u64 o = s.offset + (va - s.vaddr);
      if (o < file_size) {
        off = o;
        return true;
      }
    }
  }
  return false;
}
bool ElfModel::off_to_vaddr(u64 off, u64& va) const {
  for (auto& s : segs) {
    if (s.type != elf::PT_LOAD) continue;
    if (off >= s.offset && off - s.offset < s.filesz) {
      va = s.vaddr + (off - s.offset);
      return true;
    }
  }
  return false;
}
bool ElfModel::is_exec_vaddr(u64 va) const {
  const ElfSegment* s = seg_for_vaddr(va);
  return s && (s->flags & elf::PF_X);
}
int ElfModel::section_for_vaddr(u64 va) const {
  int best = -1;
  for (auto& s : secs) {
    if (!s.alloc() || s.size == 0 || (s.flags & 0x400)) continue;
    if (va >= s.addr && va - s.addr < s.size) {
      best = s.index;
      if (!s.synthetic) break;
    }
  }
  return best;
}
int ElfModel::section_for_offset(u64 off) const {
  for (auto& s : secs) {
    if (!s.has_file_data() || s.size == 0) continue;
    if (off >= s.offset && off - s.offset < s.size) return s.index;
  }
  return -1;
}
const ElfSection* ElfModel::section_by_name(const std::string& n) const {
  for (auto& s : secs)
    if (s.name == n) return &s;
  return nullptr;
}
const ElfSection* ElfModel::section_by_type(u32 t) const {
  for (auto& s : secs)
    if (s.type == t) return &s;
  return nullptr;
}
const ElfSymbol* ElfModel::find_dynsym(const std::string& name) const {
  for (auto& s : dynsym)
    if (s.name == name) return &s;
  return nullptr;
}
void ElfModel::finish_derived() {
  bool any = false;
  u64 lo = 0, hi = 0;
  for (auto& s : segs) {
    if (s.type != elf::PT_LOAD || s.memsz == 0) continue;
    if (!any) {
      lo = s.vaddr;
      hi = s.vaddr + s.memsz;
      any = true;
    } else {
      lo = std::min(lo, s.vaddr);
      hi = std::max(hi, s.vaddr + s.memsz);
    }
  }
  min_load_vaddr = lo;
  max_load_vaddr = hi;
  load_base_rel = lo & ~(u64)0xfff;
}

void ParseCtx::note(ElfModel& m, u64 off, const char* where, const std::string& text) const {
  if (m.anomalies.size() < 2000) m.anomalies.push_back({off, where, text});
  if (diagnostics) log.log(LogLevel::Warning, "elf", strf("[0x%llx] %s: %s", (unsigned long long)off, where, text.c_str()));
  else log.log(LogLevel::Debug, "elf", strf("[0x%llx] %s: %s", (unsigned long long)off, where, text.c_str()));
}

// ---------------------------------------------------------------- helpers
namespace {

struct Rd {
  bool le;
  u16 u16_(const u8* p) const { return rd16(p, le); }
  u32 u32_(const u8* p) const { return rd32(p, le); }
  u64 u64_(const u8* p) const { return rd64(p, le); }
};

std::string cstr_at(const std::vector<u8>& tab, u64 off) {
  if (off >= tab.size()) return std::string();
  size_t i = (size_t)off, n = tab.size();
  size_t e = i;
  while (e < n && tab[e] != 0 && e - i < syscap::kMaxStringLen) e++;
  return std::string((const char*)tab.data() + i, e - i);
}

u64 sleb_read(const u8*& p, const u8* end, bool& ok) {
  u64 result = 0;
  int shift = 0;
  u8 b;
  do {
    if (p >= end) {
      ok = false;
      return 0;
    }
    b = *p++;
    if (shift < 64) result |= (u64)(b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  if (shift < 64 && (b & 0x40)) result |= ~(u64)0 << shift;
  return result;
}

// Reads a table [off, off+bytes) with memory budget accounting; releases on destruction.
struct BudgetBuf {
  MemBudget& mem;
  std::vector<u8> data;
  u64 reserved = 0;
  explicit BudgetBuf(MemBudget& m) : mem(m) {}
  ~BudgetBuf() { mem.release(reserved); }
  bool read(const ByteSource& src, u64 off, u64 len, u64 cap) {
    if (len > cap || off > src.size() || len > src.size() - off) return false;
    if (!mem.try_reserve(len)) return false;
    reserved += len;
    data.assign((size_t)len, 0);
    return src.read_exact(off, data.data(), (size_t)len);
  }
};

}  // namespace

// ---------------------------------------------------------------- identification
namespace {

struct IdentScore {
  int got = 0, max = 0;
};

// How well the header fields fit the given class and byte order.
IdentScore ident_score(const u8* h, size_t n, u64 fsize, bool is64, bool le) {
  IdentScore s;
  auto add = [&](int w, bool ok) {
    s.max += w;
    if (ok) s.got += w;
  };
  const u16 type = rd16(h + 16, le), machine = rd16(h + 18, le);
  const u32 ver = rd32(h + 20, le);
  const bool known = machine == 183 || machine == 40 || machine == 62 || machine == 3;
  add(3, known);
  if (known) add(2, (machine == 183 || machine == 62) == is64);
  else s.max += 2;
  add(1, type == 2 || type == 3);
  add(1, ver == 1);
  const size_t need = is64 ? 64 : 52;
  if (n >= need) {
    u64 phoff, shoff;
    u16 ehsize, phentsize, phnum, shentsize, shnum;
    if (is64) {
      phoff = rd64(h + 32, le); shoff = rd64(h + 40, le);
      ehsize = rd16(h + 52, le); phentsize = rd16(h + 54, le); phnum = rd16(h + 56, le); shentsize = rd16(h + 58, le); shnum = rd16(h + 60, le);
    } else {
      phoff = rd32(h + 28, le); shoff = rd32(h + 32, le);
      ehsize = rd16(h + 40, le); phentsize = rd16(h + 42, le); phnum = rd16(h + 44, le); shentsize = rd16(h + 46, le); shnum = rd16(h + 48, le);
    }
    add(2, ehsize == need);
    add(1, phnum == 0 || phentsize == (is64 ? 56 : 32));
    add(1, shnum == 0 || shentsize == (is64 ? 64 : 40));
    add(1, phoff == 0 || (phoff <= fsize && (u64)phnum * phentsize <= fsize - phoff));
    add(1, shoff == 0 || (shoff <= fsize && (u64)shnum * shentsize <= fsize - shoff));
  }
  return s;
}

}  // namespace

IdentGuess elf_guess_ident(const u8* h, size_t n, u64 file_size) {
  IdentGuess g;
  if (n < 24) return g;
  const bool cls_ok = h[4] == 1 || h[4] == 2, ord_ok = h[5] == 1 || h[5] == 2;
  const bool decl64 = h[4] == 2, decl_le = h[5] != 2;
  g.is64 = decl64;
  g.le = decl_le;
  IdentScore declared;
  if (cls_ok && ord_ok) declared = ident_score(h, n, file_size, decl64, decl_le);
  IdentScore best;
  bool best64 = decl64, best_le = decl_le, have_best = false;
  for (int c = 0; c < 2; c++) {
    const bool is64 = c == 1;
    for (int o = 0; o < 2; o++) {
      const bool le = o == 0;
      IdentScore sc = ident_score(h, n, file_size, is64, le);
      const bool better = !have_best || sc.got > best.got || (sc.got == best.got && is64 == decl64 && le == decl_le);
      if (better) {
        best = sc;
        best64 = is64;
        best_le = le;
        have_best = true;
      }
    }
  }
  if (!have_best) return g;
  const bool good_fit = best.got >= 5 && best.got * 100 >= best.max * 60;
  if (cls_ok && ord_ok) {
    g.valid = true;
    // Valid declared values are replaced only when the fields fit another combination clearly better.
    if ((best64 != decl64 || best_le != decl_le) && good_fit && best.got >= declared.got + 4) {
      g.is64 = best64;
      g.le = best_le;
    }
  } else {
    if (!good_fit) return g;
    g.valid = true;
    g.is64 = best64;
    g.le = best_le;
  }
  if (g.is64 != decl64 || !cls_ok) {
    g.class_inferred = g.is64 != decl64 || !cls_ok;
    g.class_note = strf("e_ident[4] (EI_CLASS)=%u %s; the header fields fit a %s file, so it is read as %s", h[4], cls_ok ? "disagrees with the header fields" : "is not a valid class",
                        g.is64 ? "64-bit" : "32-bit", g.is64 ? "64-bit" : "32-bit");
  }
  if (g.le != decl_le || !ord_ok) {
    g.order_inferred = true;
    g.order_note = strf("e_ident[5] (EI_DATA)=%u %s; the header fields fit a %s file, so it is read as %s", h[5], ord_ok ? "disagrees with the header fields" : "is not a valid byte order",
                        g.le ? "little-endian" : "big-endian", g.le ? "little-endian" : "big-endian");
  }
  return g;
}

// ---------------------------------------------------------------- header
bool elf_parse_header(ParseCtx& c, ElfModel& m, std::string& err) {
  m.file_size = c.src.size();
  u8 h[64];
  size_t got = c.src.read_at(0, h, sizeof h);
  if (got < 16) {
    err = "file is too small to be an ELF file";
    return false;
  }
  if (h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') {
    err = "ELF signature (7f 45 4c 46) not found";
    return false;
  }
  IdentGuess ig = elf_guess_ident(h, got, m.file_size);
  if (!ig.valid) {
    if (h[4] != 1 && h[4] != 2) err = strf("invalid ELF class %u in e_ident[4]", h[4]);
    else if (h[5] != 1 && h[5] != 2) err = strf("invalid byte order %u in e_ident[5]", h[5]);
    else err = "the ELF header is too short to check its identification";
    return false;
  }
  m.is64 = ig.is64;
  m.le = ig.le;
  const size_t need = m.is64 ? 64 : 52;
  if (got < need) {
    err = "ELF header is truncated";
    return false;
  }
  Rd r{m.le};
  m.osabi = h[7];
  m.abiversion = h[8];
  m.type = r.u16_(h + 16);
  m.machine = r.u16_(h + 18);
  m.version = r.u32_(h + 20);
  if (m.is64) {
    m.entry = r.u64_(h + 24);
    m.phoff = r.u64_(h + 32);
    m.shoff = r.u64_(h + 40);
    m.flags = r.u32_(h + 48);
    m.ehsize = r.u16_(h + 52);
    m.phentsize = r.u16_(h + 54);
    m.phnum = r.u16_(h + 56);
    m.shentsize = r.u16_(h + 58);
    m.shnum = r.u16_(h + 60);
    m.shstrndx = r.u16_(h + 62);
  } else {
    m.entry = r.u32_(h + 24);
    m.phoff = r.u32_(h + 28);
    m.shoff = r.u32_(h + 32);
    m.flags = r.u32_(h + 36);
    m.ehsize = r.u16_(h + 40);
    m.phentsize = r.u16_(h + 42);
    m.phnum = r.u16_(h + 44);
    m.shentsize = r.u16_(h + 46);
    m.shnum = r.u16_(h + 48);
    m.shstrndx = r.u16_(h + 50);
  }
  switch (m.machine) {
    case 183: m.arch = Arch::Arm64; break;
    case 40: m.arch = Arch::Arm; break;
    case 62: m.arch = Arch::X86_64; break;
    case 3: m.arch = Arch::X86; break;
    default: m.arch = Arch::Other; break;
  }
  m.header_ok = true;
  // Anomalies in the header.
  if (ig.class_inferred) c.note(m, 4, "e_ident", ig.class_note);
  if (ig.order_inferred) c.note(m, 5, "e_ident", ig.order_note);
  m.ident_note = ig.class_inferred ? ig.class_note : std::string();
  if (ig.order_inferred) m.ident_note += (m.ident_note.empty() ? "" : "; ") + ig.order_note;
  for (int i = 9; i < 16; i++) {
    if (h[i] != 0) {
      c.note(m, (u64)i, "e_ident", strf("padding byte e_ident[%d]=0x%02x is not zero", i, h[i]));
      break;
    }
  }
  if (h[6] != 1) c.note(m, 6, "e_ident", strf("EI_VERSION=%u (expected 1)", h[6]));
  if (m.version != 1) c.note(m, 20, "e_version", strf("e_version=%u (expected 1)", m.version));
  if (m.ehsize != need) c.note(m, m.is64 ? 52 : 40, "e_ehsize", strf("e_ehsize=%u (expected %zu)", m.ehsize, need));
  if (m.type != 3 && m.type != 2) c.note(m, 16, "e_type", strf("unusual e_type=%u (%s)", m.type, elf_type_name(m.type)));
  if (m.machine == 0) c.note(m, 18, "e_machine", "e_machine is 0");
  return true;
}

// ---------------------------------------------------------------- segments
bool elf_parse_segments(ParseCtx& c, ElfModel& m, bool allow_assume) {
  m.segs.clear();
  const u64 stdent = m.is64 ? 56 : 32;
  Rd r{m.le};
  u64 phoff = m.phoff, phnum = m.phnum, phent = m.phentsize;

  auto parse_at = [&](u64 off, u64 count, u64 ent, std::vector<ElfSegment>& out, bool strict) {
    std::vector<u8> buf(stdent);
    for (u64 i = 0; i < count; i++) {
      u64 at = off + i * ent;
      if (at + stdent > m.file_size) break;
      if (!c.src.read_exact(at, buf.data(), (size_t)stdent)) break;
      ElfSegment s;
      s.index = (int)i;
      const u8* p = buf.data();
      if (m.is64) {
        s.type = r.u32_(p);
        s.flags = r.u32_(p + 4);
        s.offset = r.u64_(p + 8);
        s.vaddr = r.u64_(p + 16);
        s.paddr = r.u64_(p + 24);
        s.filesz = r.u64_(p + 32);
        s.memsz = r.u64_(p + 40);
        s.align = r.u64_(p + 48);
      } else {
        s.type = r.u32_(p);
        s.offset = r.u32_(p + 4);
        s.vaddr = r.u32_(p + 8);
        s.paddr = r.u32_(p + 12);
        s.filesz = r.u32_(p + 16);
        s.memsz = r.u32_(p + 20);
        s.flags = r.u32_(p + 24);
        s.align = r.u32_(p + 28);
      }
      if (strict) {
        bool known = s.type <= 8 || (s.type >= 0x6474e550 && s.type <= 0x6474e552) || s.type == elf::PT_ARM_EXIDX;
        if (!known) break;
        if (s.type == elf::PT_LOAD && (s.offset > m.file_size + 0x100000 || s.filesz > m.file_size * 2 + 0x100000)) break;
      }
      out.push_back(s);
    }
  };

  bool declared_ok = phoff != 0 && phnum != 0 && phent >= stdent && phnum <= syscap::kMaxElfTables && phoff <= m.file_size;
  if (declared_ok) {
    u64 fit = (m.file_size - phoff) / phent;
    if (fit < phnum) {
      c.note(m, 32, "e_phnum", strf("program header table declared with %llu entries but only %llu fit in the file", (unsigned long long)phnum, (unsigned long long)fit));
      phnum = fit;
    }
    parse_at(phoff, phnum, phent, m.segs, false);
  } else {
    c.note(m, 32, "program headers",
           strf("program header table is unusable (phoff=0x%llx phnum=%llu phentsize=%llu)", (unsigned long long)phoff, (unsigned long long)phnum, (unsigned long long)phent));
  }

  bool has_load = false;
  for (auto& s : m.segs) has_load |= (s.type == elf::PT_LOAD);
  if (!has_load && allow_assume) {
    std::vector<ElfSegment> alt;
    parse_at(m.ehsize ? m.ehsize : (m.is64 ? 64 : 52), 64, stdent, alt, true);
    bool alt_load = false;
    for (auto& s : alt) alt_load |= (s.type == elf::PT_LOAD);
    if (alt_load) {
      m.segs = alt;
      m.phdr_assumed = true;
      c.note(m, m.ehsize, "program headers", strf("assumed standard layout: %zu entries read directly after the ELF header", alt.size()));
    }
  }
  // Sanity notes.
  for (auto& s : m.segs) {
    if (s.type == elf::PT_LOAD) {
      if (s.filesz > s.memsz) c.note(m, m.phoff + (u64)s.index * phent, "PT_LOAD", strf("segment %d: p_filesz > p_memsz", s.index));
      if (s.offset > m.file_size || s.filesz > m.file_size - std::min(m.file_size, s.offset))
        c.note(m, m.phoff + (u64)s.index * phent, "PT_LOAD", strf("segment %d extends past the end of the file", s.index));
      if (s.align > 1 && ((s.vaddr - s.offset) % s.align) != 0) c.note(m, m.phoff + (u64)s.index * phent, "PT_LOAD", strf("segment %d: vaddr and offset are not congruent modulo p_align", s.index));
    }
  }
  m.segs_ok = false;
  for (auto& s : m.segs) m.segs_ok |= (s.type == elf::PT_LOAD);
  m.finish_derived();
  return !m.segs.empty();
}

// ---------------------------------------------------------------- sections
bool elf_parse_sections(ParseCtx& c, ElfModel& m) {
  m.secs.clear();
  m.secs_ok = false;
  const u64 stdent = m.is64 ? 64 : 40;
  Rd r{m.le};
  if (m.shoff == 0) {
    c.log.log(LogLevel::Debug, "elf", "no section header table (e_shoff=0)");
    return false;
  }
  if (m.shentsize < stdent) {
    c.note(m, m.is64 ? 58 : 46, "e_shentsize", strf("e_shentsize=%u is smaller than %llu", m.shentsize, (unsigned long long)stdent));
    return false;
  }
  if (m.shoff >= m.file_size || m.file_size - m.shoff < stdent) {
    c.note(m, m.is64 ? 40 : 32, "e_shoff", strf("section header table offset 0x%llx lies outside the file", (unsigned long long)m.shoff));
    return false;
  }
  std::vector<u8> e0(stdent);
  if (!c.src.read_exact(m.shoff, e0.data(), (size_t)stdent)) return false;
  u64 n = m.shnum;
  u64 shstrndx = m.shstrndx;
  auto size_field = [&](const u8* p) { return m.is64 ? r.u64_(p + 32) : (u64)r.u32_(p + 20); };
  auto link_field = [&](const u8* p) { return m.is64 ? r.u32_(p + 40) : r.u32_(p + 24); };
  if (n == 0) {
    n = size_field(e0.data());  // extended section numbering
    if (n == 0) return false;
  }
  if (shstrndx == 0xffff) shstrndx = link_field(e0.data());
  if (n > syscap::kMaxElfTables) {
    c.note(m, m.shoff, "e_shnum", strf("section count %llu is implausible", (unsigned long long)n));
    return false;
  }
  u64 fit = (m.file_size - m.shoff) / m.shentsize;
  if (fit < n) {
    c.note(m, m.shoff, "e_shnum", strf("section table declared with %llu entries but only %llu fit in the file", (unsigned long long)n, (unsigned long long)fit));
    n = fit;
  }
  std::vector<ElfSection> secs;
  std::vector<u32> name_idx;
  secs.reserve((size_t)n);
  std::vector<u8> buf(stdent);
  u64 bad = 0;
  for (u64 i = 0; i < n; i++) {
    if (!c.src.read_exact(m.shoff + i * m.shentsize, buf.data(), (size_t)stdent)) break;
    ElfSection s;
    s.index = (int)i;
    const u8* p = buf.data();
    u32 ni = r.u32_(p);
    s.type = r.u32_(p + 4);
    if (m.is64) {
      s.flags = r.u64_(p + 8);
      s.addr = r.u64_(p + 16);
      s.offset = r.u64_(p + 24);
      s.size = r.u64_(p + 32);
      s.link = r.u32_(p + 40);
      s.info = r.u32_(p + 44);
      s.addralign = r.u64_(p + 48);
      s.entsize = r.u64_(p + 56);
    } else {
      s.flags = r.u32_(p + 8);
      s.addr = r.u32_(p + 12);
      s.offset = r.u32_(p + 16);
      s.size = r.u32_(p + 20);
      s.link = r.u32_(p + 24);
      s.info = r.u32_(p + 28);
      s.addralign = r.u32_(p + 32);
      s.entsize = r.u32_(p + 36);
    }
    if (s.has_file_data() && s.size) {
      if (s.offset > m.file_size || s.size > m.file_size - s.offset) {
        bad++;
        c.note(m, m.shoff + i * m.shentsize, "section", strf("section %llu data [0x%llx, +0x%llx) lies outside the file", (unsigned long long)i, (unsigned long long)s.offset, (unsigned long long)s.size));
      }
    }
    name_idx.push_back(ni);
    secs.push_back(std::move(s));
  }
  if (secs.empty()) return false;
  // If most sections are outside the file the table is considered damaged and not trusted.
  if (secs.size() > 2 && bad * 2 > secs.size()) {
    c.note(m, m.shoff, "section table", "most section headers point outside the file; the table is not trusted");
    return false;
  }
  // Names.
  if (shstrndx < secs.size() && secs[(size_t)shstrndx].has_file_data()) {
    const ElfSection& st = secs[(size_t)shstrndx];
    BudgetBuf b(c.mem);
    if (st.size <= (64u << 20) && b.read(c.src, st.offset, st.size, 64u << 20)) {
      for (size_t i = 0; i < secs.size(); i++) {
        if (name_idx[i] < b.data.size()) secs[i].name = cstr_at(b.data, name_idx[i]);
        else if (name_idx[i] != 0) c.note(m, m.shoff + i * m.shentsize, "sh_name", strf("section %zu name offset 0x%x is outside .shstrtab", i, name_idx[i]));
      }
    } else {
      c.note(m, m.is64 ? 62 : 50, "e_shstrndx", "section name string table cannot be read");
    }
  } else if (shstrndx != 0) {
    c.note(m, m.is64 ? 62 : 50, "e_shstrndx", strf("e_shstrndx=%llu is invalid", (unsigned long long)shstrndx));
  }
  for (auto& s : secs)
    if (s.name.empty() && s.index != 0) s.name = strf("sec%d", s.index);
  m.secs = std::move(secs);
  m.secs_ok = true;
  return true;
}

void elf_reconstruct_sections(ParseCtx& c, ElfModel& m) {
  m.secs.clear();
  ElfSection null_sec;
  null_sec.synthetic = true;
  null_sec.type = elf::SHT_NULL;
  m.secs.push_back(null_sec);
  int load_i = 0;
  for (auto& s : m.segs) {
    ElfSection x;
    x.synthetic = true;
    x.type = elf::SHT_PROGBITS;
    x.addr = s.vaddr;
    x.offset = s.offset;
    x.size = s.type == elf::PT_LOAD ? s.memsz : s.filesz;
    x.addralign = s.align;
    switch (s.type) {
      case elf::PT_LOAD: {
        std::string perm = seg_flags_str(s.flags);
        for (auto& ch : perm) ch = (char)tolower((unsigned char)ch);
        x.name = strf("seg_load_%d_%s", load_i++, perm.c_str());
        x.flags = elf::SHF_ALLOC | ((s.flags & elf::PF_W) ? elf::SHF_WRITE : 0) | ((s.flags & elf::PF_X) ? elf::SHF_EXECINSTR : 0);
        if (s.filesz < s.memsz && s.filesz == 0) x.type = elf::SHT_NOBITS;
        break;
      }
      case elf::PT_DYNAMIC: x.name = "seg_dynamic"; x.type = elf::SHT_DYNAMIC; x.flags = elf::SHF_ALLOC | elf::SHF_WRITE; x.entsize = m.is64 ? 16 : 8; break;
      case elf::PT_GNU_EH_FRAME: x.name = "seg_eh_frame_hdr"; x.flags = elf::SHF_ALLOC; break;
      case elf::PT_ARM_EXIDX: x.name = "seg_arm_exidx"; x.type = elf::SHT_ARM_EXIDX; x.flags = elf::SHF_ALLOC; x.entsize = 8; break;
      case elf::PT_NOTE: x.name = strf("seg_note_%d", s.index); x.type = elf::SHT_NOTE; x.flags = elf::SHF_ALLOC; break;
      default: continue;
    }
    x.index = (int)m.secs.size();
    m.secs.push_back(x);
  }
  m.secs_reconstructed = true;
  c.log.log(LogLevel::Info, "elf", strf("section table unavailable: %zu pseudo sections built from program headers", m.secs.size() - 1));
}

// ---------------------------------------------------------------- dynamic
namespace {
bool read_dyn_entries(ParseCtx& c, ElfModel& m, u64 off, u64 size, std::vector<ElfDyn>& out) {
  const u64 ent = m.is64 ? 16 : 8;
  Rd r{m.le};
  u64 n = std::min<u64>(size / ent, syscap::kMaxElfTables);
  if (off > m.file_size) return false;
  n = std::min<u64>(n, (m.file_size - off) / ent);
  std::vector<u8> buf(ent);
  for (u64 i = 0; i < n; i++) {
    if (!c.src.read_exact(off + i * ent, buf.data(), (size_t)ent)) break;
    ElfDyn d;
    if (m.is64) {
      d.tag = (i64)r.u64_(buf.data());
      d.val = r.u64_(buf.data() + 8);
    } else {
      d.tag = (i64)(int32_t)r.u32_(buf.data());
      d.val = r.u32_(buf.data() + 4);
    }
    out.push_back(d);
    if (d.tag == elf::DT_NULL) break;
  }
  return !out.empty();
}

const ElfDyn* dyn_find(const ElfModel& m, i64 tag) {
  for (auto& d : m.dyn)
    if (d.tag == tag) return &d;
  return nullptr;
}
}  // namespace

bool elf_parse_dynamic(ParseCtx& c, ElfModel& m, bool allow_segment_fallback) {
  m.dyn.clear();
  m.needed.clear();
  m.dyn_ok = false;
  std::vector<u8> strtab;
  u64 strtab_off = 0, strtab_size = 0;

  if (m.secs_ok) {
    for (auto& s : m.secs) {
      if (s.type == elf::SHT_DYNAMIC && s.has_file_data() && s.size && s.offset < m.file_size) {
        if (read_dyn_entries(c, m, s.offset, std::min(s.size, m.file_size - s.offset), m.dyn)) {
          if (s.link < m.secs.size()) {
            const ElfSection& st = m.secs[s.link];
            strtab_off = st.offset;
            strtab_size = st.size;
          }
          break;
        }
      }
    }
  }
  if (m.dyn.empty() && allow_segment_fallback) {
    for (auto& s : m.segs) {
      if (s.type == elf::PT_DYNAMIC && s.offset < m.file_size) {
        if (read_dyn_entries(c, m, s.offset, std::min(s.filesz, m.file_size - s.offset), m.dyn)) {
          m.dyn_from_segment = true;
          break;
        }
      }
    }
    if (m.dyn.empty()) {
      c.log.log(LogLevel::Debug, "elf", "PT_DYNAMIC is absent or unreadable");
    }
  }
  if (m.dyn.empty()) return false;

  // String table.
  if (strtab_size == 0 || strtab_off == 0) {
    const ElfDyn* st = dyn_find(m, elf::DT_STRTAB);
    const ElfDyn* sz = dyn_find(m, elf::DT_STRSZ);
    u64 off;
    if (st && m.vaddr_to_off(st->val, off)) {
      strtab_off = off;
      strtab_size = sz ? sz->val : 0;
      if (strtab_size == 0 || strtab_size > m.file_size - off) strtab_size = std::min<u64>(m.file_size - off, 1u << 20);
    }
  }
  if (strtab_size && strtab_off < m.file_size) {
    BudgetBuf b(c.mem);
    if (b.read(c.src, strtab_off, std::min<u64>(strtab_size, m.file_size - strtab_off), 256u << 20)) {
      for (auto& d : m.dyn) {
        if (d.tag == elf::DT_NEEDED) m.needed.push_back(cstr_at(b.data, d.val));
        else if (d.tag == elf::DT_SONAME) m.soname = cstr_at(b.data, d.val);
        else if (d.tag == elf::DT_RUNPATH) m.runpath = cstr_at(b.data, d.val);
        else if (d.tag == elf::DT_RPATH) m.rpath = cstr_at(b.data, d.val);
      }
    }
  } else {
    c.note(m, 0, "dynamic", "dynamic string table location is unknown; DT_NEEDED and SONAME names are unavailable");
  }
  m.dyn_ok = true;
  return true;
}

// ---------------------------------------------------------------- symbols
namespace {

// Parses `count` symbols starting at file offset `off`; names come from strtab (already in memory).
bool parse_symbol_table(ParseCtx& c, ElfModel& m, u64 off, u64 count, u64 ent, const std::vector<u8>& strtab, bool dynamic, std::vector<ElfSymbol>& out, bool& partial) {
  const u64 stdent = m.is64 ? 24 : 16;
  Rd r{m.le};
  if (ent < stdent) ent = stdent;
  if (off >= m.file_size) return false;
  u64 fit = (m.file_size - off) / ent;
  if (count > fit) {
    c.note(m, off, dynamic ? ".dynsym" : ".symtab", strf("table declares %llu symbols but only %llu fit in the file", (unsigned long long)count, (unsigned long long)fit));
    count = fit;
  }
  if (count > syscap::kMaxElfTables) {
    count = syscap::kMaxElfTables;
    partial = true;
  }
  const u64 chunk = 4096;
  std::vector<u8> buf((size_t)(chunk * ent));
  u64 reserved = 0;
  out.reserve((size_t)std::min<u64>(count, 1u << 20));
  for (u64 i = 0; i < count; i += chunk) {
    if (c.cancel && c.cancel->cancelled()) return true;
    u64 n = std::min(chunk, count - i);
    u64 est = n * (sizeof(ElfSymbol) + 40);
    if (!c.mem.try_reserve(est)) {
      partial = true;
      c.log.log(LogLevel::Warning, "elf", strf("memory limit reached while reading %s: %llu of %llu symbols kept", dynamic ? ".dynsym" : ".symtab", (unsigned long long)i, (unsigned long long)count));
      break;
    }
    reserved += est;
    if (c.src.read_at(off + i * ent, buf.data(), (size_t)(n * ent)) < n * ent) {
      partial = true;
      break;
    }
    for (u64 k = 0; k < n; k++) {
      const u8* p = buf.data() + k * ent;
      ElfSymbol s;
      s.index = (u32)(i + k);
      s.dynamic = dynamic;
      u32 ni = r.u32_(p);
      if (m.is64) {
        s.info = p[4];
        s.other = p[5];
        s.shndx = r.u16_(p + 6);
        s.value = r.u64_(p + 8);
        s.size = r.u64_(p + 16);
      } else {
        s.value = r.u32_(p + 4);
        s.size = r.u32_(p + 8);
        s.info = p[12];
        s.other = p[13];
        s.shndx = r.u16_(p + 14);
      }
      if (ni) {
        if (ni < strtab.size()) s.name = cstr_at(strtab, ni);
        else c.note(m, off + (i + k) * ent, dynamic ? ".dynsym" : ".symtab", strf("symbol %llu name offset 0x%x is outside the string table", (unsigned long long)(i + k), ni));
      }
      out.push_back(std::move(s));
    }
  }
  (void)reserved;  // symbols stay in memory for the whole run; the reservation is intentionally kept
  return true;
}

u64 count_from_gnu_hash(ParseCtx& c, ElfModel& m, u64 off) {
  Rd r{m.le};
  u8 h[16];
  if (!c.src.read_exact(off, h, 16)) return 0;
  u32 nbuckets = r.u32_(h), symoffset = r.u32_(h + 4), bloom = r.u32_(h + 8);
  if (nbuckets == 0 || nbuckets > (1u << 24) || bloom > (1u << 24)) return 0;
  u64 wordsz = m.is64 ? 8 : 4;
  u64 buckets_off = off + 16 + (u64)bloom * wordsz;
  std::vector<u8> b((size_t)nbuckets * 4);
  if (!c.src.read_exact(buckets_off, b.data(), b.size())) return 0;
  u32 maxb = 0;
  for (u32 i = 0; i < nbuckets; i++) maxb = std::max(maxb, r.u32_(&b[(size_t)i * 4]));
  if (maxb < symoffset) return symoffset;
  u64 chain_off = buckets_off + (u64)nbuckets * 4;
  u64 idx = maxb;
  for (u64 guard = 0; guard < (1u << 24); guard++) {
    u8 v[4];
    if (!c.src.read_exact(chain_off + (idx - symoffset) * 4, v, 4)) return 0;
    if (r.u32_(v) & 1) return idx + 1;
    idx++;
  }
  return 0;
}

}  // namespace

bool elf_parse_symbols(ParseCtx& c, ElfModel& m, bool allow_dynamic_fallback) {
  m.dynsym.clear();
  m.symtab.clear();
  bool got_any = false;
  const u64 stdent = m.is64 ? 24 : 16;

  if (m.secs_ok) {
    for (auto& s : m.secs) {
      if ((s.type != elf::SHT_SYMTAB && s.type != elf::SHT_DYNSYM) || !s.has_file_data() || s.size == 0) continue;
      bool dyn = s.type == elf::SHT_DYNSYM;
      if (s.link >= m.secs.size()) {
        c.note(m, 0, s.name.c_str(), "symbol table has an invalid string table link");
        continue;
      }
      const ElfSection& st = m.secs[s.link];
      BudgetBuf b(c.mem);
      if (!b.read(c.src, st.offset, st.size, 512u << 20)) {
        c.note(m, st.offset, st.name.c_str(), "symbol string table cannot be read (outside file or over the memory limit)");
        m.symbols_partial = true;
        continue;
      }
      u64 ent = s.entsize ? s.entsize : stdent;
      u64 count = s.size / ent;
      if (dyn) {
        m.dynsym_declared = count;
        m.dynsym_off = s.offset;
        m.dynsym_ent = ent;
        m.dynstr_off = st.offset;
        m.dynstr_size = st.size;
      } else {
        m.symtab_declared = count;
      }
      bool partial = false;
      if (parse_symbol_table(c, m, s.offset, count, ent, b.data, dyn, dyn ? m.dynsym : m.symtab, partial)) got_any = true;
      m.symbols_partial |= partial;
    }
  }

  if (m.dynsym.empty() && allow_dynamic_fallback && m.dyn_ok) {
    const ElfDyn* symtab = dyn_find(m, elf::DT_SYMTAB);
    const ElfDyn* strtab = dyn_find(m, elf::DT_STRTAB);
    const ElfDyn* strsz = dyn_find(m, elf::DT_STRSZ);
    const ElfDyn* syment = dyn_find(m, elf::DT_SYMENT);
    u64 symoff = 0, stroff = 0;
    if (symtab && strtab && m.vaddr_to_off(symtab->val, symoff) && m.vaddr_to_off(strtab->val, stroff)) {
      u64 ent = syment && syment->val >= stdent ? syment->val : stdent;
      u64 count = 0;
      const char* how = "";
      u64 hoff;
      if (const ElfDyn* gh = dyn_find(m, elf::DT_GNU_HASH)) {
        if (m.vaddr_to_off(gh->val, hoff)) {
          count = count_from_gnu_hash(c, m, hoff);
          how = "DT_GNU_HASH";
        }
      }
      if (count == 0) {
        if (const ElfDyn* h = dyn_find(m, elf::DT_HASH)) {
          if (m.vaddr_to_off(h->val, hoff)) {
            u8 hh[8];
            if (c.src.read_exact(hoff, hh, 8)) {
              count = Rd{m.le}.u32_(hh + 4);
              how = "DT_HASH";
            }
          }
        }
      }
      if (count == 0 && strtab->val > symtab->val) {
        count = (strtab->val - symtab->val) / ent;
        how = "distance between DT_SYMTAB and DT_STRTAB";
      }
      if (count > 0) {
        u64 ssz = strsz ? strsz->val : 0;
        if (ssz == 0 || ssz > m.file_size - stroff) ssz = std::min<u64>(m.file_size - stroff, 64u << 20);
        BudgetBuf b(c.mem);
        if (b.read(c.src, stroff, ssz, 512u << 20)) {
          m.dynsym_declared = count;
          m.dynsym_off = symoff;
          m.dynsym_ent = ent;
          m.dynstr_off = stroff;
          m.dynstr_size = ssz;
          bool partial = false;
          if (parse_symbol_table(c, m, symoff, count, ent, b.data, true, m.dynsym, partial)) {
            m.dynsym_from_dynamic = true;
            got_any = true;
            c.log.log(LogLevel::Info, "elf", strf("dynamic symbol table recovered through the dynamic segment: %zu symbols (count from %s)", m.dynsym.size(), how));
          }
          m.symbols_partial |= partial;
        }
      }
    }
  }
  return got_any;
}

u64 elf_reparse_symbols_from_relocs(ParseCtx& c, ElfModel& m) {
  if (m.dynsym_off == 0 || m.dynstr_off == 0) return 0;
  u32 maxsym = 0;
  bool any = false;
  for (auto& r : m.relocs) {
    if (r.table == 0 && r.sym) {
      maxsym = std::max(maxsym, r.sym);
      any = true;
    }
  }
  if (!any || maxsym < m.dynsym.size()) return 0;
  const u64 ent = m.dynsym_ent ? m.dynsym_ent : (m.is64 ? 24 : 16);
  u64 want = (u64)maxsym + 1;
  if (m.dynsym_off + want * ent > m.file_size) want = (m.file_size - m.dynsym_off) / ent;
  if (want <= m.dynsym.size()) return 0;
  BudgetBuf b(c.mem);
  u64 ssz = std::min<u64>(m.dynstr_size ? m.dynstr_size : (m.file_size - m.dynstr_off), m.file_size - m.dynstr_off);
  if (!b.read(c.src, m.dynstr_off, ssz, 512u << 20)) return 0;
  // Only accept entries whose name offset is plausible; stop at the first implausible one.
  std::vector<ElfSymbol> extra;
  bool partial = false;
  std::vector<ElfSymbol> tmp;
  if (!parse_symbol_table(c, m, m.dynsym_off + (u64)m.dynsym.size() * ent, want - m.dynsym.size(), ent, b.data, true, tmp, partial)) return 0;
  u64 added = 0;
  Rd r{m.le};
  (void)r;
  for (auto& s : tmp) {
    s.index = (u32)m.dynsym.size();
    m.dynsym.push_back(std::move(s));
    added++;
  }
  m.reparsed_extra_symbols = added;
  return added;
}

// ---------------------------------------------------------------- relocations
namespace {

struct RelocSink {
  ElfModel& m;
  ParseCtx& c;
  u64 reserved_total = 0;
  bool overflow = false;
  bool push(const ElfReloc& r) {
    if (m.relocs.size() >= syscap::kMaxObjects) {
      overflow = true;
      return false;
    }
    if ((m.relocs.size() & 0xFFFF) == 0) {
      u64 est = (u64)0x10000 * sizeof(ElfReloc);
      if (!c.mem.try_reserve(est)) {
        overflow = true;
        return false;
      }
      reserved_total += est;
    }
    m.relocs.push_back(r);
    return true;
  }
};

void parse_rel_rela(ParseCtx& c, ElfModel& m, RelocSink& sink, u64 off, u64 size, bool rela, u8 kind, u8 table, u64 declared_ent) {
  Rd r{m.le};
  const u64 stdent = m.is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
  const u64 ent = declared_ent >= stdent ? declared_ent : stdent;
  if (off >= m.file_size) return;
  u64 n = std::min(size, m.file_size - off) / ent;
  m.reloc_expected += size / ent;
  const u64 chunk = 4096;
  std::vector<u8> buf((size_t)(chunk * ent));
  for (u64 i = 0; i < n; i += chunk) {
    if (c.cancel && c.cancel->cancelled()) return;
    u64 k = std::min(chunk, n - i);
    if (c.src.read_at(off + i * ent, buf.data(), (size_t)(k * ent)) < k * ent) return;
    for (u64 j = 0; j < k; j++) {
      const u8* p = buf.data() + j * ent;
      ElfReloc x;
      x.kind = kind;
      x.table = table;
      x.has_addend = rela;
      if (m.is64) {
        x.offset = r.u64_(p);
        u64 info = r.u64_(p + 8);
        x.type = (u32)(info & 0xffffffffu);
        x.sym = (u32)(info >> 32);
        if (rela) x.addend = (i64)r.u64_(p + 16);
      } else {
        x.offset = r.u32_(p);
        u32 info = r.u32_(p + 4);
        x.type = info & 0xff;
        x.sym = info >> 8;
        if (rela) x.addend = (i64)(int32_t)r.u32_(p + 8);
      }
      if (!sink.push(x)) return;
    }
  }
}

// Android packed relocations (APS2, SLEB128 encoded).
void parse_android_packed(ParseCtx& c, ElfModel& m, RelocSink& sink, u64 off, u64 size, bool rela_hint, u8 table) {
  if (size < 4 || off >= m.file_size) return;
  BudgetBuf b(c.mem);
  size = std::min(size, m.file_size - off);
  if (!b.read(c.src, off, size, 512u << 20)) {
    c.note(m, off, "android relocations", "packed relocation table cannot be read (outside file or over the memory limit)");
    m.relocs_partial = true;
    return;
  }
  const u8* p = b.data.data();
  const u8* end = p + b.data.size();
  if (!(p[0] == 'A' && p[1] == 'P' && p[2] == 'S' && p[3] == '2')) {
    c.note(m, off, "android relocations", "packed relocation table has no APS2 signature");
    return;
  }
  p += 4;
  bool ok = true;
  u64 count = sleb_read(p, end, ok);
  u64 roff = sleb_read(p, end, ok);
  u64 info = 0;
  i64 addend = 0;
  const u64 FLAG_INFO = 1, FLAG_DELTA = 2, FLAG_ADDEND_GROUP = 4, FLAG_HAS_ADDEND = 8;
  m.reloc_expected += count;
  u64 done = 0;
  while (ok && done < count) {
    if (c.cancel && c.cancel->cancelled()) return;
    u64 gsize = sleb_read(p, end, ok);
    u64 gflags = sleb_read(p, end, ok);
    if (!ok) break;
    u64 gdelta = 0;
    if (gflags & FLAG_DELTA) gdelta = sleb_read(p, end, ok);
    if (gflags & FLAG_INFO) info = sleb_read(p, end, ok);
    bool has_addend = (gflags & FLAG_HAS_ADDEND) != 0;
    if ((gflags & FLAG_ADDEND_GROUP) && has_addend) addend += (i64)sleb_read(p, end, ok);
    else if (!has_addend) addend = 0;
    if (!ok || gsize == 0 || gsize > count - done) {
      if (ok) c.note(m, off, "android relocations", "invalid group size in packed relocation table");
      break;
    }
    for (u64 i = 0; i < gsize && ok; i++) {
      if (gflags & FLAG_DELTA) roff += gdelta;
      else roff += sleb_read(p, end, ok);
      if (!(gflags & FLAG_INFO)) info = sleb_read(p, end, ok);
      if (has_addend && !(gflags & FLAG_ADDEND_GROUP)) addend += (i64)sleb_read(p, end, ok);
      if (!ok) break;
      ElfReloc x;
      x.kind = 3;
      x.table = table;
      x.offset = roff;
      x.has_addend = has_addend;
      x.addend = has_addend ? addend : 0;
      if (m.is64) {
        x.type = (u32)(info & 0xffffffffu);
        x.sym = (u32)(info >> 32);
      } else {
        x.type = (u32)(info & 0xff);
        x.sym = (u32)(info >> 8);
      }
      if (!sink.push(x)) return;
      done++;
    }
  }
  (void)rela_hint;
  if (!ok && done < count) {
    m.relocs_partial = true;
    c.note(m, off, "android relocations", strf("packed table ended early after %llu of %llu relocations", (unsigned long long)done, (unsigned long long)count));
  }
}

void parse_relr(ParseCtx& c, ElfModel& m, RelocSink& sink, u64 off, u64 size) {
  if (off >= m.file_size) return;
  const u64 wsz = m.ptr_size();
  size = std::min(size, m.file_size - off);
  u64 n = size / wsz;
  m.reloc_expected += 0;  // RELR expands to an unknown number of relocations
  Rd r{m.le};
  u32 relative_type = 0;
  switch (m.arch) {
    case Arch::Arm64: relative_type = 1027; break;
    case Arch::Arm: relative_type = 23; break;
    default: relative_type = 8; break;
  }
  const u64 chunk = 4096;
  std::vector<u8> buf((size_t)(chunk * wsz));
  u64 where = 0;
  for (u64 i = 0; i < n; i += chunk) {
    if (c.cancel && c.cancel->cancelled()) return;
    u64 k = std::min(chunk, n - i);
    if (c.src.read_at(off + i * wsz, buf.data(), (size_t)(k * wsz)) < k * wsz) return;
    for (u64 j = 0; j < k; j++) {
      u64 e = m.is64 ? r.u64_(buf.data() + j * 8) : (u64)r.u32_(buf.data() + j * 4);
      auto emit = [&](u64 at) {
        ElfReloc x;
        x.kind = 4;
        x.table = 0;
        x.offset = at;
        x.type = relative_type;
        x.has_addend = false;
        return sink.push(x);
      };
      if ((e & 1) == 0) {
        if (!emit(e)) return;
        where = e + wsz;
      } else {
        u64 bits = e >> 1;
        for (u64 b = 0; bits; b++, bits >>= 1) {
          if (bits & 1)
            if (!emit(where + b * wsz)) return;
        }
        where += (wsz * 8 - 1) * wsz;
      }
    }
  }
}

}  // namespace

bool elf_parse_relocs(ParseCtx& c, ElfModel& m, bool allow_dynamic_fallback) {
  m.relocs.clear();
  m.reloc_expected = 0;
  RelocSink sink{m, c};
  bool any = false;

  if (m.secs_ok) {
    for (auto& s : m.secs) {
      if (!s.has_file_data() || s.size == 0) continue;
      u8 table = 0;
      if (s.link < m.secs.size() && m.secs[s.link].type == elf::SHT_SYMTAB) table = 1;
      bool plt = s.name.find(".plt") != std::string::npos;
      switch (s.type) {
        case elf::SHT_REL: parse_rel_rela(c, m, sink, s.offset, s.size, false, plt ? 2 : 0, table, s.entsize); any = true; break;
        case elf::SHT_RELA: parse_rel_rela(c, m, sink, s.offset, s.size, true, plt ? 2 : 1, table, s.entsize); any = true; break;
        case elf::SHT_ANDROID_REL: parse_android_packed(c, m, sink, s.offset, s.size, false, table); any = true; break;
        case elf::SHT_ANDROID_RELA: parse_android_packed(c, m, sink, s.offset, s.size, true, table); any = true; break;
        case elf::SHT_RELR:
        case elf::SHT_ANDROID_RELR: parse_relr(c, m, sink, s.offset, s.size); any = true; break;
        default: break;
      }
    }
  }
  if (!any && allow_dynamic_fallback && m.dyn_ok) {
    auto tab = [&](i64 t) -> const ElfDyn* { return dyn_find(m, t); };
    auto loc = [&](const ElfDyn* d, u64& off) { return d && m.vaddr_to_off(d->val, off); };
    u64 off;
    if (loc(tab(elf::DT_REL), off) && tab(elf::DT_RELSZ)) { parse_rel_rela(c, m, sink, off, tab(elf::DT_RELSZ)->val, false, 0, 0, tab(elf::DT_RELENT) ? tab(elf::DT_RELENT)->val : 0); any = true; }
    if (loc(tab(elf::DT_RELA), off) && tab(elf::DT_RELASZ)) { parse_rel_rela(c, m, sink, off, tab(elf::DT_RELASZ)->val, true, 1, 0, tab(elf::DT_RELAENT) ? tab(elf::DT_RELAENT)->val : 0); any = true; }
    if (loc(tab(elf::DT_JMPREL), off) && tab(elf::DT_PLTRELSZ)) {
      bool rela = tab(elf::DT_PLTREL) ? tab(elf::DT_PLTREL)->val == elf::DT_RELA : m.is64;
      parse_rel_rela(c, m, sink, off, tab(elf::DT_PLTRELSZ)->val, rela, 2, 0, 0);
      any = true;
    }
    if (loc(tab(elf::DT_ANDROID_REL), off) && tab(elf::DT_ANDROID_RELSZ)) { parse_android_packed(c, m, sink, off, tab(elf::DT_ANDROID_RELSZ)->val, false, 0); any = true; }
    if (loc(tab(elf::DT_ANDROID_RELA), off) && tab(elf::DT_ANDROID_RELASZ)) { parse_android_packed(c, m, sink, off, tab(elf::DT_ANDROID_RELASZ)->val, true, 0); any = true; }
    if (loc(tab(elf::DT_RELR), off) && tab(elf::DT_RELRSZ)) { parse_relr(c, m, sink, off, tab(elf::DT_RELRSZ)->val); any = true; }
    if (loc(tab(elf::DT_ANDROID_RELR), off) && tab(elf::DT_ANDROID_RELRSZ)) { parse_relr(c, m, sink, off, tab(elf::DT_ANDROID_RELRSZ)->val); any = true; }
    if (any) m.relocs_from_dynamic = true;
  }
  if (sink.overflow) {
    m.relocs_partial = true;
    c.log.log(LogLevel::Warning, "elf", strf("relocation list truncated at %zu entries (memory or object limit)", m.relocs.size()));
  }
  return any;
}

// ---------------------------------------------------------------- notes
bool elf_parse_notes(ParseCtx& c, ElfModel& m, bool allow_segment_fallback) {
  m.notes.clear();
  m.build_id.clear();
  Rd r{m.le};
  auto parse_blob = [&](u64 off, u64 size, u64 align) {
    if (off >= m.file_size) return;
    size = std::min({size, m.file_size - off, (u64)(8u << 20)});
    std::vector<u8> b((size_t)size);
    if (!c.src.read_exact(off, b.data(), b.size())) return;
    size_t p = 0;
    while (p + 12 <= b.size()) {
      u32 nsz = r.u32_(&b[p]), dsz = r.u32_(&b[p + 4]), type = r.u32_(&b[p + 8]);
      p += 12;
      u64 nsz_a = (nsz + align - 1) & ~(align - 1), dsz_a = (dsz + align - 1) & ~(align - 1);
      if (p + nsz_a + dsz_a > b.size() + (align - 1) || p + nsz > b.size() || p + nsz_a + dsz > b.size()) break;
      ElfNote n;
      n.name.assign((const char*)&b[p], nsz ? nsz - 1 : 0);
      n.type = type;
      n.desc.assign(b.begin() + (long)(p + nsz_a), b.begin() + (long)(p + nsz_a + dsz));
      if (n.name == "GNU" && type == 3 && m.build_id.empty()) m.build_id = bytes_hex(n.desc.data(), n.desc.size(), 0);
      m.notes.push_back(std::move(n));
      p += (size_t)(nsz_a + dsz_a);
      if (m.notes.size() > 4096) break;
    }
  };
  bool got = false;
  if (m.secs_ok) {
    for (auto& s : m.secs) {
      if (s.type == elf::SHT_NOTE && s.has_file_data() && s.size) {
        parse_blob(s.offset, s.size, 4);
        got = true;
      }
    }
  }
  if (!got && allow_segment_fallback) {
    for (auto& s : m.segs) {
      if (s.type == elf::PT_NOTE && s.filesz) {
        parse_blob(s.offset, s.filesz, s.align >= 8 ? 8 : 4);
        got = true;
      }
    }
  }
  return got;
}

// ---------------------------------------------------------------- section reading
bool elf_read_section(const ParseCtx& c, const ElfModel& m, const ElfSection& s, std::vector<u8>& out, u64 cap, bool decompress, bool* was_compressed, std::string& err) {
  if (was_compressed) *was_compressed = false;
  if (!s.has_file_data()) {
    err = "section has no file data";
    return false;
  }
  const bool comp = (s.flags & elf::SHF_COMPRESSED) != 0;
  if (!comp || !decompress) {
    if (!c.src.read_vec(s.offset, s.size, out, cap)) {
      err = "section lies outside the file or exceeds the size cap";
      return false;
    }
    return true;
  }
  if (was_compressed) *was_compressed = true;
  const size_t hdr = m.is64 ? 24 : 12;
  if (s.size < hdr) {
    err = "compressed section header is truncated";
    return false;
  }
  u8 h[24];
  if (!c.src.read_exact(s.offset, h, hdr)) {
    err = "cannot read compression header";
    return false;
  }
  Rd r{m.le};
  u32 ch_type = r.u32_(h);
  u64 ch_size = m.is64 ? r.u64_(h + 8) : r.u32_(h + 4);
  if (ch_size > cap) {
    err = strf("decompressed size %llu exceeds the cap", (unsigned long long)ch_size);
    return false;
  }
  std::vector<u8> in;
  if (!c.src.read_vec(s.offset + hdr, s.size - hdr, in, cap)) {
    err = "compressed data cannot be read";
    return false;
  }
  out.assign((size_t)ch_size, 0);
  if (ch_type == 1) {
    uLongf dl = (uLongf)ch_size;
    int rc = uncompress(out.data(), &dl, in.data(), (uLong)in.size());
    if (rc != Z_OK) {
      err = strf("zlib error %d", rc);
      return false;
    }
    out.resize(dl);
    return true;
  }
  if (ch_type == 2) {
    size_t rc = ZSTD_decompress(out.data(), out.size(), in.data(), in.size());
    if (ZSTD_isError(rc)) {
      err = std::string("zstd error: ") + ZSTD_getErrorName(rc);
      return false;
    }
    out.resize(rc);
    return true;
  }
  err = strf("unsupported section compression type %u", ch_type);
  return false;
}

}  // namespace kratos
