// Robust ELF model and parser (ARM32/ARM64/x86/x86-64 and structure of any other ELF).
// Every stage tolerates missing or damaged tables and records anomalies instead of failing.
#pragma once

#include "kratos/io.h"
#include "kratos/log.h"
#include "kratos/settings.h"

namespace kratos {

enum class Arch { Unknown, Arm64, Arm, X86_64, X86, Other };
const char* arch_name(Arch a);   // "arm64", "arm", "x86_64", "x86", "other", "unknown"
const char* arch_label(Arch a);  // "ARM64 (AArch64)"
const char* abi_for_arch(Arch a);

// ELF constants used across the engine.
namespace elf {
constexpr u32 PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4, PT_SHLIB = 5, PT_PHDR = 6, PT_TLS = 7,
              PT_GNU_EH_FRAME = 0x6474e550, PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552, PT_ARM_EXIDX = 0x70000001;
constexpr u32 PF_X = 1, PF_W = 2, PF_R = 4;
constexpr u32 SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_RELA = 4, SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7,
              SHT_NOBITS = 8, SHT_REL = 9, SHT_DYNSYM = 11, SHT_INIT_ARRAY = 14, SHT_FINI_ARRAY = 15, SHT_PREINIT_ARRAY = 16, SHT_GROUP = 17,
              SHT_RELR = 19, SHT_ANDROID_REL = 0x60000001, SHT_ANDROID_RELA = 0x60000002, SHT_ANDROID_RELR = 0x6fffff00, SHT_GNU_HASH = 0x6ffffff6,
              SHT_GNU_VERSYM = 0x6fffffff, SHT_ARM_EXIDX = 0x70000001, SHT_ARM_ATTRIBUTES = 0x70000003;
constexpr u64 SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4, SHF_MERGE = 0x10, SHF_STRINGS = 0x20, SHF_COMPRESSED = 0x800;
constexpr i64 DT_NULL = 0, DT_NEEDED = 1, DT_PLTRELSZ = 2, DT_PLTGOT = 3, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6, DT_RELA = 7, DT_RELASZ = 8,
              DT_RELAENT = 9, DT_STRSZ = 10, DT_SYMENT = 11, DT_INIT = 12, DT_FINI = 13, DT_SONAME = 14, DT_RPATH = 15, DT_REL = 17, DT_RELSZ = 18,
              DT_RELENT = 19, DT_PLTREL = 20, DT_JMPREL = 23, DT_INIT_ARRAY = 25, DT_FINI_ARRAY = 26, DT_INIT_ARRAYSZ = 27, DT_FINI_ARRAYSZ = 28,
              DT_RUNPATH = 29, DT_PREINIT_ARRAY = 32, DT_PREINIT_ARRAYSZ = 33, DT_RELRSZ = 35, DT_RELR = 36, DT_RELRENT = 37,
              DT_ANDROID_REL = 0x6000000f, DT_ANDROID_RELSZ = 0x60000010, DT_ANDROID_RELA = 0x60000011, DT_ANDROID_RELASZ = 0x60000012,
              DT_ANDROID_RELR = 0x6fffe000, DT_ANDROID_RELRSZ = 0x6fffe001, DT_ANDROID_RELRENT = 0x6fffe003, DT_GNU_HASH = 0x6ffffef5;
constexpr u8 STT_NOTYPE = 0, STT_OBJECT = 1, STT_FUNC = 2, STT_SECTION = 3, STT_FILE = 4, STT_COMMON = 5, STT_TLS = 6, STT_GNU_IFUNC = 10;
constexpr u8 STB_LOCAL = 0, STB_GLOBAL = 1, STB_WEAK = 2;
constexpr u16 SHN_UNDEF = 0, SHN_ABS = 0xfff1, SHN_COMMON = 0xfff2, SHN_LORESERVE = 0xff00;
}  // namespace elf

struct ElfSegment {
  int index = 0;
  u32 type = 0, flags = 0;
  u64 offset = 0, vaddr = 0, paddr = 0, filesz = 0, memsz = 0, align = 0;
  bool synthetic = false;  // reconstructed, not read from the file
};

struct ElfSection {
  int index = 0;
  std::string name;
  u32 type = 0;
  u64 flags = 0, addr = 0, offset = 0, size = 0;
  u32 link = 0, info = 0;
  u64 addralign = 0, entsize = 0;
  bool synthetic = false;  // pseudo section built from segments
  bool exec() const { return (flags & elf::SHF_EXECINSTR) != 0; }
  bool alloc() const { return (flags & elf::SHF_ALLOC) != 0; }
  bool has_file_data() const { return type != elf::SHT_NOBITS && type != elf::SHT_NULL; }
};

struct ElfSymbol {
  u32 index = 0;
  std::string name;
  u64 value = 0, size = 0;
  u8 info = 0, other = 0;
  u16 shndx = 0;
  bool dynamic = false;
  u8 type() const { return info & 0xf; }
  u8 bind() const { return info >> 4; }
  u8 visibility() const { return other & 3; }
  bool undefined() const { return shndx == elf::SHN_UNDEF; }
};

struct ElfReloc {
  u64 offset = 0;
  i64 addend = 0;
  u32 type = 0;
  u32 sym = 0;
  bool has_addend = false;
  u8 kind = 0;      // 0 REL, 1 RELA, 2 PLT (JMPREL), 3 Android packed, 4 RELR
  u8 table = 0;     // 0 .dynsym, 1 .symtab
};

struct ElfDyn {
  i64 tag = 0;
  u64 val = 0;
};

struct ElfNote {
  std::string name;
  u32 type = 0;
  std::vector<u8> desc;
};

struct Anomaly {
  u64 offset = 0;
  std::string where;
  std::string text;
};

struct ElfModel {
  // ---- header ----
  std::string ident_note;  // set when the class or byte order was inferred from the header fields instead of e_ident
  bool header_ok = false;
  bool is64 = false, le = true;
  u8 osabi = 0, abiversion = 0;
  u16 type = 0, machine = 0;
  u32 version = 0, flags = 0;
  u64 entry = 0, phoff = 0, shoff = 0;
  u16 ehsize = 0, phentsize = 0, phnum = 0, shentsize = 0, shnum = 0, shstrndx = 0;
  Arch arch = Arch::Unknown;
  u64 file_size = 0;

  // ---- tables ----
  std::vector<ElfSegment> segs;
  std::vector<ElfSection> secs;
  std::vector<ElfDyn> dyn;
  std::vector<ElfSymbol> dynsym, symtab;
  std::vector<ElfReloc> relocs;
  std::vector<std::string> needed;
  std::string soname, runpath, rpath;
  std::vector<ElfNote> notes;
  std::string build_id;
  std::vector<Anomaly> anomalies;

  // ---- parse state ----
  bool segs_ok = false, secs_ok = false, dyn_ok = false;
  bool phdr_assumed = false;       // phoff taken from the standard position
  bool secs_reconstructed = false;  // pseudo sections built from segments
  bool dyn_from_segment = false;    // dynamic table read through PT_DYNAMIC
  bool dynsym_from_dynamic = false;
  bool relocs_from_dynamic = false;
  bool symbols_partial = false, relocs_partial = false;
  u64 dynsym_declared = 0, symtab_declared = 0;
  u64 reloc_expected = 0;
  u64 reparsed_extra_symbols = 0;
  u64 dynsym_off = 0, dynsym_ent = 0, dynstr_off = 0, dynstr_size = 0;  // location of the dynamic symbol table in the file

  // ---- derived ----
  u64 min_load_vaddr = 0, max_load_vaddr = 0;
  u64 load_base_rel = 0;  // page-aligned minimum load address; RVA = vaddr - load_base_rel
  bool has_loads() const;

  const ElfSegment* seg_for_vaddr(u64 va) const;
  const ElfSegment* seg_for_offset(u64 off) const;
  bool vaddr_to_off(u64 va, u64& off) const;
  bool off_to_vaddr(u64 off, u64& va) const;
  bool is_exec_vaddr(u64 va) const;
  int section_for_vaddr(u64 va) const;
  int section_for_offset(u64 off) const;
  const ElfSection* section_by_name(const std::string& n) const;
  const ElfSection* section_by_type(u32 t) const;
  u64 rva(u64 vaddr) const { return vaddr - load_base_rel; }
  u64 ptr_size() const { return is64 ? 8 : 4; }
  const ElfSymbol* find_dynsym(const std::string& name) const;
  void finish_derived();
};

struct ParseCtx {
  const ByteSource& src;
  const Config& cfg;
  Logger& log;
  MemBudget& mem;
  const CancelToken* cancel = nullptr;
  bool diagnostics = false;
  void note(ElfModel& m, u64 off, const char* where, const std::string& text) const;
};

// Class and byte order of an ELF header whose e_ident bytes may be damaged. When the declared values are valid but the header fields
// only make sense with others (or the declared values are invalid), the best fit is chosen and described in the notes.
struct IdentGuess {
  bool valid = false;      // a usable class and byte order were found
  bool is64 = false;
  bool le = true;
  bool class_inferred = false, order_inferred = false;
  std::string class_note, order_note;
};
// h holds the first n bytes of the file (n >= 24); file_size is used to check table offsets (pass UINT64_MAX when unknown).
IdentGuess elf_guess_ident(const u8* h, size_t n, u64 file_size);

// Individual parse stages. Each returns false only when nothing useful could be read.
bool elf_parse_header(ParseCtx& c, ElfModel& m, std::string& err);
bool elf_parse_segments(ParseCtx& c, ElfModel& m, bool allow_assume);
bool elf_parse_sections(ParseCtx& c, ElfModel& m);
bool elf_parse_dynamic(ParseCtx& c, ElfModel& m, bool allow_segment_fallback);
bool elf_parse_symbols(ParseCtx& c, ElfModel& m, bool allow_dynamic_fallback);
bool elf_parse_relocs(ParseCtx& c, ElfModel& m, bool allow_dynamic_fallback);
bool elf_parse_notes(ParseCtx& c, ElfModel& m, bool allow_segment_fallback);
// Builds pseudo sections from segments when no section table is usable.
void elf_reconstruct_sections(ParseCtx& c, ElfModel& m);
// Extends the dynamic symbol table when relocations reference indices beyond it. Returns added count.
u64 elf_reparse_symbols_from_relocs(ParseCtx& c, ElfModel& m);

// Reads the bytes of a section (decompressing SHF_COMPRESSED when allowed). cap protects memory.
bool elf_read_section(const ParseCtx& c, const ElfModel& m, const ElfSection& s, std::vector<u8>& out, u64 cap, bool decompress, bool* was_compressed,
                      std::string& err);

// Names and descriptions.
std::string reloc_type_name(const ElfModel& m, u32 type);
bool reloc_is_relative(const ElfModel& m, u32 type);
bool reloc_is_jump_slot(const ElfModel& m, u32 type);
bool reloc_is_glob_dat(const ElfModel& m, u32 type);
bool reloc_is_abs(const ElfModel& m, u32 type);
const char* seg_type_name(u32 t);
const char* sec_type_name(u32 t);
std::string seg_flags_str(u32 f);
std::string sec_flags_str(u64 f);
const char* sym_type_name(u8 t);
const char* sym_bind_name(u8 b);
const char* sym_vis_name(u8 v);
const char* elf_type_name(u16 t);
const char* machine_name(u16 m);
const char* dyn_tag_name(i64 t);
std::string sym_shndx_name(const ElfModel& m, u16 shndx);

}  // namespace kratos
