// Shared run/library contexts and result types for all analysis stages.
#pragma once

#include "kratos/elf.h"
#include "kratos/io.h"
#include "kratos/json.h"
#include "kratos/log.h"
#include "kratos/settings.h"
#include "kratos/zip.h"

namespace kratos {

// ---------------------------------------------------------------- ledger
struct StageRec {
  std::string id, title;
  StageStatus status = StageStatus::Skipped;
  u64 ms = 0;
  bool mandatory = false;
  std::string reason;                // why skipped/disabled/failed
  std::vector<std::string> notes;    // facts worth showing
  int lib = -1;                      // -1 run level
  int order = 0;                     // creation order, used to sort reports
};

struct FileRec {
  std::string name;      // e.g. "strings.txt"
  std::string rel_path;  // relative to the run directory
  u64 bytes = 0, lines = 0, objects = 0;
  bool truncated = false;
  std::string trunc_reason;
  bool ok = true;
  std::string error;
  int lib = -1;
  bool mandatory = false;
};

struct Gap {
  std::string kind;  // "unavailable" | "skipped" | "inferred" | "partial"
  std::string what;
  std::string why;
  int lib = -1;
};

class Ledger {
 public:
  void add_stage(const StageRec& s);
  void update_stage(const std::string& id, int lib, const std::function<void(StageRec&)>& fn);
  void add_file(const FileRec& f);
  void add_gap(const std::string& kind, const std::string& what, const std::string& why, int lib = -1);
  void add_counter(const std::string& key, u64 v);
  void set_counter(const std::string& key, u64 v);
  u64 counter(const std::string& key) const;
  std::vector<StageRec> stages() const;
  std::vector<FileRec> files() const;
  std::vector<Gap> gaps() const;
  std::map<std::string, u64> counters() const;

 private:
  mutable std::mutex mu_;
  std::vector<StageRec> stages_;
  std::vector<FileRec> files_;
  std::vector<Gap> gaps_;
  std::map<std::string, u64> counters_;
};

// Stage context of the current thread (installed by the executor). Stages use these to report incomplete results.
struct StageScope {
  explicit StageScope(StageRec* s);
  ~StageScope();
  StageScope(const StageScope&) = delete;
  StageScope& operator=(const StageScope&) = delete;
};
void stage_partial(const std::string& why);  // marks the running stage as partially completed and records why
void stage_note(const std::string& note);    // attaches a fact to the running stage

// ---------------------------------------------------------------- result types
struct Indicator {
  std::string id, title, detail;
  std::string strength;  // "weak" | "moderate" | "strong" (strength of the indicator, never proof)
};
struct EntropyRec {
  int seg = -1;
  u64 off = 0, size = 0;
  double entropy = 0;
  u32 flags = 0;
};
struct RelatedRec {
  std::string kind;  // "embedded_elf" | "embedded_dex" | "embedded_zip" | "appended_data" | "protector_name" | "packed_blob"
  std::string where;
  std::string detail;
};
struct ProtectionResult {
  bool ran = false;
  std::vector<Indicator> indicators;
  std::vector<EntropyRec> entropy;
  double file_entropy = 0;
  u64 trailing_bytes = 0;
  std::vector<RelatedRec> related;
};

enum StrEnc : u8 { ENC_ASCII = 0, ENC_UTF8 = 1, ENC_UTF16LE = 2, ENC_UTF16BE = 3 };
struct StringRec {
  u64 off = 0;
  u64 vaddr = 0;
  bool has_vaddr = false;
  int sec = -1;
  u8 enc = 0;
  u32 chars = 0;
  u32 count = 1;
  u32 span = 0;  // bytes covered in the file (UTF-16 only; used to find hits that overlap)
  bool decompressed = false;
  std::string text;
};
struct StringsResult {
  bool ran = false;
  u64 total_found = 0, written = 0, filtered_out = 0, bytes_scanned = 0, ranges = 0;
  u64 by_enc[4] = {0, 0, 0, 0};
  bool truncated = false, memory_partial = false;
  bool streamed = false;
  std::vector<std::pair<u64, u32>> index;  // (file offset, byte length) of ASCII/UTF-8 strings, sorted by offset
  bool index_partial = false;
};

enum FuncSrc : u32 {
  FS_SYMTAB = 1, FS_DYNSYM = 2, FS_INIT = 4, FS_ENTRY = 8, FS_UNWIND = 16, FS_CALL = 32, FS_PROLOGUE = 64, FS_PLT = 128, FS_PTRTAB = 256
};
const char* func_src_names(u32 mask, std::string& out);  // "symtab,unwind"

struct FuncRec {
  u64 vaddr = 0;
  u64 size = 0;
  u32 sources = 0;
  u8 conf = 0;  // 0 low, 1 medium, 2 high
  bool size_known = false, size_est = false, generated = true, thumb = false;
  int sec = -1;
  std::string name, demangled;
  std::string kind;  // "" | "jni" | "cxx" | "plt" | "init"
};
struct MethodRec {
  std::string kind;       // "jni" | "cxx"
  std::string symbol;     // raw symbol
  std::string signature;  // human readable
  u64 vaddr = 0;
};
struct PltStub {
  u64 addr = 0, got = 0;
  std::string name;
  u32 size = 0;
  bool header = false;  // PLT0: the lazy-binding resolver trampoline at the start of .plt, not a call stub of one symbol
};
struct PointerTable {
  u64 vaddr = 0;
  u32 count = 0;
  int sec = -1;
};
struct FunctionsResult {
  bool ran = false;
  std::vector<FuncRec> list;  // sorted by vaddr after finalize
  std::vector<PltStub> plt;
  std::vector<MethodRec> methods;
  std::vector<PointerTable> tables;
  u64 from_symbols = 0, from_unwind = 0, from_init = 0, from_calls = 0, from_prologue = 0, from_plt = 0;
  bool finalized = false;
};

enum XrefType : u8 { XR_CALL = 0, XR_JUMP = 1, XR_PCREL = 2, XR_LITERAL = 3, XR_DATA = 4, XR_STRING = 5 };
const char* xref_type_name(u8 t);
struct XrefRec {
  u64 from = 0, to = 0;
  u8 type = 0;
  bool confirmed = true;
  bool thumb_target = false;
  u32 note = 0;  // 1 = resolved through PLT, 2 = through thunk
};

struct CodeScanResult {
  bool ran = false;
  std::vector<XrefRec> xrefs;
  std::vector<u64> call_targets;  // sorted unique
  std::vector<std::pair<u64, u8>> prologues;  // (vaddr, strength)
  std::vector<PltStub> plt;
  u64 insns = 0, bytes_decoded = 0, bytes_data = 0, bytes_total = 0, regions = 0, undecodable = 0;
  std::map<u64, u64> thunks;  // address of a one-hop stub -> its target (direct jumps and ARM long-branch veneers)
  bool xref_partial = false;
  std::string arch_note;
};

struct CodeRegion {
  u64 vaddr = 0, foff = 0, size = 0;
  int sec = -1;
  std::string name;
};
struct ModeSpan {
  u64 start = 0, end = 0;
  u8 mode = 0;  // 0 = ARM, 1 = Thumb, 2 = data
  u8 conf = 0;  // 0 = guessed, 1 = from symbols, 2 = from mapping symbols
};

struct ElfioCheck {
  bool ran = false, loaded = false;
  std::string error;
  u64 sections = 0, segments = 0, symbols = 0;
  std::vector<std::string> diffs;
};

struct DynamicResult {
  bool ran = false, available = false;
  std::string reason;
  u64 base = 0;   // lowest mapped address of the module
  u64 bias = 0;   // runtime address = vaddr + bias
  u64 maps_matched = 0, loads_consistent = 0, loads_total = 0;
  std::string module_path;
  std::vector<std::string> lines;
};

struct MetaResult {
  bool probed = false, found = false;
  std::string handler;     // "il2cpp"
  std::string name;        // entry name or file name
  std::string status;      // "ok" | "invalid" | "unsupported_version" | "incompatible"
  Json info = Json::object();
  std::vector<std::string> notes;
  u64 size = 0;
  std::string source;      // "auto" | "manual" | "file"
  std::string local_path;  // copy of the metadata file inside the run directory
  std::string rel_path;    // same, relative to the run directory
};

// ---------------------------------------------------------------- range filter
struct RangeFilter {
  bool active = false;
  bool vaddr_space = false;
  u64 lo = 0, hi = ~(u64)0;
  bool ok(const ElfModel& m, u64 file_off) const {
    if (!active) return true;
    if (!vaddr_space) return file_off >= lo && file_off < hi;
    u64 va;
    return m.off_to_vaddr(file_off, va) && va >= lo && va < hi;
  }
  bool ok_va(const ElfModel& m, u64 va) const {
    if (!active) return true;
    if (vaddr_space) return va >= lo && va < hi;
    u64 off;
    return m.vaddr_to_off(va, off) && off >= lo && off < hi;
  }
  // File-offset interval equivalent to the filter for [off, off+len).
  bool clip_file(const ElfModel& m, u64& off, u64& len) const;
};

// ---------------------------------------------------------------- contexts
// Progress callback (stage id, done, total (0 = unknown), text).
using ProgressFn = std::function<void(const std::string&, u64, u64, const std::string&)>;

struct RunRequest {
  std::string mode = "apk";  // "apk" | "lib"
  std::string display_name;
  int apk_fd = -1, lib_fd = -1, meta_fd = -1;
  std::string lib_name, meta_name;
  std::string out_root;
  std::vector<std::string> selected_libs;  // zip entry names (apk mode); empty = automatic if enabled
  std::string selected_meta;               // zip entry name; "" = automatic; "none" = no metadata
  std::string profile_id = "standard";
  std::string temp_dir;                    // writable scratch directory
  Json config = Json::object();
  std::string meta_version_note;
};

struct LibContext {
  int index = 0;
  std::string id;          // stable short id, e.g. "arm64-v8a_libfoo.so"
  std::string entry_name;  // path inside the APK or file name
  std::string display;
  std::string abi_dir;     // ABI by APK directory ("" for standalone)
  std::string local_path;  // local file with the library bytes
  std::string reports_dir; // absolute
  std::string rel_reports; // relative to run dir
  std::shared_ptr<ByteSource> src;
  u64 size = 0;
  std::string sha256, crc32_hex;
  bool from_apk = false;
  bool extracted_ok = false;

  ElfModel elf;
  bool elf_ok = false;
  Arch arch = Arch::Unknown;  // effective architecture used for disassembly
  RangeFilter range;
  bool large_file = false;
  ProtectionResult prot;
  StringsResult strings;
  FunctionsResult funcs;
  CodeScanResult scan;
  ElfioCheck elfio;
  DynamicResult dyn;
  std::vector<CodeRegion> regions;  // executable regions selected for scanning and listing
  std::vector<ModeSpan> spans;      // ARM32 instruction-set spans (sorted); empty for other architectures
  bool spans_ready = false;
  std::vector<std::string> companions;  // readable names
  Json companions_json = Json::array();

  Ledger* ledger = nullptr;  // run ledger (shared)
  std::mutex mu;
};

struct ApkLib {
  std::string entry;     // zip entry name (or "outer!inner" for nested)
  std::string name;      // file name
  std::string abi;
  u64 size = 0;
  bool is_elf = false;
  bool validated = false;
  Arch arch = Arch::Unknown;
  int bits = 0;
  bool le = true;
  bool skipped_by_arch = false;
  std::string note;
  std::string nested;    // name of the nested APK this entry belongs to, if any
  int rank = 0;          // automatic selection order (0 = best)
  bool selected_auto = false;
};

struct MetaCandidate {
  std::string entry;
  std::string name;
  std::string handler;
  u64 size = 0;
  std::string status;
  std::string note;
};

struct ApkScan {
  bool ok = false;
  std::string error;
  u64 entries = 0, dirs = 0, total_uncompressed = 0, total_compressed = 0;
  bool recovered = false, zip64 = false;
  std::vector<std::string> warnings;
  std::vector<ApkLib> libs;
  std::vector<MetaCandidate> metas;
  std::vector<std::string> abis;
  std::map<std::string, std::pair<u64, u64>> top_dirs;  // dir -> (count, uncompressed size)
  std::map<std::string, u64> methods;
  std::vector<std::string> nested_apks;
  bool has_lib_dir = false;
  std::vector<RelatedRec> related;
};

struct RunContext {
  RunRequest req;
  Config cfg;
  Logger* log = nullptr;
  CancelToken* cancel = nullptr;
  std::unique_ptr<MemBudget> mem;
  Ledger ledger;

  std::string run_dir, run_name;
  std::string src_dir, libs_dir, meta_dir, reports_root, logs_dir;
  u64 started_ms = 0;

  // input
  std::shared_ptr<ByteSource> apk_src;
  std::unique_ptr<ZipArchive> zip;
  std::string input_sha256, input_crc32;
  u64 input_size = 0;
  ApkScan apk;
  MetaResult meta;
  std::map<std::string, std::shared_ptr<ZipArchive>> nested_zips;  // nested archives opened during the scan (key: entry name)
  std::vector<std::string> temp_files;                             // scratch files removed at the end of the run

  std::vector<std::unique_ptr<LibContext>> libs;
  std::vector<std::string> warnings, errors;
  std::mutex mu;
  ProgressFn progress;
  void prog(const std::string& stage, u64 done, u64 total, const std::string& text) const {
    if (progress) progress(stage, done, total, text);
  }
  void warn(const std::string& stage, const std::string& msg) {
    log->log(LogLevel::Warning, stage, msg);
    std::lock_guard<std::mutex> g(mu);
    if (warnings.size() < 2000) warnings.push_back(stage + ": " + msg);
  }
  void error(const std::string& stage, const std::string& msg) {
    log->log(LogLevel::Error, stage, msg);
    std::lock_guard<std::mutex> g(mu);
    if (errors.size() < 2000) errors.push_back(stage + ": " + msg);
  }

  bool reproducible() const { return cfg.b("expert.reproducible"); }
  u64 total_output_limit() const { return cfg.limit("limits.max_output_total_mb") * 1048576ull; }
  std::atomic<u64> total_output_bytes{0};
};

OutLimits make_out_limits(const Config& cfg, u64 max_objects);
size_t io_buffer_kb(const Config& cfg);

}  // namespace kratos
