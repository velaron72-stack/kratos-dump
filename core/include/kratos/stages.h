// Stage entry points. Each stage reads from the contexts and records its results there.
#pragma once

#include "kratos/analysis.h"

namespace kratos {

// apk.cpp
bool stage_apk_scan(RunContext& rc);                      // inspects the archive, lists libraries/metadata/companions
bool stage_select_extract(RunContext& rc);                // chooses libraries and writes them to disk
bool stage_lib_input(RunContext& rc, LibContext& lc);     // size and checksums of a library file
bool hash_source(const ByteSource& src, bool want_sha, bool want_crc, const CancelToken* cancel, std::string& sha_hex, std::string& crc_hex);
ApkScan inspect_apk_only(int fd, const std::string& name, const Config& cfg, Logger& log, CancelToken* cancel, std::string& err, const std::string& temp_dir = "");
// Quick content checks used by the UI before a run (they never touch the run directory).
ApkLib probe_library_source(const ByteSource& src, const std::string& name);
Json probe_metadata_source(const ByteSource& src, const std::string& name);

// elf stage (elf_stage.cpp)
bool stage_elf(RunContext& rc, LibContext& lc);           // header, segments, sections, dynamic, symbols, relocs, notes
bool stage_elfio_check(RunContext& rc, LibContext& lc);

// protect.cpp
bool stage_protection(RunContext& rc, LibContext& lc);

// strings.cpp
bool stage_strings(RunContext& rc, LibContext& lc);

// functions.cpp
bool stage_functions_static(RunContext& rc, LibContext& lc);   // symbols, init, entry, unwind, PLT synthetic
bool stage_functions_final(RunContext& rc, LibContext& lc);    // merges scan results, bounds, names, methods
bool stage_codescan(RunContext& rc, LibContext& lc);           // linear sweep: call targets, prologues, xrefs, PLT stubs
bool stage_unknown_structures(RunContext& rc, LibContext& lc); // pointer tables in data segments

// reports
bool stage_report_structure(RunContext& rc, LibContext& lc);   // sections, segments, relocations, imports, exports
bool stage_report_functions(RunContext& rc, LibContext& lc);   // functions.txt, methods.txt, offsets.h
bool stage_report_disasm(RunContext& rc, LibContext& lc);      // disassembly.txt
bool stage_report_xrefs(RunContext& rc, LibContext& lc);       // cross_references.txt
bool stage_report_hex(RunContext& rc, LibContext& lc);         // hex_dump.txt

// metadata.cpp
bool stage_metadata(RunContext& rc);
bool stage_metadata_report(RunContext& rc);  // run level: reports/metadata_report.txt (includes per-library compatibility notes)

// dynamic.cpp
bool stage_dynamic(RunContext& rc, LibContext& lc);

// final reports (run level; written after all analysis stages)
bool stage_report_dump(RunContext& rc);          // reports/dump.txt
bool stage_report_completeness(RunContext& rc);  // reports/completeness.txt

// Final status of the run computed from the ledger. Used by dump.txt, completeness.txt and summary.json.
struct StatusInfo {
  std::string id;    // "success" | "error" | "cancelled"
  std::string text;  // Russian status text
  std::vector<std::string> mandatory_failed, optional_failed;
};
StatusInfo compute_status(RunContext& rc);
Json build_summary(RunContext& rc, const StatusInfo& st);

}  // namespace kratos
