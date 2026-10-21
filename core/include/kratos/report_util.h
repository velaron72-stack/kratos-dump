// Helpers shared by all report writers: toggles, limits, headers, ledger bookkeeping.
#pragma once

#include "kratos/analysis.h"

namespace kratos {

struct AddrCols {
  bool foff = true, va = true, rva = true;
  static AddrCols from(const Config& c);
  std::string header() const;
  // Formats the enabled address columns; unknown values print as "-".
  std::string fmt(const ElfModel& m, bool has_off, u64 off, bool has_va, u64 va) const;
};

class ReportFile {
 public:
  // dir: absolute directory, rel_dir: path relative to the run directory (for the ledger).
  ReportFile(RunContext& rc, int lib, const std::string& name, const std::string& dir, const std::string& rel_dir, u64 max_objects, const char* comment = "# ");
  ~ReportFile();
  bool ok() const { return out_ && out_->ok(); }
  OutFile& f() { return *out_; }
  // Writes the standard header comment (omits time and paths in reproducible mode).
  void header(const std::string& title, const LibContext* lc);
  // Closes the file and records it in the ledger. Returns false on I/O error.
  bool finish(bool mandatory = false);
  const std::string& name() const { return name_; }
  const std::string& path() const { return path_; }
  const std::string& create_error() const { return create_err_; }
  void abandon();  // removes the file and records nothing

 private:
  RunContext& rc_;
  int lib_;
  std::string name_, path_, rel_, create_err_, cp_;
  std::unique_ptr<OutFile> out_;
  bool finished_ = false;
};

// True when the report toggle is on. Records a "disabled" gap-free no-op otherwise.
bool report_wanted(const RunContext& rc, const char* key);
// Records that an enabled report could not be produced (no handler/data).
void report_unavailable(RunContext& rc, int lib, const std::string& name, const std::string& why);
void report_skipped(RunContext& rc, int lib, const std::string& name, const std::string& why);
// Records a failed optional report.
void report_failed(RunContext& rc, int lib, const std::string& name, const std::string& err, bool mandatory = false);

// Creates a report file for a library with the standard header. Returns nullptr (and records the failure) when it cannot be created.
std::unique_ptr<ReportFile> open_report(RunContext& rc, LibContext& lc, const char* name, const std::string& title, u64 max_objects,
                                         const char* comment = "# ");
// Closes a report started with open_report, noting limit truncation in the stage record.
bool close_report(RunContext& rc, ReportFile& rf, bool mandatory = false);

std::string json_str_list(const std::vector<std::string>& v);
bool write_text_retry(RunContext& rc, const std::string& path, const std::string& text, std::string& err);

}  // namespace kratos
