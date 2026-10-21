#include "kratos/report_util.h"

#include <chrono>
#include <thread>

namespace kratos {

AddrCols AddrCols::from(const Config& c) {
  AddrCols a;
  a.foff = c.flag("out.addr_columns", "file_offset");
  a.va = c.flag("out.addr_columns", "vaddr");
  a.rva = c.flag("out.addr_columns", "rva");
  return a;
}

std::string AddrCols::header() const {
  std::string s;
  if (foff) s += strf("%-10s ", "file_off");
  if (va) s += strf("%-10s ", "vaddr");
  if (rva) s += strf("%-10s ", "rva");
  return s;
}

std::string AddrCols::fmt(const ElfModel& m, bool has_off, u64 off, bool has_va, u64 va) const {
  std::string s;
  if (foff) s += has_off ? strf("0x%08llx ", (unsigned long long)off) : strf("%-10s ", "-");
  if (va) s += has_va ? strf("0x%08llx ", (unsigned long long)va) : strf("%-10s ", "-");
  if (rva) s += has_va ? strf("0x%08llx ", (unsigned long long)m.rva(va)) : strf("%-10s ", "-");
  return s;
}

ReportFile::ReportFile(RunContext& rc, int lib, const std::string& name, const std::string& dir, const std::string& rel_dir, u64 max_objects, const char* comment)
    : rc_(rc), lib_(lib), name_(name), cp_(comment) {
  path_ = path_join(dir, name);
  rel_ = path_join(rel_dir, name);
  OutLimits lim = make_out_limits(rc.cfg, max_objects);
  u64 total = rc.total_output_limit();
  if (total) {
    u64 used = rc.total_output_bytes.load();
    u64 rem = used >= total ? 1 : total - used;
    lim.max_bytes = lim.max_bytes ? std::min(lim.max_bytes, rem) : rem;
  }
  int retries = (int)rc.cfg.i("general.retry_count");
  for (int attempt = 0;; attempt++) {
    // Names inside a fresh run directory never collide; a leftover file means a repeated write: replace it.
    if (path_exists(path_)) remove_file(path_);
    out_.reset(new OutFile(path_, io_buffer_kb(rc.cfg), lim, cp_));
    if (out_->ok()) break;
    create_err_ = out_->io_error_text();
    if (attempt >= retries) break;
    rc.log->log(LogLevel::Warning, "report", strf("cannot create %s (%s); retry %d/%d", name.c_str(), create_err_.c_str(), attempt + 1, retries));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!out_->ok()) create_err_ = out_->io_error_text();
}

ReportFile::~ReportFile() {
  if (!finished_ && out_) out_->close();
}

void ReportFile::header(const std::string& title, const LibContext* lc) {
  if (!ok()) return;
  out_->line(cp_ + "KRATOS DUMP " + KRATOS_VERSION + " - " + title);
  if (lc) out_->line(cp_ + "library: " + lc->display);
  if (!rc_.reproducible()) out_->line(cp_ + "generated: " + iso_time_utc(now_ms()));
  out_->line(cp_ + "profile: " + rc_.req.profile_id);
  out_->line("");
}

bool ReportFile::finish(bool mandatory) {
  finished_ = true;
  FileRec fr;
  fr.name = name_;
  fr.rel_path = rel_;
  fr.lib = lib_;
  fr.mandatory = mandatory;
  if (!out_) {
    fr.ok = false;
    fr.error = create_err_;
    rc_.ledger.add_file(fr);
    return false;
  }
  bool ok = out_->close() && !out_->io_error();
  fr.bytes = out_->bytes();
  fr.lines = out_->lines();
  fr.objects = out_->objects();
  fr.truncated = out_->truncated();
  fr.trunc_reason = out_->truncation_reason();
  fr.ok = ok;
  if (!ok) {
    fr.error = out_->io_error_text().empty() ? create_err_ : out_->io_error_text();
    rc_.error("report", strf("%s: %s", name_.c_str(), fr.error.c_str()));
    // A file cut short by a write error is not a correctly created result: it is removed and the failure is recorded.
    // (out.partial_results decides what happens to the whole run directory, see the end of the run.)
    remove_file(path_);
    fr.error += " (неполный файл удалён)";
  } else {
    rc_.total_output_bytes += fr.bytes;
    if (fr.truncated) rc_.warn("report", strf("%s truncated: %s", name_.c_str(), fr.trunc_reason.c_str()));
  }
  rc_.ledger.add_file(fr);
  return ok;
}

void ReportFile::abandon() {
  finished_ = true;
  if (out_) {
    out_->close();
    remove_file(path_);
  }
}

bool report_wanted(const RunContext& rc, const char* key) { return rc.cfg.b(key); }

void report_unavailable(RunContext& rc, int lib, const std::string& name, const std::string& why) {
  rc.ledger.add_gap("unavailable", name, why, lib);
  rc.log->log(LogLevel::Warning, "report", name + " not created: " + why);
}
void report_skipped(RunContext& rc, int lib, const std::string& name, const std::string& why) {
  rc.ledger.add_gap("skipped", name, why, lib);
  rc.log->log(LogLevel::Info, "report", name + " skipped: " + why);
}
void report_failed(RunContext& rc, int lib, const std::string& name, const std::string& err, bool mandatory) {
  FileRec fr;
  fr.name = name;
  fr.lib = lib;
  fr.ok = false;
  fr.error = err;
  fr.mandatory = mandatory;
  rc.ledger.add_file(fr);
  rc.error("report", name + ": " + err);
}

std::unique_ptr<ReportFile> open_report(RunContext& rc, LibContext& lc, const char* name, const std::string& title, u64 max_objects, const char* comment) {
  std::unique_ptr<ReportFile> rf(new ReportFile(rc, lc.index, name, lc.reports_dir, lc.rel_reports, max_objects, comment));
  if (!rf->ok()) {
    report_failed(rc, lc.index, name, rf->create_error());
    stage_partial(std::string(name) + " could not be created");
    return nullptr;
  }
  rf->header(title, &lc);
  return rf;
}

bool close_report(RunContext& rc, ReportFile& rf, bool mandatory) {
  bool trunc = rf.f().truncated();
  std::string reason = rf.f().truncation_reason();
  bool ok = rf.finish(mandatory);
  if (!ok) stage_partial(rf.name() + " write error");
  else if (trunc) stage_partial(rf.name() + " cut by limit");
  (void)rc;
  (void)reason;
  return ok;
}

std::string json_str_list(const std::vector<std::string>& v) {
  Json a = Json::array();
  for (auto& s : v) a.push(Json(s));
  return a.dump();
}

bool write_text_retry(RunContext& rc, const std::string& path, const std::string& text, std::string& err) {
  int retries = (int)rc.cfg.i("general.retry_count");
  for (int attempt = 0;; attempt++) {
    if (write_text_file(path, text, err)) return true;
    if (attempt >= retries) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

}  // namespace kratos
