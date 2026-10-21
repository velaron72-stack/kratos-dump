// Run executor: builds the stage graph for one request, runs it, and writes the result directory.
#pragma once

#include "kratos/analysis.h"

namespace kratos {

struct RunOutcome {
  std::string status_id;    // "success" | "error" | "cancelled" | "not_started"
  std::string status_text;  // "Успешно завершено" | "Завершено с ошибкой" | "Отменено пользователем" | "Не запущено"
  std::string run_dir;      // absolute path; empty when the run did not start
  std::string summary_path; // absolute path of summary.json (empty when it was not written)
  std::string error;        // reason, when the run did not start
  Json summary;             // content of summary.json (null when the run did not start)
};

// Runs one analysis. Never throws. The cancel token may be triggered from another thread at any time.
// progress: (stage id, done, total, text); log_cb: receives every log entry (console).
RunOutcome run_analysis(const RunRequest& req, CancelToken& cancel, ProgressFn progress, Logger::Callback log_cb);

}  // namespace kratos
