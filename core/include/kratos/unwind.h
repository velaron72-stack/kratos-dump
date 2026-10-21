// Function boundaries from unwind tables (.eh_frame / .eh_frame_hdr and ARM .ARM.exidx).
#pragma once

#include "kratos/analysis.h"

namespace kratos {

struct UnwindFunc {
  u64 start = 0;
  u64 size = 0;       // 0 = unknown
  bool exact = true;  // size comes from the table itself (FDE) rather than an estimate
};

struct UnwindResult {
  std::vector<UnwindFunc> funcs;
  bool eh_frame_found = false, exidx_found = false;
  u64 fde_count = 0, cie_count = 0, exidx_entries = 0;
  u64 skipped_entries = 0;  // damaged or unsupported entries
  bool partial = false;
  std::string source;       // where the tables were found
};

// Reads whatever unwind tables exist. Uses sections when present, program headers otherwise.
UnwindResult read_unwind_tables(RunContext& rc, LibContext& lc);

}  // namespace kratos
