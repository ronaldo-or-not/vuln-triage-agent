v5 agent runs (tool-computed counts) re-graded for prose accuracy

Same grader version as baseline (baseline = triage/v4 runs re-graded). The agent change is described in .claude/hillclimb/triage/v5/change.md: check_packages returns `counts` and per-package `vulnerability_count`, the input carries dependency/unchecked counts, and the prompt says to copy every number from these fields. The grader counts from `results` itself and never reads `counts`.
