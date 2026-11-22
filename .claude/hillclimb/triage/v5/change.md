Haiku 5.5 + v4 + tool-computed counts for the prose (--validate --tool-hints)

Week-7 prose eval (triage-prose) found 21/60 v4 summaries with wrong counts ("12 packages, 20 vulns" vs 8 and 19), concentrated in cases where several vulnerable packages must be added up by hand. Same remedy as v4's safe_upgrade/policy_rank: counting is computation, not judgment.

The one change: with --tool-hints, check_packages also returns top-level `counts` (packages_checked, vulnerable_packages, no_known_vulns_packages, not_checked_packages, vulnerabilities, unique_vulnerabilities, kev_listed) and `vulnerability_count` per vulnerable package; the user message carries `counts` for dependencies / unchecked / total entries; HINTS_ADDENDUM and the MCP tool description tell the model to copy numbers from these and never count by hand. The prose grader still counts from `results` itself and never reads `counts`.

Confounds vs v4 (noted, not intended as changes): v4 ran before the DB session time zone was pinned to UTC (kev_released now prints +00:00 in tool output) and before the run log module existed (CLI only, not used by the eval runner). Gold changed only in kev_released format. If the prose gain is inside the noise (~±13pp at n=60), rerun a v4 control.

Expected: triage-prose counts_ok up from 39/60; structured pass stays 60/60; cost/latency no worse. Check that the gain is not from omission (count claims per summary v4 vs v5) and read ~10 passing summaries from formerly failing cases by eye (grader still misses ~45% of wrong-target errors).
