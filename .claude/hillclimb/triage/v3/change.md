Haiku 5.5 + report validation loop (--validate)

Week-3 error analysis: all 3 Haiku failures in v1 (3 reps) were bookkeeping errors when copying the tool list (typo in a CVE id, a vulnerability under the wrong package, one omission). v3 checks the final report against this run's check_packages results in code and, if anything is off, sends the problem list back for a corrected report (max 2 rounds). Compare with v1 (same model, same cases, 3 reps).
