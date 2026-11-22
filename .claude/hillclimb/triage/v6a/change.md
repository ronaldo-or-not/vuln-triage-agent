Haiku 5.5 + v5 (--validate --tool-hints) + CWE arm "memory" (--cwe memory)

Week 8 question: does connecting the CWE knowledge base (week 4 retriever, security-kb MCP server) to the agent make its weakness types and workarounds better? Three arms share the v5 harness, the same report schema (+ `cwe` per vulnerability, + `workaround` per package) and the same instructions; they differ only in where CWE information comes from:

- v6a memory: no CWE data. get_vulnerability's CWE fields are hidden (VULNAGENT_CWE_MODE=hidden), no security-kb tools. The model picks CWE ids and mitigations from its own knowledge.
- v6b labels: check_packages attaches the GHSA/NVD labels (`cwes`, with names from the CWE catalog). security-kb get_weakness (and search_weaknesses as a fallback for unlabeled vulnerabilities) are attached as a second MCP server.
- v6c search: labels hidden; security-kb search_weaknesses_many (batched BM25 + observed examples) and get_weakness attached. The agent must pick each CWE from search candidates.

Free pre-check (eval/cwe/retrieval_check.json): GHSA or NVD already labels 456 of 466 unique vulnerabilities. With the one-line OSV summary the agent sees, BM25 puts a label at rank 1 for 27% and in the top 5 for 45% — the ceiling for v6c if it only picks from candidates.

Graded in code (eval/cwe_grade.py): CWE accuracy vs GHSA ∪ NVD labels, ids exist in the catalog, grounding by trace, workaround present / cites a labeled CWE / cites a CWE fetched with get_weakness for the 14 packages an upgrade cannot fully fix. Same runs are re-graded with grade.py and prose_grade.py for regression. 16 cases with vulnerabilities × 1 rep per arm.

Expected: v6b near 100% (it copies labels), v6c at most ~45%, v6a unknown — if memory beats retrieval, report that. Workaround grounding only possible in v6b/v6c.
