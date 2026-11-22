# 진단 보고서 추출 평가

| 방법 | 양식 | 문서 | pair recall | pair precision | finding recall | distractor FP | 완전 일치 | 문서당 비용 | 문서당 시간 |
|---|---|---|---|---|---|---|---|---|---|
| deterministic | docx_prose | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0000 | 0.02s |
| deterministic | pdf_grouped | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0000 | 0.28s |
| deterministic | pdf_scan | 10 | 0.000 | 0.000 | 0.000 | 0 | 0/10 | $0.0000 | 0.00s |
| deterministic | pdf_table | 10 | 0.995 | 1.000 | 1.000 | 0 | 9/10 | $0.0000 | 4.45s |
| deterministic | xlsx | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0000 | 0.01s |
| deterministic | (전체) | 50 | 0.799 | 1.000 | 0.800 | 0 | 39/50 | $0.0000 | 0.95s |
| llm:claude-haiku-5-5 | pdf_scan | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0006 | 3.72s |
| llm:claude-haiku-5-5 | docx_prose | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0004 | 3.11s |
| llm:claude-haiku-5-5 | pdf_grouped | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0005 | 2.37s |
| llm:claude-haiku-5-5 | pdf_table | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0006 | 2.92s |
| llm:claude-haiku-5-5 | xlsx | 10 | 1.000 | 1.000 | 1.000 | 0 | 10/10 | $0.0004 | 3.23s |
| llm:claude-haiku-5-5 | (전체) | 50 | 1.000 | 1.000 | 1.000 | 0 | 50/50 | $0.0005 | 3.07s |
