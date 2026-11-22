| 실험군 | CWE 정답률 (95% CI) | 케이스 평균 | 채움 | 카탈로그에 있음 | 도구 근거 | 완화책 작성 | 완화책 CWE 맞음 | 완화책 KB 근거 | 구조화 pass | 서술 prose_ok | 비용/실행 | 지연 중앙값 | 도구 호출 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pilot-cwe-memory 기억만 | 74% (61/83, 63%–82%) | 66% | 99% | 100% | 0% | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | $0.0068 | 32.675s | 1 |
| pilot-cwe-labels 라벨 전달 | 100% (83/83, 96%–100%) | 100% | 99% | 100% | 100% | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | $0.0076 | 34.525000000000006s | 2.5 |
| pilot-cwe-search 검색 | 64% (53/83, 53%–73%) | 61% | 87% | 100% | 100% | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | $0.0116 | 50.935s | 3 |

짝지은 비교 (같은 케이스·취약점):

- pilot-cwe-memory vs pilot-cwe-labels: n 83, both_right 61, only_pilot-cwe-memory 0, only_pilot-cwe-labels 22, both_wrong 0
- pilot-cwe-memory vs pilot-cwe-search: n 83, both_right 51, only_pilot-cwe-memory 10, only_pilot-cwe-search 2, both_wrong 20
- pilot-cwe-labels vs pilot-cwe-search: n 83, both_right 53, only_pilot-cwe-labels 30, only_pilot-cwe-search 0, both_wrong 0
- pilot-cwe-search 검색 분해 (검색한 취약점 83개): 후보 5개 안에 정답 52/83, 검색 1위가 정답 38, 후보 1위를 고름 51, 후보 중에서 고름 69, 비움 10 | 정답: 후보에서 50, 후보 밖(기억) 3 | 오답: 정답이 후보에 있었는데 다른 것 2, 후보에 정답 없음 28
