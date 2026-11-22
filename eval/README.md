# 트리아지 에이전트 평가 (v0)

## 무엇을 재나

에이전트가 **도구가 준 사실을 빠짐없이, 지어내지 않고, 정책대로 정리하는가**. 정답은 "도구 결과를 완벽하게
정리한 보고서"이고, 1주차 DB에서 코드로 계산한다 (사람이나 모델이 쓴 정답이 아님).

| 지표 | 뜻 | pass에 포함 |
|---|---|---|
| `pass` | 아래 필수 조건을 모두 만족 (헤드라인) | - |
| `recall` | 정답 취약점 중 보고서에 나온 비율 (GHSA 등 별칭도 인정) | 1.0이어야 |
| `no_halluc` | 도구 결과에 없는 ID를 쓰지 않음 | O |
| `kev_order` | KEV 등재 취약점이 모두 비등재보다 위 | O |
| `kev_facts` | 보고한 kev 표기가 실제와 일치 | O |
| `upgrade_ok` | 추천 버전을 각 취약점의 OSV 범위에 다시 넣어 하나도 걸리지 않는 패키지 비율 (다운그레이드 불가) | 1.0이어야 |
| `unchecked_ok` | 파서가 넘긴 검사 불가 항목을 모두 보고 | O |
| `order_tau` | 정책 순서(KEV→EPSS)와 순위의 켄달 타우 | 참고용 |

해당 사항이 없는 케이스(예: KEV가 없음)는 그 지표를 1로 둔다.

일부러 넣지 않은 것
- 설명 품질(한국어 요약이 유용한가): LLM 판정이 필요해서 3주차 이후로 미룸
- 업그레이드 최소성(더 낮은 안전 버전이 있었나): 안전성과 별개라 지금은 재지 않음
- 배포 맥락(외부 노출 등)에 따른 우선순위 조정: 정답을 코드로 정할 수 없음

## 케이스 (20개)

공개 저장소(OWASP 실습 앱, Snyk goof 등)의 실제 의존성 파일을 커밋 고정으로 가져왔다 (`cases.json`, `fetch_cases.py`).
npm 6 · PyPI 7 · Maven/Gradle 7. 정답 0건 케이스 4개 (깨끗한 파일, 전부 검사 불가 2개, 전이 의존성 사각지대).
전체 입력과 정답 요약은 [inputs.md](inputs.md).

## 재현성

- KEV/EPSS 스냅샷 2026-11-20 고정 (`pinned`), 에이전트의 MCP 서버는 `VULNAGENT_OFFLINE=1`, `VULNAGENT_AS_OF=2026-11-20`
- OSV·NVD는 미리 채운 캐시만 사용 (`build_gold.py`, `warm_nvd.py`)

## 실행

```bash
python eval/run_eval.py --fake oracle      # 정답 보고서: 100%여야 정상
python eval/run_eval.py --fake null        # 빈 보고서: 5% (깨끗한 파일 1개만 통과)
python eval/run_eval.py --variant baseline --reps 2   # 실제 실행 (유료, 하네스 승인 필요)
```

결과는 `.claude/hillclimb/triage/<variant>/` (results.jsonl, traces/, errors.jsonl).
요청한 모델이 아닌 모델이 응답(fallback 포함)했거나 시간 초과·API 오류가 나면 점수에 섞지 않고 errors.jsonl에 기록한다.

## 잡음 수준

pass율의 95% 신뢰구간 반폭은 대략 `1/sqrt(케이스 × 반복)`: 20×1 ≈ ±22%p, 20×2 ≈ ±16%p, 20×3 ≈ ±13%p.
이보다 작은 차이는 버전 간 개선으로 볼 수 없다.
