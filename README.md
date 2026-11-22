# vuln-triage-agent

[![ci](https://github.com/ronaldo-or-not/vuln-triage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/ronaldo-or-not/vuln-triage-agent/actions/workflows/ci.yml)

의존성 파일이나 보안 진단 보고서를 받아 **"무엇을, 어떤 순서로, 몇 버전으로 고쳐야 하는지"** 보고서를 쓰는 LLM 에이전트.
에이전트 자체보다 **평가로 개선을 증명하는 것**에 무게를 둔 6주 프로젝트다.

- 실제 취약점 데이터(OSV, NVD, CISA KEV, FIRST EPSS)를 PostgreSQL에 캐시하고 MCP 서버로 제공한다
- 공개 저장소의 실제 의존성 파일 20개와 코드로 계산한 정답으로 채점한다. LLM 채점은 쓰지 않는다
- 오류 분석으로 가장 싼 모델(Haiku 5.5)을 Opus 5.5와 같은 품질까지 올렸다: **실행당 비용 1/46, 지연 절반**
- PDF·DOCX·XLSX·스캔 보고서에서 발견사항을 추출하고, 문서 속 프롬프트 인젝션을 막는다
- 6주 전체 API 비용 약 $7

한 장 요약: **[docs/PORTFOLIO.md](docs/PORTFOLIO.md)**

## 구조

```
 requirements.txt / package-lock.json / pom.xml / build.gradle        진단 보고서 (PDF·DOCX·XLSX·스캔)
                │ depfiles.py (정확한 버전만, 나머지는 "검사 불가"로)                │ docs/extract.py
                │                                                 결정적 추출 ──┤── LLM 추출 (Haiku, D1 프롬프트 강화)
                │                                                               └─ D2 교차 검증 → 경고
                ▼                                                                   │ 패키지·버전만 넘김
         ┌─────────────────────────────── 트리아지 에이전트 (agent.py) ◀────────────┘
         │  직접 구현한 도구 호출 루프 · JSON 스키마 출력 · 보고서 검증 루프(validate.py, 최대 2회 교정)
         └──MCP(stdio)──▶ vuln-data   check_packages / get_vulnerability ─▶ PostgreSQL ◀─ OSV·NVD 캐시, KEV·EPSS 스냅샷

 security-kb (별도 MCP 서버)  search_weaknesses / get_weakness ─▶ CWE 1,352개 (BM25 기본, 임베딩·pgvector 선택)
   트리아지 에이전트에는 아직 연결하지 않았다. Claude Code 같은 MCP 클라이언트에 붙여 CVE 설명으로 약점 유형을 찾는 데 쓴다
```

## 결과

| 주차 | 질문 | 결과 | 자세히 |
|---|---|---|---|
| 1 | 데이터 레이어 | OSV/NVD 요청 시 조회 + KEV/EPSS 일별 스냅샷, `as_of`로 재현 가능 | [data-layer.md](docs/data-layer.md) |
| 2 | 에이전트 v0 + 평가 | Opus 20/20 ($0.155), Sonnet 20/20 ($0.075), Haiku 19/20 ($0.0057). 평가가 포화 | [eval/README.md](eval/README.md) |
| 3 | 싼 모델을 어디까지? | Haiku 57/60 → **60/60**, $0.0034/실행, 지연 중앙값 13s. 실패는 전부 기록 실수 → 코드 검증 루프 | [week3.md](eval/analysis/week3.md) |
| 4 | CWE 검색 | BM25 hit@5 0.331 > 범용 임베딩 0.199. CWE 관찰 사례 색인으로 **0.475** (누수 제외해도 0.471) | [week4_retrieval.md](eval/analysis/week4_retrieval.md) |
| 4 | 보고서 문서 처리 | 결정적 추출 재현율 0.799 (스캔 0), Haiku 50/50 완전 일치, 문서당 $0.0005 | [week4_documents.md](eval/analysis/week4_documents.md) |
| 5 | 문서 속 인젝션 | 방어 없음 20% 성공 → 프롬프트 강화 0% / 결정적 교차 검증 0% (오탐 2% / 0%) | [week5_injection.md](eval/analysis/week5_injection.md) |
| 6 | 운영 | API 비용 0인 CI 회귀 검사, 평가 데이터 스냅샷(1.2MB)으로 어디서나 재현, 실행 기록 | 아래 |
| 7 | 서술은 맞나? | 구조화 필드 60/60인 같은 보고서에서 요약문 사실 정확성 **63%** (개수 오류 35%). 채점기는 변이 테스트로 검증 (대상을 잘못 쓴 오류 검출 0% → 55%) | [week7_prose.md](eval/analysis/week7_prose.md) |

3주차 핵심 표 (같은 20 케이스, 데이터 2026-11-20 고정):

| 버전 | 통과 | 95% CI | 실행당 비용 | 지연 중앙값 / p90 |
|---|---|---|---|---|
| Opus 5.5 | 20/20 | 84–100% | $0.155 | 26s / 72s |
| Haiku 5.5 | 57/60 | 86–98% | $0.0057 | 22s / 66s |
| Haiku + 보고서 검증 루프 | 60/60 | 94–100% | $0.0060 | 20s / 60s |
| **Haiku + 검증 + 결정적 계산 도구** | **60/60** | 94–100% | **$0.0034** | **13s / 34s** |

## 빠른 시작

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" pymupdf python-docx openpyxl pillow
createdb vulnagent && createdb vulnagent_test
export DATABASE_URL=postgresql:///vulnagent TEST_DATABASE_URL=postgresql:///vulnagent_test

.venv/bin/python -m vulnagent sync                          # KEV/EPSS 스냅샷 (약 6초)
.venv/bin/python -m vulnagent check PyPI/jinja2@2.10        # 데이터 레이어만 (API 키 불필요)
.venv/bin/python -m vulnagent extract report.pdf            # 결정적 추출 (무료)

export ANTHROPIC_API_KEY=...                                # 아래부터 Claude API 호출
.venv/bin/python -m vulnagent triage requirements.txt --model claude-haiku-5-5
.venv/bin/python -m vulnagent extract scan.pdf --llm --triage
.venv/bin/python -m vulnagent runs                          # 실행 기록 요약
```

MCP 클라이언트(Claude Code 등)에 데이터 서버만 붙일 수도 있다:

```json
{ "mcpServers": { "vuln-data": {
    "command": "/절대경로/vuln-triage-agent/.venv/bin/python",
    "args": ["-m", "vulnagent.mcp_server"],
    "env": { "DATABASE_URL": "postgresql:///vulnagent" } } } }
```

CWE 검색 서버(`python -m vulnagent.kb_server`)는 `pip install -e ".[kb]"`와 `python -m vulnagent.kb.cwe` 적재가 필요하다.
sudo 없는 서버에 PostgreSQL을 사용자 권한으로 올리는 방법은 [data-layer.md](docs/data-layer.md)에 있다.

## 운영 (6주차)

**CI 회귀 검사** (`scripts/ci.sh`, GitHub Actions `.github/workflows/ci.yml`). API를 부르지 않으므로 매 커밋 돌려도 비용 0이다.

| 검사 | 무엇이 깨지면 잡히나 |
|---|---|
| 단위·통합 테스트 (pytest) | 파서, 버전 계산, 캐시, MCP stdio, 에이전트 루프(가짜 클라이언트), 검증기, 추출기, 인젝션 방어 |
| 채점기 자체 점검: 정답 보고서 20/20, 빈 보고서 ≤2/20 | 채점기가 너무 관대해지거나 깨짐 |
| 결정적 문서 추출: 재현율 ≥0.79, 정밀도 1.0, 무관 CVE 0 | 추출기 퇴행 (PyMuPDF 판 차이로 표 추출이 깨진 적이 있다) |
| 결정적 추출기는 공격 문서 80개에서 표적을 빼지 않음 | 교차 검증 방어(D2)의 전제 |
| 스냅샷을 빈 DB에 적재 → 정답 오프라인 재계산 → 커밋된 정답과 완전 일치 | OSV/KEV/EPSS 처리, 버전 계산, 정답 생성 어디든 |
| 서술 채점기 변이 테스트: 일부러 틀린 요약문 검출률과 맞는 요약 오탐 0 | 서술 채점기(`eval/prose_grade.py`)가 느슨해짐 |

**평가 데이터 스냅샷** (`eval/snapshot.py`): 평가에 필요한 DB 행만(OSV 643, NVD 451, KEV·EPSS는 정답 CVE만) 1.2MB로 내보낸다.
어떤 PostgreSQL에서도 `VULNAGENT_OFFLINE=1`로 같은 도구 결과가 나와, 외부 API 상태와 상관없이 평가를 재현한다.

**실행 기록** (`src/vulnagent/runlog.py`): `triage`/`extract` 실행마다 `~/.vulnagent/runs.jsonl`에 한 줄 남긴다
(모델, 토큰, 비용, 지연, 도구 호출·오류, 검증 교정 횟수, 모델 대체 여부, 인젝션 경고 수). 문서·보고서 내용은 남기지 않는다.
`vulnagent runs`가 총비용, 지연 p50/p90, 교정·경고가 난 실행 수를 요약한다. `VULNAGENT_RUNLOG=off`로 끈다.

## 평가 다시 돌리기

```bash
python eval/ci_checks.py                                    # 비용 0 검사 전부
python eval/run_eval.py --variant vN --model claude-haiku-5-5 --reps 3 --budget-usd 0.5   # 에이전트 평가 (유료)
python eval/retrieval_eval.py                               # CWE 검색 (LLM 비용 0)
python eval/docs_eval.py --llm --budget-usd 0.15            # 문서 추출
python eval/injection_eval.py --budget-usd 0.5              # 인젝션
python eval/prose_eval.py --from-variant v4 --variant baseline   # 보고서 서술 사실 정확성 (기존 실행 재채점, 비용 0)
```

에이전트 평가는 하네스(코드·케이스·정답) 해시가 바뀌면 `--approve-harness` 없이는 돌지 않고, `--budget-usd`를 넘기면 멈춘다.
결과는 `.claude/hillclimb/triage/<variant>/`에 실행별 기록·대화 기록과 함께 남는다.

## 디렉터리

| 경로 | 내용 |
|---|---|
| `src/vulnagent/` | 데이터 레이어(`sources/`, `service.py`), MCP 서버 2개, 에이전트(`agent.py`, `validate.py`), 파서(`depfiles.py`, `versions.py`), 문서(`docs/`), CWE 검색(`kb/`), 실행 기록 |
| `eval/` | 케이스·정답·채점기·러너, 검색/문서/인젝션 평가, 스냅샷, 주차별 분석(`analysis/`) |
| `.claude/hillclimb/triage/` | 에이전트 개선 실험 기록 (variant별 변경 내용과 결과, `report.html`) |
| `tests/` | 오프라인 테스트 (`VULNAGENT_LIVE=1`이면 실제 API 테스트 포함) |
| `docs/` | 포트폴리오 요약, 데이터 레이어 설계 |
