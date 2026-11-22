# 데이터 레이어 (vuln-data MCP 서버)

```
에이전트 ──MCP(stdio)──> vuln-data 서버 ──> VulnService ──> PostgreSQL (캐시·스냅샷)
                          check_packages                 ├─ OSV   (요청 시 조회 + TTL 캐시)
                          get_vulnerability              ├─ NVD   (요청 시 조회 + TTL 캐시, 속도 제한)
                                                         ├─ KEV   (일 1회 벌크 스냅샷)
                                                         └─ EPSS  (일 1회 벌크 스냅샷, COPY 적재)
```

| 파일 | 역할 |
|---|---|
| `src/vulnagent/schema.sql` | 테이블 정의. 모든 소스의 원문을 `raw jsonb`로 보존 |
| `src/vulnagent/sources/{osv,nvd,kev,epss}.py` | 소스별 수집(네트워크) / 정규화(순수 함수) / 캐시(DB) |
| `src/vulnagent/service.py` | 소스를 합쳐 두 기능 제공. 3주차부터 결정적 계산(`safe_upgrade`, `policy_rank`)도 여기서 |
| `src/vulnagent/mcp_server.py` | MCP 도구 2개 (MCP Python SDK 2.x의 `MCPServer`) |
| `src/vulnagent/http.py` | 재시도·지수 백오프·슬라이딩 윈도우 속도 제한 |
| `src/vulnagent/ids.py` | CVE ID·시각·패키지 이름 정규화 |
| `tests/fixtures/` | 실제 API 응답을 잘라 만든 픽스처 |

## 설계 결정과 근거 (1주차, 실제 데이터로 확인한 수치)

| 결정 | 근거 |
|---|---|
| KEV/EPSS는 벌크 스냅샷, OSV/NVD는 요청 시 조회 + 캐시 | KEV는 1,790건(1.8MB), EPSS는 하루 410,485행(gzip 2.9MB)이라 통째로 받는 게 낫다. NVD는 키 없이 30초에 5회라 벌크 미러링이 비현실적 |
| OSV 레코드를 별칭으로 묶음 | jinja2 2.10 조회 결과 12건 = GHSA와 PYSEC가 같은 CVE 6건을 중복 기록 |
| OSV `modified`를 마이크로초로 잘라 비교 | 같은 레코드가 querybatch에서는 마이크로초, 상세 조회에서는 나노초로 와서 문자열 비교 시 캐시가 항상 무효 |
| NVD Primary 점수가 없으면 CNA Secondary로 대체 + 출처 반환 | 2026-10-01~03 공개 CVE 200건 표본(이틀치)에서 NVD Primary 점수 3건, Deferred 170건, CNA 등 Secondary 점수는 199건 |
| CVSS는 v3.1 → v3.0 → v4.0 → v2 순으로 선택 | 같은 200건 표본에서 v3.1 보유 163건, v4.0 보유 107건 → v3.1 우선이면 CVE끼리 같은 잣대로 비교 가능(v3.1 163건 + v4.0 36건 + 없음 1건). v4 점수는 v3와 같은 잣대로 비교하면 안 됨 |
| NVD metrics에서 `cvssMetric*` 키만 읽음 | metrics 안에 CISA SSVC(`ssvcV203`)가 섞여 있고 구조가 다름 |
| "없음"과 "모름" 구분 | KEV 스냅샷 없음 → `kev: null`, 목록에 없음 → `false`. EPSS 점수 없음 → `null`(0 아님). OSV 결과 없음 → "안전하다는 뜻 아님" 안내 (OSV는 오타 난 패키지에도 같은 `{}`를 준다) |
| check_packages에서는 NVD를 부르지 않음 | 패키지 50개에서 CVE가 총 100개 나오면 NVD 한도(30초 5회)로 약 10분. NVD는 상세 조회에서 CVE 하나씩만 |
| 데이터 레이어는 정렬·우선순위를 매기지 않음 | 우선순위 판단은 에이전트의 일이고, 2주차에 그 판단을 KEV/EPSS와 비교해 채점한다. 도구가 미리 정렬하면 평가가 무의미해짐 |
| KEV/EPSS 스냅샷을 날짜별 보존 + `as_of` + `pinned` | 평가를 같은 데이터로 재현해야 점수 변화가 에이전트 때문인지 데이터 때문인지 구분됨. EPSS 스냅샷 1개 ≈ DB 50MB라 pinned 아닌 건 최근 7개만 유지 |
| EPSS는 COPY, KEV는 executemany | 41만 행은 COPY로 적재(다운로드 포함 sync 전체 5.9초). 1,800행은 executemany로 충분 |
| 도구는 의도 단위 2개, 출력은 필요한 필드만 | OSV 원문 34KB → check_packages 출력 약 3KB. `affected[].versions`와 references 제거 |
| 오류는 모델이 고칠 수 있는 문장으로 | `pip` → "Use one of: PyPI, npm, ...", `>=2.0` → "exact installed version, not a range" |
| 외부 API에는 일반 User-Agent만 | `vuln-triage-agent/0.1`. 개인정보를 보내지 않음 |

> 1주차 결정 중 "데이터 레이어는 정렬하지 않음"은 3주차에 뒤집었다. 오류 분석 결과 Haiku의 시간과 순위 오류가
> 대부분 손으로 정렬하는 데서 나와서, 정렬·버전 계산을 도구가 하도록 바꿨다 ([week3.md](../eval/analysis/week3.md)).

## 알려진 한계

- OSV에 없는 ID(404)는 음성 캐시를 하지 않아 매번 다시 묻는다.
- NVD/OSV 캐시 자체는 스냅샷이 아니다. 평가 재현은 `eval/snapshot.py`로 평가에 쓰는 행만 고정해 둔다 (6주차).
- CISA Vulnrichment(NVD 공백 보완 데이터)는 아직 직접 수집하지 않는다. 일부는 NVD 응답에 CISA-ADP 점수로 이미 들어온다.
- 한 취약점 그룹에 CVE가 여러 개면 KEV/EPSS는 첫 번째 CVE 기준으로만 붙인다.
- OSV 페이지네이션(`next_page_token`) 경로는 실제로 페이지가 나뉘는 패키지로 아직 검증하지 않았다.

## sudo 없는 서버에 올리기

프로젝트 폴더 안에 사용자 권한으로 PostgreSQL을 설치하고, TCP 포트는 열지 않고 유닉스 소켓으로만 쓴다.
폴더를 지우면 전부 같이 지워진다.

```bash
cd ~/vuln-triage-agent
mkdir -p .tools/bin .pgsock && chmod 700 .pgsock
curl -sSL -o .tools/bin/micromamba https://github.com/mamba-org/micromamba-releases/releases/latest/download/micromamba-linux-64
chmod +x .tools/bin/micromamba
export MAMBA_ROOT_PREFIX=$PWD/.tools/mamba
.tools/bin/micromamba create -y -p $PWD/.tools/pg -c conda-forge postgresql=16 pgvector
PG=$PWD/.tools/pg/bin
$PG/initdb -D .pgdata --auth-local=peer --auth-host=scram-sha-256
$PG/pg_ctl -D .pgdata -l .pgdata/server.log -o "-c listen_addresses='' -c unix_socket_directories=$PWD/.pgsock" start
$PG/createdb -h $PWD/.pgsock vulnagent && $PG/createdb -h $PWD/.pgsock vulnagent_test

uv venv --python 3.12 && uv pip install -e ".[dev]"
export DATABASE_URL="postgresql:///vulnagent?host=$PWD/.pgsock"
export TEST_DATABASE_URL="postgresql:///vulnagent_test?host=$PWD/.pgsock"
.venv/bin/python -m pytest -q && .venv/bin/python -m vulnagent sync
```

매일 스냅샷 갱신(crontab):

```
0 9 * * * cd $HOME/vuln-triage-agent && DATABASE_URL="postgresql:///vulnagent?host=$HOME/vuln-triage-agent/.pgsock" .venv/bin/python -m vulnagent sync >> sync.log 2>&1
```
