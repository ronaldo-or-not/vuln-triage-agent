-- vuln-data 스키마 (PostgreSQL 16)
--
-- 원칙
-- 1. 원본 보존: 모든 소스의 응답 원문을 raw JSONB로 저장한다. 파싱 규칙이 바뀌면
--    API를 다시 부르지 않고 raw에서 다시 뽑으면 된다.
-- 2. 두 가지 수집 방식
--    - 벌크 스냅샷(KEV, EPSS): 전체가 작거나 하루 1회 갱신 -> 통째로 받아 스냅샷으로 저장
--    - 요청 시 조회 + 캐시(OSV, NVD): 전체가 크거나 속도 제한이 빡빡함 -> 필요한 것만 받아 TTL 캐시
-- 3. 스냅샷은 날짜(버전)별로 남긴다. 2주차 평가에서 "같은 데이터로 다시 돌리기"가 가능해야
--    점수 변화가 에이전트 때문인지 데이터 때문인지 구분할 수 있다.

-- ---------- OSV: 패키지 버전 -> 취약점 ----------
CREATE TABLE IF NOT EXISTS osv_vuln (
    id          text PRIMARY KEY,                 -- GHSA-..., PYSEC-..., GO-..., RUSTSEC-...
    modified    timestamptz NOT NULL,             -- 마이크로초로 잘라서 저장 (ids.parse_ts 참고)
    published   timestamptz,
    withdrawn   timestamptz,
    summary     text,
    aliases     text[] NOT NULL DEFAULT '{}',
    cve_ids     text[] NOT NULL DEFAULT '{}',     -- aliases 중 CVE만 뽑아 정규화. KEV/EPSS/NVD와의 조인 키
    raw         jsonb NOT NULL,
    fetched_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS osv_vuln_cve_ids_idx ON osv_vuln USING gin (cve_ids);

-- "이 패키지 이 버전에 어떤 취약점이 있나"의 질의 결과 캐시. 빈 배열도 저장한다(= 알려진 취약점 없음).
CREATE TABLE IF NOT EXISTS osv_package_query (
    ecosystem   text NOT NULL,
    name        text NOT NULL,                    -- 생태계 규칙으로 정규화한 이름 (PyPI: PEP 503)
    version     text NOT NULL,
    vuln_ids    text[] NOT NULL,
    fetched_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ecosystem, name, version)
);

-- ---------- NVD: CVE 상세 (설명, CVSS, CWE) ----------
CREATE TABLE IF NOT EXISTS nvd_cve (
    cve_id         text PRIMARY KEY,
    found          boolean NOT NULL,              -- false = NVD에 없음 (음성 캐시: 없는 걸 매번 다시 묻지 않기)
    vuln_status    text,                          -- Analyzed / Awaiting Analysis / Deferred / Rejected ...
    published      timestamptz,
    last_modified  timestamptz,
    description    text,
    cvss_score     numeric(3,1),
    cvss_severity  text,
    cvss_version   text,
    cvss_vector    text,
    cvss_source    text,                          -- 점수를 매긴 주체 (NVD / CNA / CISA-ADP)
    cvss_type      text,                          -- Primary(NVD) / Secondary(CNA 등)
    cwes           text[] NOT NULL DEFAULT '{}',
    raw            jsonb,
    fetched_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------- CISA KEV: 실제 악용이 확인된 취약점 목록 (스냅샷) ----------
CREATE TABLE IF NOT EXISTS kev_snapshot (
    catalog_version  text PRIMARY KEY,            -- 예: 2026.11.20
    date_released    timestamptz,
    entry_count      integer NOT NULL,
    pinned           boolean NOT NULL DEFAULT false,  -- true면 오래돼도 정리(prune)하지 않음 (평가용)
    fetched_at       timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kev_entry (
    catalog_version     text NOT NULL REFERENCES kev_snapshot ON DELETE CASCADE,
    cve_id              text NOT NULL,
    vendor_project      text,
    product             text,
    vulnerability_name  text,
    date_added          date,
    due_date            date,
    known_ransomware    text,                     -- Known / Unknown
    required_action     text,
    raw                 jsonb NOT NULL,
    PRIMARY KEY (catalog_version, cve_id)
);

-- ---------- EPSS: 30일 내 악용될 확률 (일별 스냅샷, 약 40만 행/일) ----------
CREATE TABLE IF NOT EXISTS epss_snapshot (
    score_date     date PRIMARY KEY,
    model_version  text,
    row_count      integer NOT NULL DEFAULT 0,
    pinned         boolean NOT NULL DEFAULT false,
    fetched_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS epss_score (
    score_date  date NOT NULL REFERENCES epss_snapshot ON DELETE CASCADE,
    cve_id      text NOT NULL,
    epss        real NOT NULL,
    percentile  real NOT NULL,
    PRIMARY KEY (score_date, cve_id)
);
