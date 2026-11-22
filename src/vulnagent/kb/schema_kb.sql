-- security-kb 스키마 (4주차): CWE 지식베이스 + 임베딩 (pgvector)
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS cwe_entry (
    cwe_id           text PRIMARY KEY,           -- 'CWE-79'
    kind             text NOT NULL,              -- weakness | grouping
    name             text NOT NULL,
    abstraction      text,                       -- Pillar / Class / Base / Variant ...
    status           text,
    description      text,
    doc              text NOT NULL,              -- 검색에 쓰는 본문 (관찰 사례 제외)
    observed_cves    text[] NOT NULL DEFAULT '{}',  -- 관찰 사례의 CVE 번호. 평가 누수 방지를 위해 색인하지 않고 따로 둔다
    observed_text    text,                       -- 관찰 사례 설명 (누수 비교 실험에만 사용)
    catalog_version  text NOT NULL,
    raw              jsonb NOT NULL               -- 추출한 필드 원문 (결과, 완화책 등)
);

-- 모델별 임베딩. 모델마다 차원이 달라 차원 없는 vector로 저장하고, 1,400여 행이라 색인 없이 정확 검색한다.
CREATE TABLE IF NOT EXISTS cwe_embedding (
    cwe_id     text NOT NULL REFERENCES cwe_entry ON DELETE CASCADE,
    model      text NOT NULL,
    embedding  vector NOT NULL,
    PRIMARY KEY (cwe_id, model)
);
