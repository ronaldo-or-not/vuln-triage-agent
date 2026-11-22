"""PostgreSQL 연결과 스키마 적용."""

from importlib import resources

import psycopg
from psycopg.rows import dict_row


def connect(database_url: str) -> psycopg.Connection:
    # autocommit: 문장 하나하나가 바로 커밋된다. 여러 문장을 묶어야 할 때만
    # `with conn.transaction():` 블록을 명시적으로 쓴다 (스냅샷 적재 등).
    # TimeZone=UTC: 시각을 늘 UTC로 받는다. 서버 기본 시간대(KST 등)를 따르면 같은 시각이 환경마다
    # 다른 문자열(+09:00 / +00:00)로 나와 도구 출력과 평가 정답이 재현되지 않는다 (GitHub Actions에서 발견).
    return psycopg.connect(database_url, autocommit=True, row_factory=dict_row, options="-c TimeZone=UTC")


def apply_schema(conn: psycopg.Connection) -> None:
    sql = resources.files("vulnagent").joinpath("schema.sql").read_text(encoding="utf-8")
    conn.execute(sql)
