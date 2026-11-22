"""EPSS (FIRST): 앞으로 30일 안에 이 CVE가 악용될 확률 (0~1)과 백분위.

수집 방식: 벌크 스냅샷. 하루 한 번 전체 점수 파일(gzip CSV, 약 2.9MB, 약 41만 행)이 나온다.
CVE마다 API를 부르는 것보다 하루 한 번 통째로 받는 게 빠르고, 날짜별 스냅샷으로 남길 수 있다.

파일 첫 줄은 주석이다:  #model_version:v2026.06.15,score_date:2026-11-20T12:03:05Z
그 다음 줄이 헤더(cve,epss,percentile)이고 이후가 데이터.

주의: 파일에 없는 CVE(막 공개됐거나 REJECTED)는 "점수 0"이 아니라 "점수 없음"이다.
"""

import csv
import gzip
import io
from datetime import date

import httpx
import psycopg

from ..errors import SourceError
from ..http import request
from ..ids import normalize_cve, parse_ts

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_current(client: httpx.Client) -> str:
    r = request(client, "GET", URL)
    if r.status_code >= 400:
        raise SourceError(f"EPSS HTTP {r.status_code}")
    return gzip.decompress(r.content).decode("utf-8")


def parse_csv(text: str) -> tuple[dict, list[tuple[str, float, float]]]:
    lines = text.splitlines()
    meta: dict = {}
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()
        lines = lines[1:]
    score_ts = parse_ts(meta.get("score_date"))
    meta = {"model_version": meta.get("model_version"), "score_date": score_ts.date() if score_ts else None}
    rows = []
    for rec in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = normalize_cve(rec.get("cve", ""))
        if cve:
            rows.append((cve, float(rec["epss"]), float(rec["percentile"])))
    return meta, rows


def load_snapshot(conn: psycopg.Connection, meta: dict, rows: list[tuple[str, float, float]]) -> bool:
    score_date: date | None = meta.get("score_date")
    if score_date is None:
        raise SourceError("EPSS file has no score_date header")
    with conn.transaction():
        inserted = conn.execute(
            """
            INSERT INTO epss_snapshot (score_date, model_version, row_count)
            VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING score_date
            """,
            (score_date, meta.get("model_version"), len(rows)),
        ).fetchone()
        if not inserted:
            conn.execute("UPDATE epss_snapshot SET fetched_at = now() WHERE score_date = %s", (score_date,))
            return False
        # COPY: 행 단위 INSERT보다 훨씬 빠른 PostgreSQL 대량 적재 방식. 41만 행에 몇 초.
        with conn.cursor() as cur:
            with cur.copy("COPY epss_score (score_date, cve_id, epss, percentile) FROM STDIN") as copy:
                for cve, epss, pct in rows:
                    copy.write_row((score_date, cve, epss, pct))
    return True


def lookup(conn: psycopg.Connection, score_date: date, cve_ids: list[str]) -> dict[str, dict]:
    rows = conn.execute(
        "SELECT cve_id, epss, percentile FROM epss_score WHERE score_date = %s AND cve_id = ANY(%s)",
        (score_date, cve_ids),
    )
    return {r["cve_id"]: {"epss": round(r["epss"], 5), "percentile": round(r["percentile"], 4)} for r in rows}
