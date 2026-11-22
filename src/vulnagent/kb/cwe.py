"""MITRE CWE 카탈로그 수집·파싱·적재.

  python -m vulnagent.kb.cwe            # 최신 XML을 받아 DB에 적재 (약 2MB zip, 1,400여 항목)

설계 메모
- 검색 본문(doc)에는 이름, 설명, 확장 설명, 다른 이름, 영향, 완화책을 넣고 관찰 사례(Observed_Examples)는
  뺀다. 관찰 사례에는 실제 CVE 번호와 설명이 들어 있어서, CVE 설명으로 CWE를 찾는 평가에서 거의 같은
  문장이 정답 문서에 들어가 있는 셈이 된다(누수). 따로 저장해 두고 누수 효과를 비교 실험으로 보여준다.
- Deprecated 항목은 적재하지 않는다 (더 이상 쓰지 말라는 항목).
"""

import io
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from importlib import resources

import psycopg
from psycopg.types.json import Jsonb

URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_SPACE = re.compile(r"\s+")


def _text(el: ET.Element | None) -> str:
    return _SPACE.sub(" ", " ".join(el.itertext())).strip() if el is not None else ""


def parse(xml_bytes: bytes) -> tuple[str, list[dict]]:
    root = ET.fromstring(xml_bytes)
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    version = root.attrib.get("Version", "unknown")
    entries = []
    for kind, section, tag in (("weakness", "Weaknesses", "Weakness"), ("grouping", "Groupings", "Grouping")):
        for el in root.findall(f"{ns}{section}/{ns}{tag}"):
            status = el.attrib.get("Status", "")
            if status == "Deprecated":
                continue
            fields = {
                "description": _text(el.find(f"{ns}Description")) or _text(el.find(f"{ns}Summary")),
                "extended_description": _text(el.find(f"{ns}Extended_Description")),
                "alternate_terms": "; ".join(_text(t.find(f"{ns}Term")) for t in el.findall(f"{ns}Alternate_Terms/{ns}Alternate_Term")),
                "consequences": " ".join(_text(c) for c in el.findall(f"{ns}Common_Consequences/{ns}Consequence")),
                "mitigations": " ".join(_text(m.find(f"{ns}Description")) for m in el.findall(f"{ns}Potential_Mitigations/{ns}Mitigation")),
            }
            observed = [(_text(o.find(f"{ns}Reference")), _text(o.find(f"{ns}Description")))
                        for o in el.findall(f"{ns}Observed_Examples/{ns}Observed_Example")]
            name = el.attrib.get("Name", "")
            doc = "\n".join(x for x in (name, fields["description"], fields["extended_description"],
                                        fields["alternate_terms"], fields["consequences"], fields["mitigations"]) if x)
            entries.append({
                "cwe_id": f"CWE-{el.attrib['ID']}",
                "kind": kind,
                "name": name,
                "abstraction": el.attrib.get("Abstraction"),
                "status": status,
                "description": fields["description"],
                "doc": doc,
                "observed_cves": sorted({ref.upper() for ref, _ in observed if ref.upper().startswith("CVE-")}),
                "observed_text": " ".join(desc for _, desc in observed),
                "fields": fields,
            })
    return version, entries


def apply_schema(conn: psycopg.Connection) -> None:
    conn.execute(resources.files("vulnagent.kb").joinpath("schema_kb.sql").read_text(encoding="utf-8"))


def load(conn: psycopg.Connection, version: str, entries: list[dict]) -> int:
    with conn.transaction():
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO cwe_entry (cwe_id, kind, name, abstraction, status, description, doc,
                                       observed_cves, observed_text, catalog_version, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cwe_id) DO UPDATE SET
                    kind = EXCLUDED.kind, name = EXCLUDED.name, abstraction = EXCLUDED.abstraction,
                    status = EXCLUDED.status, description = EXCLUDED.description, doc = EXCLUDED.doc,
                    observed_cves = EXCLUDED.observed_cves, observed_text = EXCLUDED.observed_text,
                    catalog_version = EXCLUDED.catalog_version, raw = EXCLUDED.raw
                """,
                [(e["cwe_id"], e["kind"], e["name"], e["abstraction"], e["status"], e["description"], e["doc"],
                  e["observed_cves"], e["observed_text"], version, Jsonb(e["fields"])) for e in entries],
            )
        # 카탈로그에서 빠진(이번에 Deprecated 된) 항목 정리. 임베딩은 CASCADE로 같이 지워진다.
        conn.execute("DELETE FROM cwe_entry WHERE catalog_version <> %s", (version,))
    return len(entries)


def main() -> int:
    from ..config import load_settings
    from ..db import connect
    from ..http import make_client, request

    settings = load_settings()
    with make_client(settings.user_agent) as client:
        r = request(client, "GET", URL)
        r.raise_for_status()
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    version, entries = parse(archive.read(archive.namelist()[0]))
    conn = connect(settings.database_url)
    apply_schema(conn)
    n = load(conn, version, entries)
    kinds = {k: sum(1 for e in entries if e["kind"] == k) for k in ("weakness", "grouping")}
    print(f"CWE {version}: loaded {n} entries {kinds}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
