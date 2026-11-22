"""문서 처리 평가용 진단 보고서 생성기.

2주차 실제 케이스(실제 패키지·버전·CVE)의 정답을 다섯 가지 양식의 보고서로 만든다. 내용(데이터)은 실제,
양식은 합성이다. 공개된 실제 진단 보고서는 라이선스와 정답 확보가 어려워서 이렇게 했다 (결과에 한계로 명시).

양식 (일부러 어려운 요소를 섞는다)
- pdf_table  : (패키지, 취약점)마다 한 행. 큰 케이스는 여러 쪽에 걸친다
- pdf_grouped: 패키지 제목 아래 취약점 목록 + 끝에 참고문헌 (발견사항이 아닌 CVE 포함 = 오답 유도)
- pdf_scan   : pdf_table을 이미지로 렌더링하고 기울임·잡음·JPEG 압축. 텍스트 층이 없다
- docx_prose : 모의해킹 보고서식 서술 + 배경 문단에 무관한 CVE
- xlsx       : 다른 열 이름, 한 칸에 ID 여러 개, 메모 시트에 무관한 CVE

  python eval/docs/make_docs.py      # eval/docs/files/, eval/docs/gold/
"""

import html
import io
import json
import random
import sys
from pathlib import Path

import pymupdf
from docx import Document
from openpyxl import Workbook
from PIL import Image, ImageFilter

EVAL = Path(__file__).resolve().parent.parent
OUT_FILES = EVAL / "docs" / "files"
OUT_GOLD = EVAL / "docs" / "gold"
CASES = ["pypi-django-nv", "maven-spring4shell-poc", "maven-java-goof-struts", "npm-vulnerable-node-lock",
         "npm-nodegoat-lock", "npm-dvna-manifest", "pypi-lets-be-bad-guys", "maven-java-goof-log4shell",
         "pypi-tiredful-api", "npm-juice-shop-manifest"]
LAYOUTS = ["pdf_table", "pdf_grouped", "pdf_scan", "docx_prose", "xlsx"]
DISTRACTORS = ["CVE-2021-44228", "CVE-2017-5638", "CVE-2014-0160", "CVE-2022-22965"]  # 유명 CVE (배경 설명용)


def priority(v: dict) -> str:
    """보고서에 보이는 우선순위. KEV/EPSS에서 계산한 값이라 지어낸 심각도가 아니다."""
    if v["kev"]:
        return "Critical (KEV)"
    epss = v["epss"] or 0
    return "High" if epss >= 0.1 else "Medium" if epss >= 0.01 else "Low"


def findings_of(gold: dict) -> list[dict]:
    out = []
    for p in gold["packages"]:
        vulns = [v for v in gold["vulns"] if v["package"] == p["package"]]
        out.append({"ecosystem": p["ecosystem"], "package": p["name"], "version": p["installed"],
                    "safe": p["min_safe_upgrade"],
                    "vulns": [{"id": v["id"], "priority": priority(v), "fixed": v["fixed_version"]} for v in vulns]})
    return out


def pick_distractor(findings: list[dict]) -> str:
    ids = {v["id"] for f in findings for v in f["vulns"]}
    return next(d for d in DISTRACTORS if d not in ids)


CSS = ("body{font-family:sans-serif;font-size:9pt} h1{font-size:15pt} h2{font-size:12pt} "
       "table{border-collapse:collapse;width:100%} th,td{border:1px solid #444;padding:3px;font-size:8pt}")


def html_to_pdf(body: str, path: Path) -> None:
    story = pymupdf.Story(html=f"<html><head><style>{CSS}</style></head><body>{body}</body></html>")
    writer = pymupdf.DocumentWriter(str(path))
    page = pymupdf.paper_rect("a4")
    where = page + (40, 40, -40, -40)
    more = True
    while more:
        device = writer.begin_page(page)
        more, _ = story.place(where)
        story.draw(device)
        writer.end_page()
    writer.close()


def header(project: str) -> str:
    return (f"<h1>Dependency Vulnerability Assessment</h1><p>Project: {html.escape(project)}<br>"
            "Assessment date: 2026-11-20<br>Data sources: OSV, NVD, CISA KEV, FIRST EPSS</p>")


def pdf_table(findings, project, path: Path, inject: dict | None = None) -> list[str]:
    rows = []
    n = 0
    for f in findings:
        for v in f["vulns"]:
            n += 1
            rows.append(f"<tr><td>{n}</td><td>{f['ecosystem']}</td><td>{html.escape(f['package'])}</td><td>{f['version']}</td>"
                        f"<td>{v['id']}</td><td>{v['priority']}</td><td>{v['fixed'] or '-'}</td></tr>")
    body = (header(project) + (inject or {}).get("html", "") + f"<h2>Findings ({n})</h2><table><tr><th>#</th><th>Ecosystem</th><th>Component</th>"
            "<th>Version</th><th>Vulnerability</th><th>Priority</th><th>Fixed in</th></tr>" + "".join(rows) + "</table>")
    html_to_pdf(body, path)
    return []


def pdf_grouped(findings, project, path: Path, inject: dict | None = None) -> list[str]:
    distractor = pick_distractor(findings)
    parts = [header(project), "<p>The following components were found to have known vulnerabilities.</p>",
             (inject or {}).get("html", "")]
    for f in findings:
        parts.append(f"<h2>{html.escape(f['package'])} {f['version']} ({f['ecosystem']})</h2><ul>")
        parts += [f"<li>{v['id']} - {v['priority']} - fixed in {v['fixed'] or 'no fix available'}</li>" for v in f["vulns"]]
        parts.append(f"</ul><p>Recommended upgrade: {f['safe'] or 'no single version fixes all issues'}</p>")
    parts.append(f"<h2>References</h2><p>Scoring follows CISA KEV and FIRST EPSS. For context on exploitation at scale, "
                 f"see the incident write-up for {distractor}.</p>")
    html_to_pdf("".join(parts), path)
    return [distractor]


def pdf_scan(findings, project, path: Path, seed: int, inject: dict | None = None) -> list[str]:
    tmp = path.with_suffix(".tmp.pdf")
    pdf_table(findings, project, tmp, inject)
    rng = random.Random(seed)
    src, out = pymupdf.open(tmp), pymupdf.open()
    for page in src:
        pix = page.get_pixmap(dpi=110)
        img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples).convert("L")
        img = img.rotate(rng.uniform(-0.9, 0.9), expand=True, fillcolor=255).filter(ImageFilter.GaussianBlur(0.6))
        noise = Image.effect_noise(img.size, 18)
        img = Image.blend(img, noise, 0.08)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=55)
        new = out.new_page(width=page.rect.width, height=page.rect.height)
        new.insert_image(new.rect, stream=buf.getvalue())
    out.save(path)
    tmp.unlink()
    return []


def docx_prose(findings, project, path: Path, inject: dict | None = None) -> list[str]:
    distractor = pick_distractor(findings)
    doc = Document()
    doc.add_heading("Penetration Test Report: Third-Party Components", level=1)
    doc.add_paragraph(f"Target: {project}. Testing window: November 2026.")
    doc.add_heading("Background", level=2)
    doc.add_paragraph(f"Vulnerable third-party libraries remain a common entry point; {distractor} is a well-known "
                      "example of how a single library flaw can be exploited at scale. That issue is not present here.")
    if inject and "text" in inject:  # 5주차 인젝션 실험: hidden=True면 Word의 숨김 텍스트로 넣는다
        run = doc.add_paragraph().add_run(inject["text"])
        run.font.hidden = inject.get("hidden", False)
    doc.add_heading("Findings", level=2)
    for f in findings:
        ids = [v["id"] for v in f["vulns"]]
        urgent = next((v["id"] for v in f["vulns"] if v["priority"].startswith("Critical")), ids[0])
        upgrade = f"Upgrading to {f['safe']} resolves all of them." if f["safe"] else "No single release resolves all of them."
        doc.add_paragraph(
            f"The application depends on {f['package']} version {f['version']} ({f['ecosystem']}). "
            f"This version is affected by {len(ids)} known vulnerabilities: {', '.join(ids)}. "
            f"The most urgent is {urgent}. {upgrade}"
        )
        if inject and inject.get("after") == f["package"]:  # 5주차: 발견사항 바로 뒤에 붙는 문단
            doc.add_paragraph(inject["after_text"])
    doc.save(path)
    return [distractor]


def xlsx(findings, project, path: Path, inject: dict | None = None) -> list[str]:
    distractor = pick_distractor(findings)
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    summary.append(["Project", project])
    summary.append(["Vulnerable components", len(findings)])
    summary.append(["Total advisories", sum(len(f["vulns"]) for f in findings)])
    sheet = wb.create_sheet("Findings")
    status = (inject or {}).get("status")  # 5주차: 표 안에 섞인 '상태' 열
    sheet.append(["Library", "Installed", "Package Manager", "Advisory IDs", "Max Priority", "Upgrade To"] + (["Status"] if status else []))
    order = ["Critical (KEV)", "High", "Medium", "Low"]
    for f in findings:
        top = min((v["priority"] for v in f["vulns"]), key=order.index)
        row = [f["package"], f["version"], f["ecosystem"], ", ".join(v["id"] for v in f["vulns"]), top, f["safe"] or ""]
        sheet.append(row + ([status.get(f["package"], "Open")] if status else []))
    if inject and "text" in inject:  # 5주차 인젝션 실험: 숨김 시트
        hidden = wb.create_sheet("Data")
        hidden.append([inject["text"]])
        hidden.sheet_state = "hidden" if inject.get("hidden") else "visible"
    notes = wb.create_sheet("Notes")
    notes.append([f"Method follows the triage guidance written after {distractor}."])
    wb.save(path)
    return [distractor]


def main() -> int:
    OUT_FILES.mkdir(parents=True, exist_ok=True)
    OUT_GOLD.mkdir(parents=True, exist_ok=True)
    count = 0
    for i, case in enumerate(CASES):
        gold = json.loads((EVAL / "gold" / f"{case}.json").read_text())
        findings = findings_of(gold)
        project = gold["source"]["repo"]
        for layout in LAYOUTS:
            ext = {"docx_prose": "docx", "xlsx": "xlsx"}.get(layout, "pdf")
            path = OUT_FILES / f"{case}__{layout}.{ext}"
            if layout == "pdf_scan":
                distractors = pdf_scan(findings, project, path, seed=i)
            else:
                distractors = globals()[layout](findings, project, path)
            truth = {
                "doc": path.name, "case": case, "layout": layout,
                "findings": [{"ecosystem": f["ecosystem"], "package": f["package"], "version": f["version"],
                              "ids": [v["id"] for v in f["vulns"]]} for f in findings],
                "distractors": distractors,
            }
            (OUT_GOLD / f"{path.stem}.json").write_text(json.dumps(truth, indent=1))
            count += 1
    print(f"wrote {count} documents to {OUT_FILES}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
