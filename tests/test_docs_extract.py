"""문서 추출기 테스트 (결정적 방식). 작은 문서를 그 자리에서 만들어 검사한다."""

import pytest

docx = pytest.importorskip("docx")
openpyxl = pytest.importorskip("openpyxl")
pymupdf = pytest.importorskip("pymupdf")

from vulnagent.docs.extract import Extraction, Finding, extract_deterministic, to_parse_result  # noqa: E402


def test_docx_prose_keeps_background_ids_out_of_findings(tmp_path):
    d = docx.Document()
    d.add_heading("Background", level=2)
    d.add_paragraph("CVE-2021-44228 is a famous example. It is not present here.")
    d.add_heading("Findings", level=2)
    d.add_paragraph("The application depends on jinja2 version 2.10 (PyPI). It is affected by CVE-2019-10906 and CVE-2020-28493.")
    path = tmp_path / "r.docx"
    d.save(path)
    r = extract_deterministic(path)
    assert [(f.package, f.version, f.ids) for f in r.findings] == [("jinja2", "2.10", ["CVE-2019-10906", "CVE-2020-28493"])]
    assert r.other_ids == ["CVE-2021-44228"]


def test_xlsx_with_package_manager_column_and_multi_id_cells(tmp_path):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Library", "Installed", "Package Manager", "Advisory IDs"])
    ws.append(["lodash", "4.17.15", "npm", "CVE-2020-8203, GHSA-35JH-R3H4-6JHM"])
    path = tmp_path / "r.xlsx"
    wb.save(path)
    f = extract_deterministic(path).findings[0]
    assert (f.ecosystem, f.package, f.version, f.ids) == ("npm", "lodash", "4.17.15", ["CVE-2020-8203", "GHSA-35jh-r3h4-6jhm"])


def test_pdf_table_ids_with_hyphens_survive_extraction(tmp_path):
    """PyMuPDF 버전에 따라 표 칸의 하이픈·점 순서가 뒤섞인 적이 있다. 이 테스트가 그 회귀를 잡는다."""
    html = ("<table style='border-collapse:collapse'><tr><th style='border:1px solid #000'>Component</th>"
            "<th style='border:1px solid #000'>Version</th><th style='border:1px solid #000'>Vulnerability</th></tr>"
            "<tr><td style='border:1px solid #000'>org.apache.logging.log4j:log4j-core</td>"
            "<td style='border:1px solid #000'>2.7</td><td style='border:1px solid #000'>CVE-2017-5645</td></tr></table>")
    path = tmp_path / "t.pdf"
    story = pymupdf.Story(html=html)
    writer = pymupdf.DocumentWriter(str(path))
    rect = pymupdf.paper_rect("a4")
    device = writer.begin_page(rect)
    story.place(rect + (40, 40, -40, -40))
    story.draw(device)
    writer.end_page()
    writer.close()
    f = extract_deterministic(path).findings
    assert [(x.package, x.version, x.ids) for x in f] == [("org.apache.logging.log4j:log4j-core", "2.7", ["CVE-2017-5645"])]


def test_image_only_pdf_yields_no_findings_and_says_why(tmp_path):
    src = pymupdf.open()
    page = src.new_page()
    page.insert_text((72, 72), "CVE-2019-10906 jinja2 2.10")
    pix = page.get_pixmap(dpi=72)
    scan = pymupdf.open()
    scan.new_page(width=page.rect.width, height=page.rect.height).insert_image(page.rect, pixmap=pix)
    path = tmp_path / "scan.pdf"
    scan.save(path)
    r = extract_deterministic(path)
    assert r.findings == [] and "no text layer" in r.notes[0]


def test_extraction_becomes_triage_input_without_trusting_report_ids():
    ext = Extraction(method="llm", findings=[Finding("PyPI", "jinja2", "2.10", ["CVE-2019-10906"]),
                                             Finding(None, "mystery-lib", "1.0", ["CVE-2020-0001"])],
                     other_ids=["CVE-2021-44228"])
    parsed = to_parse_result(ext, "report.pdf")
    assert [(d.ecosystem, d.name, d.version) for d in parsed.dependencies] == [("PyPI", "jinja2", "2.10")]
    assert parsed.unchecked[0].spec == "mystery-lib 1.0" and "ecosystem" in parsed.unchecked[0].reason
    assert any("re-checked with the tools" in n for n in parsed.notes)
