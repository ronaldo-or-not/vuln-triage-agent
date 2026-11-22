"""v3 검증기: 3주차 Haiku 실패 3가지 유형을 실제 사례 그대로 잡는지 확인한다."""

from vulnagent.validate import validate_report

TOOL = {"results": [
    {"package": "PyPI/djangorestframework@3.7.3", "status": "vulnerable", "vulnerabilities": [
        {"id": "CVE-2020-25626", "cve_ids": ["CVE-2020-25626"], "osv_ids": ["GHSA-fx83-3ph3-9j2q"], "kev": False},
        {"id": "CVE-2018-25045", "cve_ids": ["CVE-2018-25045"], "osv_ids": ["GHSA-xxxx-yyyy-zzzz"], "kev": {"date_added": "2024-01-01"}},
    ]},
    {"package": "PyPI/django@1.11.7", "status": "vulnerable", "vulnerabilities": [
        {"id": "CVE-2019-6975", "cve_ids": ["CVE-2019-6975"], "osv_ids": ["PYSEC-2019-13"], "kev": False},
    ]},
    {"package": "PyPI/oauth@1.0.1", "status": "no_known_vulns"},
]}


def _report(drf_vulns, django_vulns=None):
    packages = [{"package": "PyPI/djangorestframework@3.7.3", "upgrade_to": None, "reason": "", "vulnerabilities": drf_vulns}]
    if django_vulns is not None:
        packages.append({"package": "PyPI/django@1.11.7", "upgrade_to": None, "reason": "", "vulnerabilities": django_vulns})
    return {"summary": "", "packages": packages, "unchecked": [], "notes": []}


def v(vid, kev=False, rank=1):
    return {"id": vid, "rank": rank, "priority": "low", "kev": kev}


def test_correct_report_passes_and_aliases_are_accepted():
    report = _report([v("GHSA-fx83-3ph3-9j2q"), v("CVE-2018-25045", kev=True)], [v("cve-2019-6975")])
    assert validate_report(report, [TOOL]) == []


def test_transcription_error_is_caught():  # 실제 사례: CVE-2020-25626 -> CVE-2025-25626
    problems = validate_report(_report([v("CVE-2025-25626"), v("CVE-2018-25045", kev=True)], [v("CVE-2019-6975")]), [TOOL])
    assert any("CVE-2025-25626" in p and "typos" in p for p in problems)
    assert any("missing 1" in p and "CVE-2020-25626" in p for p in problems)


def test_vulnerability_under_the_wrong_package_is_caught():  # 실제 사례: node-serialize 취약점을 mathjs 아래에
    report = _report([v("CVE-2020-25626"), v("CVE-2018-25045", kev=True), v("CVE-2019-6975")], [v("CVE-2019-6975")])
    problems = validate_report(report, [TOOL])
    assert problems == ["CVE-2019-6975 is listed under PyPI/djangorestframework@3.7.3, but check_packages returned it only for PyPI/django@1.11.7"]


def test_omission_and_wrong_kev_and_extra_package_are_caught():
    report = _report([v("CVE-2020-25626"), v("CVE-2018-25045", kev=False)])
    report["packages"].append({"package": "PyPI/oauth@1.0.1", "upgrade_to": None, "reason": "", "vulnerabilities": []})
    problems = validate_report(report, [TOOL])
    assert any("kev should be true" in p for p in problems)
    assert any("django@1.11.7: missing 1" in p for p in problems)
    assert any("oauth@1.0.1" in p and "remove it" in p for p in problems)
