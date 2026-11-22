"""채점기 검증: 정답은 통과, 그럴듯한 오답은 실패해야 한다 (채점기가 너무 관대하거나 엄격하지 않은지)."""

import copy
import json
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).parent.parent / "eval"
sys.path.insert(0, str(EVAL))

from grade import grade, null_report, oracle_report  # noqa: E402

GOLD = EVAL / "gold" / "maven-java-goof-struts.json"
pytestmark = pytest.mark.skipif(not GOLD.exists(), reason="gold not built (run eval/build_gold.py)")


@pytest.fixture
def gold():
    return json.loads(GOLD.read_text())


def test_oracle_passes_and_null_fails(gold):
    assert grade(oracle_report(gold), gold)[0]["pass"] == 1
    scores, _ = grade(null_report(gold), gold)
    assert scores["pass"] == 0 and scores["recall"] == 0


def test_upgrade_that_fixes_only_log4shell_is_wrong(gold):
    report = oracle_report(gold)
    for pkg in report["packages"]:
        if "log4j-core" in pkg["package"]:
            pkg["upgrade_to"] = "2.15.0"
    scores, why = grade(report, gold)
    assert scores["pass"] == 0 and scores["upgrade_ok"] < 1
    assert "still affected" in why["upgrade_ok"]


def test_downgrade_to_unaffected_old_line_is_wrong(gold):
    report = oracle_report(gold)
    for pkg in report["packages"]:
        if "zt-zip" in pkg["package"]:
            pkg["upgrade_to"] = "1.0"
    assert grade(report, gold)[0]["upgrade_ok"] < 1


def test_invented_high_version_is_wrong(gold):
    report = oracle_report(gold)
    for pkg in report["packages"]:
        pkg["upgrade_to"] = "999.0.0"  # 범위상 안전하지만 도구가 알려준 적 없는 버전
    scores, why = grade(report, gold)
    assert scores["upgrade_ok"] == 0 and "not a fixed version" in why["upgrade_ok"]


def test_same_cve_under_two_packages_needs_both():
    gold = json.loads((EVAL / "gold" / "maven-benchmark-java.json").read_text())
    assert grade(oracle_report(gold), gold)[0]["pass"] == 1
    report = oracle_report(gold)
    for pkg in report["packages"]:
        if "spring-web@" in pkg["package"]:
            pkg["vulnerabilities"] = [v for v in pkg["vulnerabilities"] if v["id"] != "CVE-2024-38820"]
    scores, _ = grade(report, gold)
    assert scores["recall"] < 1  # spring-context 쪽에만 있다고 spring-web 쪽까지 인정하지 않는다


def test_hallucinated_id_and_wrong_kev_flag_fail(gold):
    report = oracle_report(gold)
    report["packages"][0]["vulnerabilities"].append({"id": "CVE-2099-0001", "rank": 999, "priority": "low", "kev": False})
    assert grade(report, gold)[0]["no_halluc"] == 0

    report = oracle_report(gold)
    vuln = report["packages"][0]["vulnerabilities"][0]
    vuln["kev"] = not vuln["kev"]
    assert grade(report, gold)[0]["kev_facts"] == 0


def test_kev_must_rank_first(gold):
    report = oracle_report(gold)
    vulns = [v for p in report["packages"] for v in p["vulnerabilities"]]
    for v in vulns:
        v["rank"] = len(vulns) + 1 - v["rank"]
    scores, _ = grade(report, gold)
    assert scores["kev_order"] == 0 and scores["order_tau"] == -1.0


def test_alias_ids_count_as_found(gold):
    report = oracle_report(gold)
    first = gold["vulns"][0]
    ghsa = next(a for a in first["aliases"] if a.startswith("GHSA-"))
    for pkg in report["packages"]:
        for v in pkg["vulnerabilities"]:
            if v["id"] == first["id"]:
                v["id"] = ghsa.lower()
    assert grade(report, gold)[0]["pass"] == 1


def test_dropping_unchecked_entries_is_caught():
    gold = json.loads((EVAL / "gold" / "npm-dvna-manifest.json").read_text())
    report = oracle_report(gold)
    report["unchecked"] = report["unchecked"][:-1]
    assert grade(report, gold)[0]["unchecked_ok"] == 0
    assert grade(oracle_report(copy.deepcopy(gold)), gold)[0]["unchecked_ok"] == 1
