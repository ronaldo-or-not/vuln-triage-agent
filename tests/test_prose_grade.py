"""서술 채점기: 맞는 서술은 통과, 그럴듯하게 틀린 서술은 해당 지표만 실패해야 한다."""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "eval"))

from prose_grade import grade_prose  # noqa: E402

PAYLOAD = {
    "dependencies": [{"ecosystem": "Maven", "name": f"g:a{i}", "version": "1.0"} for i in range(5)],
    "unchecked": [{"spec": "g:b", "reason": "no version"}],
    "parser_notes": ["lockfileVersion 2: 1274 packages in total"],
}
CHECK = {"results": [
    {"package": "Maven/org.apache.logging.log4j:log4j-core@2.14.1", "status": "vulnerable", "vulnerabilities": [
        {"id": "CVE-2021-44228", "cve_ids": ["CVE-2021-44228"], "osv_ids": ["GHSA-jfh8-c2jp-5v3q"], "kev": {"dateAdded": "x"}, "policy_rank": 1},
        {"id": "CVE-2021-45046", "cve_ids": ["CVE-2021-45046"], "osv_ids": [], "kev": {"dateAdded": "x"}, "policy_rank": 2},
        {"id": "CVE-2021-44832", "cve_ids": ["CVE-2021-44832"], "osv_ids": [], "kev": False, "policy_rank": 3}]},
    {"package": "Maven/org.yaml:snakeyaml@1.30", "status": "vulnerable", "vulnerabilities": [
        {"id": "CVE-2022-1471", "cve_ids": ["CVE-2022-1471"], "osv_ids": [], "kev": False, "policy_rank": 4}]},
    *({"package": f"Maven/g:a{i}@1.0", "status": "no_known_vulns"} for i in range(3)),
]}
REPORT = {
    "summary": "직접 의존성 5개 중 2개 패키지에서 취약점 4건이 확인되었습니다. 가장 시급한 것은 KEV에 등재된 log4j-core의 "
               "CVE-2021-44228입니다. 버전이 없는 1개 항목은 확인하지 못했습니다.",
    "packages": [
        {"package": "Maven/org.apache.logging.log4j:log4j-core@2.14.1", "upgrade_to": "2.17.1",
         "reason": "CVE-2021-44228, CVE-2021-45046(KEV)과 CVE-2021-44832를 모두 해결하는 최소 버전은 2.17.1입니다.", "vulnerabilities": []},
        {"package": "Maven/org.yaml:snakeyaml@1.30", "upgrade_to": "2.0",
         "reason": "CVE-2022-1471(GHSA 없음)은 2.0에서 수정됩니다. 이 패키지에 KEV 등록 항목은 없습니다.", "vulnerabilities": []},
    ],
    "unchecked": [], "notes": ["lockfile의 1274개 패키지 중 직접 의존성만 검사했습니다."],
}


def grade_with(**changes):
    report = copy.deepcopy(REPORT)
    for key, value in changes.items():
        report[key] = value
    return grade_prose(PAYLOAD, CHECK, report)


def test_correct_prose_passes_everything():
    scores, why = grade_with()
    assert scores == {m: 1 for m in scores}, why


def test_wrong_counts_fail_only_counts():
    scores, why = grade_with(summary=REPORT["summary"].replace("취약점 4건", "취약점 10건"))
    assert scores["counts_ok"] == 0 and scores["prose_ok"] == 0 and "10건" in why["counts_ok"]
    assert all(scores[m] == 1 for m in ("ids_grounded", "kev_consistent", "top1_named", "korean_only"))


def test_per_package_and_parser_note_numbers_are_allowed():
    scores, _ = grade_with(summary=REPORT["summary"] + " log4j-core에는 3건이 있고, 전체 1274개 패키지 중 일부만 봤습니다.")
    assert scores["counts_ok"] == 1


def test_approximate_counts_within_ten_percent():
    assert grade_with(summary=REPORT["summary"] + " 약 5개 의존성")[0]["counts_ok"] == 1
    assert grade_with(summary=REPORT["summary"] + " 3개 이상의 취약점")[0]["counts_ok"] == 1  # 실제 4건
    assert grade_with(summary=REPORT["summary"] + " 약 40개 의존성")[0]["counts_ok"] == 0
    assert grade_with(summary=REPORT["summary"] + " 7개 이상의 취약점")[0]["counts_ok"] == 0  # '이상'인데 실제가 더 적다


def test_invented_id_fails_grounding():
    scores, why = grade_with(notes=["CVE-2099-0001도 확인이 필요합니다."])
    assert scores["ids_grounded"] == 0 and "CVE-2099-0001" in why["ids_grounded"]


def test_alias_ids_count_as_grounded():
    assert grade_with(notes=["GHSA-jfh8-c2jp-5v3q는 CVE-2021-44228과 같은 항목입니다."])[0]["ids_grounded"] == 1


def test_kev_contradiction_global_and_per_package():
    assert grade_with(notes=["KEV 등재 항목은 없습니다."])[0]["kev_consistent"] == 0
    packages = copy.deepcopy(REPORT["packages"])
    packages[0]["reason"] = "이 패키지의 KEV 등록 항목은 없습니다."
    assert grade_with(packages=packages)[0]["kev_consistent"] == 0
    # KEV가 없는 패키지(snakeyaml)에 대해 "없다"고 쓴 것은 모순이 아니다 (REPORT 기본값)


def test_summary_must_name_rank_one():
    scores, why = grade_with(summary="직접 의존성 5개 중 2개 패키지에서 취약점 4건이 확인되었습니다. snakeyaml을 먼저 올리세요.")
    assert scores["top1_named"] == 0 and "CVE-2021-44228" in why["top1_named"]


def test_foreign_script_fails_korean_only():
    scores, _ = grade_with(summary=REPORT["summary"] + " ランサム웨어 사용 이력도 있습니다.")
    assert scores["korean_only"] == 0


def test_no_vulnerabilities_case():
    check = {"results": [{"package": "PyPI/flask@2.0.0", "status": "no_known_vulns"}]}
    report = {"summary": "직접 의존성 1개를 확인했고 알려진 취약점은 없었습니다.", "packages": [], "unchecked": [], "notes": []}
    payload = {"dependencies": [{"ecosystem": "PyPI", "name": "flask", "version": "2.0.0"}], "unchecked": [], "parser_notes": []}
    scores, why = grade_prose(payload, check, report)
    assert scores["prose_ok"] == 1, why


def test_number_attached_to_the_wrong_thing_fails():
    # 5는 사실표에 있는 값(직접 의존성 수)이지만 "취약점 5건"은 틀렸다 (실제 취약점 4건)
    scores, why = grade_with(summary=REPORT["summary"].replace("취약점 4건", "취약점 5건"))
    assert scores["counts_ok"] == 0 and "[vuln]" in why["counts_ok"]
    # 반대로 패키지 자리에 취약점 수(4)를 쓴 경우: 취약 패키지는 2개
    scores, why = grade_with(summary=REPORT["summary"].replace("2개 패키지에서", "4개 패키지에서"))
    assert scores["counts_ok"] == 0 and "[vulnerable_pkg]" in why["counts_ok"]


def test_claim_category_reads_korean_context():
    from prose_grade import count_claims
    cats = {c["n"]: c["category"] for c in count_claims("직접 의존성 13개 중 4개에서 취약점이 확인되었고, 총 16개의 취약점과 나머지 9개 의존성")}
    assert cats == {13: "pkg", 4: "vulnerable_pkg", 16: "vuln", 9: "pkg"}


def test_total_vulnerabilities_with_jung_is_a_vulnerability_count():
    # "취약점 총 4건 중"의 "중" 때문에 패키지 수로 보면 안 된다 (실제 오탐 사례에서 나온 회귀 테스트)
    scores, why = grade_with(summary=REPORT["summary"] + " 취약점 총 4건 중 KEV는 2건입니다.")
    assert scores["counts_ok"] == 1, why


def test_thousands_separator_is_one_number():
    scores, why = grade_with(summary=REPORT["summary"] + " lockfile의 1,274개 패키지 중 직접 의존성만 봤습니다.")
    assert scores["counts_ok"] == 1, why


def test_unique_vulnerability_count_is_allowed():
    # 같은 ID가 두 패키지에 걸린 경우: 합계 2건, 고유 1건. "고유 취약점 1건"도, "취약점 2건"도 맞다
    check = {"results": [
        {"package": "Maven/org.springframework:spring-web@5.3.0", "status": "vulnerable",
         "vulnerabilities": [{"id": "CVE-2024-38820", "kev": False, "policy_rank": 1}]},
        {"package": "Maven/org.springframework:spring-context@5.3.0", "status": "vulnerable",
         "vulnerabilities": [{"id": "CVE-2024-38820", "kev": False, "policy_rank": 2}]}]}
    payload = {"dependencies": [{}, {}, {}], "unchecked": [], "parser_notes": []}
    for summary in ("직접 의존성 3개 중 2개 패키지에서 취약점 2건(고유 1건)이 확인되었습니다. spring-web을 먼저 올리세요.",):
        report = {"summary": summary, "packages": [], "unchecked": [], "notes": []}
        scores, why = grade_prose(payload, check, report)
        assert scores["counts_ok"] == 1, why
