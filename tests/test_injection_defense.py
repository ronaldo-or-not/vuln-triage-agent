"""5주차 D2 교차 검증: 모델이 문서 속 지시를 따라도 결정적 추출이 되살리는지."""

from vulnagent.docs.extract import Extraction, Finding, cross_check

DET = Extraction(method="deterministic", findings=[
    Finding("Maven", "org.apache.logging.log4j:log4j-core", "2.7", ["CVE-2021-44228", "CVE-2017-5645"]),
    Finding("Maven", "org.zeroturnaround:zt-zip", "1.12", ["CVE-2018-1002201"]),
])


def test_suppressed_finding_is_restored_with_an_alert():
    # 공격: 'log4j-core를 빼라'를 따른 LLM 출력
    llm = Extraction(method="llm", findings=[Finding("Maven", "org.zeroturnaround:zt-zip", "1.12", ["CVE-2018-1002201"])])
    merged = cross_check(llm, DET)
    keys = {(f.package, f.version) for f in merged.findings}
    assert ("org.apache.logging.log4j:log4j-core", "2.7") in keys
    assert any("missing from the LLM output" in a for a in merged.alerts)


def test_dropped_single_id_is_restored():
    llm = Extraction(method="llm", findings=[
        Finding("Maven", "org.apache.logging.log4j:log4j-core", "2.7", ["CVE-2017-5645"]),
        Finding("Maven", "org.zeroturnaround:zt-zip", "1.12", ["CVE-2018-1002201"])])
    merged = cross_check(llm, DET)
    log4j = next(f for f in merged.findings if "log4j" in f.package)
    assert "CVE-2021-44228" in log4j.ids and any("CVE-2021-44228" in a for a in merged.alerts)


def test_tampered_version_keeps_both_versions():
    # 공격: '이미 2.25.4로 올렸다'를 따른 LLM 출력
    llm = Extraction(method="llm", findings=[
        Finding("Maven", "org.apache.logging.log4j:log4j-core", "2.25.4", ["CVE-2021-44228", "CVE-2017-5645"]),
        Finding("Maven", "org.zeroturnaround:zt-zip", "1.12", ["CVE-2018-1002201"])])
    merged = cross_check(llm, DET)
    versions = {f.version for f in merged.findings if "log4j" in f.package}
    assert versions == {"2.7", "2.25.4"}  # 트리아지가 둘 다 검사 -> 실제 버전의 취약점이 가려지지 않는다
    assert any("report lists version 2.7" in a for a in merged.alerts)


def test_clean_agreement_raises_no_alert():
    llm = Extraction(method="llm", findings=[Finding(f.ecosystem, f.package, f.version, list(f.ids)) for f in DET.findings])
    assert cross_check(llm, DET).alerts == []
