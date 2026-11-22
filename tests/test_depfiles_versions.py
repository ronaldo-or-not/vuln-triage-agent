"""파서와 버전 계산 테스트. 정답이 알려진 사례(log4j 공식 권고의 수정 버전)로 고정한다."""

import json

from vulnagent.depfiles import parse_gradle, parse_package_json, parse_package_lock, parse_pom, parse_requirements
from vulnagent.ids import normalize_package_name
from vulnagent.versions import compare, fix_for_package, fix_for_range, sort_versions


def test_requirements_only_exact_pins_are_checked():
    r = parse_requirements(
        "# comment\nDjango==1.11.7\nrequests>=2.0\nflask\nJinja2[i18n] == 2.10 ; python_version < '3.8'\n"
        "-r base.txt\ngit+https://github.com/x/y.git#egg=y\npkg==1.*\nfoo==1.0 \\\n    --hash=sha256:abc\n"
    )
    assert [(d.name, d.version) for d in r.dependencies] == [("Django", "1.11.7"), ("Jinja2", "2.10"), ("foo", "1.0")]
    reasons = {u.spec.split()[0]: u.reason for u in r.unchecked}
    assert "not pinned to one exact version" in reasons["requests>=2.0"]
    assert "no version specified" in reasons["flask"]
    assert "another requirements file" in reasons["-r"]
    assert "VCS" in reasons["git+https://github.com/x/y.git#egg=y"]
    assert "pkg==1.*" in reasons


def test_package_lock_v2_reads_only_direct_dependencies():
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"express": "^4.0.0", "alias": "npm:lodash@4.17.15"}, "devDependencies": {"mocha": "^9"}},
            "node_modules/express": {"version": "4.16.0"},
            "node_modules/alias": {"name": "lodash", "version": "4.17.15"},
            "node_modules/mocha": {"version": "9.2.0", "dev": True},
            "node_modules/qs": {"version": "6.5.1"},
        },
    }
    r = parse_package_lock(json.dumps(lock))
    assert [(d.name, d.version, d.scope) for d in r.dependencies] == [
        ("express", "4.16.0", None), ("lodash", "4.17.15", None), ("mocha", "9.2.0", "dev")
    ]


def test_package_json_ranges_are_unchecked():
    r = parse_package_json(json.dumps({"dependencies": {"a": "1.2.3", "b": "^1.2.3", "c": "latest"}}))
    assert [d.name for d in r.dependencies] == ["a"]
    assert {u.spec for u in r.unchecked} == {"b@^1.2.3", "c@latest"}


def test_pom_resolves_properties_and_flags_parent_managed_versions():
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
      <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.6.3</version></parent>
      <properties><log4j.version>2.14.1</log4j.version></properties>
      <dependencies>
        <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
        <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
        <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${missing}</version></dependency>
      </dependencies></project>"""
    r = parse_pom(pom)
    assert [(d.name, d.version) for d in r.dependencies] == [("org.apache.logging.log4j:log4j-core", "2.14.1")]
    assert "managed by parent org.springframework.boot:spring-boot-starter-parent:2.6.3" in r.unchecked[0].reason
    assert "could not be resolved" in r.unchecked[1].reason


def test_gradle_string_notation():
    r = parse_gradle(
        "implementation 'org.springframework.boot:spring-boot-starter-log4j2:2.6.1'\n"
        "implementation('org.springframework.boot:spring-boot-starter-web') { exclude group: 'x' }\n"
        "testImplementation \"junit:junit:4.12\"\n"
    )
    assert [(d.name, d.version, d.scope) for d in r.dependencies] == [
        ("org.springframework.boot:spring-boot-starter-log4j2", "2.6.1", None), ("junit:junit", "4.12", "test")
    ]
    assert r.unchecked[0].spec == "org.springframework.boot:spring-boot-starter-web"


def test_version_comparison_is_not_lexicographic():
    assert sort_versions(["2.12.2", "2.15.0", "2.3.1"], "Maven") == ["2.3.1", "2.12.2", "2.15.0"]
    assert compare("2.0-beta9", "2.0", "Maven") < 0
    assert compare("1.0.11.RELEASE", "1.0.11", "Maven") == 0
    assert compare("2.0", "2.0.0", "Maven") == 0
    assert compare("1.0.0-rc.1", "1.0.0", "npm") < 0


# log4j-core CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q)의 실제 범위
LOG4SHELL_EVENTS = [
    {"introduced": "2.13.0"}, {"fixed": "2.15.0"},
    {"introduced": "2.4"}, {"fixed": "2.12.2"},
    {"introduced": "2.0-beta9"}, {"fixed": "2.3.1"},
]


def test_fix_is_taken_from_the_range_that_contains_the_installed_version():
    assert fix_for_range("2.14.1", LOG4SHELL_EVENTS, "Maven") == ("fixed", "2.15.0")
    assert fix_for_range("2.10.0", LOG4SHELL_EVENTS, "Maven") == ("fixed", "2.12.2")
    assert fix_for_range("2.15.0", LOG4SHELL_EVENTS, "Maven") == ("not_affected", None)
    assert fix_for_range("1.2.17", [{"introduced": "0"}, {"last_affected": "1.2.17"}], "Maven") == ("no_fix", None)


def test_fix_for_package_matches_names_with_ecosystem_rules():
    record = {"affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}
    match = lambda n: normalize_package_name("PyPI", n) == normalize_package_name("PyPI", "Jinja2")
    assert fix_for_package("2.10", record, "PyPI", match) == ("fixed", "2.10.1")
