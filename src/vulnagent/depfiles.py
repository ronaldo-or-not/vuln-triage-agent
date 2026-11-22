"""의존성 파일 파서 (결정적 코드, LLM 아님).

원칙: 정확한 버전이 확정되는 것만 '검사 대상(dependencies)'으로 내보내고, 나머지는 이유와 함께
'검사 불가(unchecked)'로 내보낸다. 버전을 추측하지 않는다. 범위 버전(>=, ^, ~)을 임의로 골라
검사하면 "안전하다"는 거짓 결과가 나올 수 있기 때문이다.

범위(v0): 직접 의존성만. package-lock.json은 수천 개의 전이 의존성을 담고 있지만, 루트가 직접
선언한 패키지의 확정 버전만 읽는다. Maven/Gradle은 lock 파일이 없으면 전이 의존성을 알 수 없다
(예: spring-boot-starter-log4j2 안에 들어 있는 log4j-core). 이 한계는 notes에 남긴다.
"""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str
    scope: str | None = None  # dev / test / provided ...


@dataclass
class Unchecked:
    spec: str
    reason: str


@dataclass
class ParseResult:
    file_type: str
    ecosystem: str
    dependencies: list[Dependency] = field(default_factory=list)
    unchecked: list[Unchecked] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_file(path: str | Path, companion: str | Path | None = None) -> ParseResult:
    """companion: package-lock v1에는 package.json, Maven 모듈 pom에는 부모 pom 경로."""
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    companion_text = Path(companion).read_text(encoding="utf-8", errors="replace") if companion else None
    name = path.name.lower()
    if name == "package-lock.json":
        return parse_package_lock(text, companion_text)
    if name == "package.json":
        return parse_package_json(text)
    if name.endswith("pom.xml"):
        return parse_pom(text, companion_text)
    if name.endswith(".gradle"):
        return parse_gradle(text)
    if name.endswith(".txt"):
        return parse_requirements(text)
    raise ValueError(f"unsupported dependency file: {path.name}")


# ------------------------------------------------------------------ PyPI: requirements.txt
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(text: str) -> ParseResult:
    result = ParseResult("requirements.txt", "PyPI")
    # 줄 끝 '\'는 다음 줄과 이어진다 (pip-compile --generate-hashes 출력 등)
    logical = re.sub(r"\\\r?\n", " ", text).splitlines()
    for raw in logical:
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()  # 주석 제거 (URL 안의 #은 공백 뒤가 아니라 보존)
        if not line:
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            result.unchecked.append(Unchecked(line, "references another requirements file that was not provided"))
            continue
        if line.startswith(("-e ", "--editable")) or "git+" in line or "://" in line:
            result.unchecked.append(Unchecked(line, "VCS/URL/editable dependency has no registry version"))
            continue
        if line.startswith("-"):
            result.notes.append(f"ignored pip option: {line.split()[0]}")
            continue
        line = re.sub(r"\s--hash[= ]\S+", "", line)
        spec_part, _, marker = line.partition(";")
        m = _REQ_NAME.match(spec_part.strip())
        if not m:
            result.unchecked.append(Unchecked(line, "could not parse requirement"))
            continue
        name, _extras, spec = m.group(1), m.group(2), m.group(3).replace(" ", "")
        exact = re.fullmatch(r"===?([A-Za-z0-9][A-Za-z0-9._+!-]*)", spec)
        if exact and "*" not in exact.group(1):
            result.dependencies.append(Dependency("PyPI", name, exact.group(1)))
            if marker.strip():
                result.notes.append(f"{name}: environment marker '{marker.strip()}' ignored (checked anyway)")
        elif not spec:
            result.unchecked.append(Unchecked(spec_part.strip(), "not pinned: no version specified"))
        else:
            result.unchecked.append(Unchecked(spec_part.strip(), f"not pinned to one exact version ({spec})"))
    return result


# ------------------------------------------------------------------ npm
_EXACT_SEMVER = re.compile(r"^v?=?\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def _npm_sections(manifest: dict):
    for key, scope in (("dependencies", None), ("devDependencies", "dev"), ("optionalDependencies", "optional")):
        for name, spec in (manifest.get(key) or {}).items():
            yield name, str(spec), scope


def parse_package_json(text: str) -> ParseResult:
    result = ParseResult("package.json", "npm")
    manifest = json.loads(text)
    for name, spec, scope in _npm_sections(manifest):
        m = _EXACT_SEMVER.match(spec.strip())
        if m:
            result.dependencies.append(Dependency("npm", name, m.group(1), scope))
        else:
            result.unchecked.append(Unchecked(f"{name}@{spec}", f"version range '{spec}' and no lockfile to resolve it"))
    return result


def parse_package_lock(text: str, package_json_text: str | None = None) -> ParseResult:
    result = ParseResult("package-lock.json", "npm")
    lock = json.loads(text)
    version = lock.get("lockfileVersion", 1)
    packages = lock.get("packages")
    if packages and "" in packages:  # lockfile v2 / v3
        root = packages[""]
        for name, spec, scope in _npm_sections(root):
            entry = packages.get(f"node_modules/{name}")
            if entry is None:
                result.unchecked.append(Unchecked(f"{name}@{spec}", "declared in package.json but not found in the lockfile"))
            elif entry.get("link"):
                result.unchecked.append(Unchecked(f"{name}@{spec}", "local link (workspace/file dependency)"))
            elif not entry.get("version") or not _EXACT_SEMVER.match(entry["version"]):
                result.unchecked.append(Unchecked(f"{name}@{spec}", f"lockfile has no registry version ({entry.get('version')})"))
            else:
                # npm 별칭 ("foo": "npm:bar@1.0")이면 실제 패키지 이름은 entry["name"]
                result.dependencies.append(Dependency("npm", entry.get("name", name), entry["version"], scope))
        result.notes.append(f"lockfileVersion {version}: {len(packages) - 1} packages in total, only direct dependencies checked")
        return result
    # lockfile v1: 평평한 dependencies 목록이라 직접/전이 구분은 package.json이 있어야 가능
    deps = lock.get("dependencies") or {}
    if package_json_text is None:
        result.notes.append("lockfileVersion 1 without package.json: cannot tell direct from transitive dependencies")
        return result
    for name, spec, scope in _npm_sections(json.loads(package_json_text)):
        entry = deps.get(name)
        if entry and entry.get("version") and _EXACT_SEMVER.match(entry["version"]):
            result.dependencies.append(Dependency("npm", name, entry["version"], scope))
        else:
            result.unchecked.append(Unchecked(f"{name}@{spec}", "not resolved in lockfile v1"))
    return result


# ------------------------------------------------------------------ Maven: pom.xml
def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: ET.Element | None, path: str) -> str | None:
    found = el.find(path) if el is not None else None
    return found.text.strip() if found is not None and found.text else None


def _pom_props_and_managed(root: ET.Element) -> tuple[dict, dict]:
    properties = root.find("properties")
    props = {child.tag: (child.text or "").strip() for child in (properties if properties is not None else [])}
    managed = {
        f"{_text(dep, 'groupId')}:{_text(dep, 'artifactId')}": _text(dep, "version")
        for dep in root.findall("dependencyManagement/dependencies/dependency")
    }
    return props, managed


def parse_pom(text: str, parent_text: str | None = None) -> ParseResult:
    result = ParseResult("pom.xml", "Maven")
    root = ET.fromstring(text)
    _strip_ns(root)
    parent = root.find("parent")
    props, managed = _pom_props_and_managed(root)
    parent_provided = False
    if parent_text:
        # 부모 pom이 함께 주어지면 그 속성과 버전 관리(dependencyManagement)를 물려받는다 (자식이 우선)
        parent_root = ET.fromstring(parent_text)
        _strip_ns(parent_root)
        parent_props, parent_managed = _pom_props_and_managed(parent_root)
        props = {**parent_props, **props}
        managed = {**parent_managed, **managed}
        if _text(parent_root, "version"):
            props.setdefault("project.parent.version", _text(parent_root, "version"))
        parent_provided = True
    project_version = _text(root, "version") or _text(parent, "version")
    if project_version:
        props.setdefault("project.version", project_version)
        props.setdefault("version", project_version)
    if parent is not None and _text(parent, "version"):
        props.setdefault("project.parent.version", _text(parent, "version"))

    def resolve(value: str | None) -> str | None:
        for _ in range(5):  # ${a} -> ${b} -> 값 (순환 방지로 5단계까지)
            if value is None or "${" not in value:
                return value
            value = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)
        return value

    parent_desc = None
    if parent is not None:
        parent_desc = f"{_text(parent, 'groupId')}:{_text(parent, 'artifactId')}:{_text(parent, 'version')}"
        if parent_provided:
            result.notes.append(f"parent POM {parent_desc} provided: its properties and managed versions were applied")
        else:
            result.notes.append(f"parent POM {parent_desc} is not resolved (its managed versions and dependencies are unknown)")
    modules = [m.text for m in root.findall("modules/module") if m.text]
    if modules:
        result.notes.append(f"{len(modules)} module POM(s) not included: {', '.join(modules)}")
    result.notes.append("Maven: direct dependencies only; transitive dependencies need a resolved dependency tree")

    for dep in root.findall("dependencies/dependency"):
        group, artifact = resolve(_text(dep, "groupId")), resolve(_text(dep, "artifactId"))
        name = f"{group}:{artifact}"
        scope = _text(dep, "scope")
        raw_version = _text(dep, "version") or managed.get(name)
        version = resolve(raw_version)
        if version is None:
            reason = f"version managed by parent {parent_desc}" if parent_desc else "no version declared"
            result.unchecked.append(Unchecked(name, reason))
        elif "${" in version:
            result.unchecked.append(Unchecked(f"{name}:{raw_version}", "version property could not be resolved in this POM"))
        elif version[:1] in "[(":
            result.unchecked.append(Unchecked(f"{name}:{version}", "version range"))
        else:
            result.dependencies.append(Dependency("Maven", name, version, scope))
    return result


# ------------------------------------------------------------------ Gradle: build.gradle
_GRADLE_CONFIGS = (
    "implementation|api|compile|compileOnly|runtimeOnly|runtime|testImplementation|testCompile|"
    "testRuntimeOnly|annotationProcessor|developmentOnly|providedCompile|providedRuntime"
)
_GRADLE_STRING = re.compile(
    rf"\b({_GRADLE_CONFIGS})\b\s*\(?\s*['\"]([^'\":\s]+):([^'\":\s]+)(?::([^'\"@\s]+))?(?:@\w+)?['\"]"
)
_GRADLE_MAP = re.compile(
    rf"\b({_GRADLE_CONFIGS})\b\s*\(?\s*group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*:\s*['\"]([^'\"]+)['\"]"
    r"(?:\s*,\s*version\s*:\s*['\"]([^'\"]+)['\"])?"
)


def parse_gradle(text: str) -> ParseResult:
    result = ParseResult("build.gradle", "Maven")
    code = re.sub(r"//.*", "", text)
    for regex in (_GRADLE_STRING, _GRADLE_MAP):
        for m in regex.finditer(code):
            config, group, artifact, version = m.groups()
            name = f"{group}:{artifact}"
            scope = "test" if config.startswith("test") else None
            if not version:
                result.unchecked.append(Unchecked(name, "no version: managed by a BOM or the Spring dependency-management plugin"))
            elif "$" in version:
                result.unchecked.append(Unchecked(f"{name}:{version}", "version comes from a build variable"))
            else:
                result.dependencies.append(Dependency("Maven", name, version, scope))
    plugin = re.search(r"id\s+['\"]org\.springframework\.boot['\"]\s+version\s+['\"]([^'\"]+)['\"]", code)
    if plugin:
        result.notes.append(f"Spring Boot plugin {plugin.group(1)} manages versions of starters and their transitive dependencies")
    result.notes.append("Gradle: direct dependencies only; transitive dependencies need a resolved dependency tree")
    return result
