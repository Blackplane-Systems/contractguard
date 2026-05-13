"""Dependency Vulnerability Scanner.

Scans requirements.txt / pyproject.toml for known vulnerable package versions.
Uses a local database — no internet required. Similar to pip-audit but self-contained.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import is_fixture_path

# Local vulnerability database — curated set of high-profile CVEs
# Format: (package, operator, version, cve, severity, description)
_VULN_DB: list[tuple[str, str, str, str, str, str]] = [
    ("django", "<", "4.2.7", "CVE-2023-46695", "critical", "DoS via file upload handler"),
    ("django", "<", "3.2.23", "CVE-2023-46695", "critical", "DoS via file upload handler"),
    ("flask", "<", "2.3.2", "CVE-2023-30861", "warning", "Session cookie vulnerability"),
    ("requests", "<", "2.31.0", "CVE-2023-32681", "warning", "Proxy-Authorization header leak"),
    ("urllib3", "<", "2.0.7", "CVE-2023-45803", "warning", "Request body not stripped on redirect"),
    ("urllib3", "<", "1.26.18", "CVE-2023-45803", "warning", "Request body not stripped on redirect"),
    ("certifi", "<", "2023.7.22", "CVE-2023-37920", "critical", "Removal of e-Tugra root certificate"),
    ("cryptography", "<", "41.0.6", "CVE-2023-49083", "critical", "NULL pointer dereference in PKCS12"),
    ("pillow", "<", "10.0.1", "CVE-2023-44271", "warning", "DoS via uncontrolled resource consumption"),
    ("jinja2", "<", "3.1.3", "CVE-2024-22195", "critical", "XSS via xmlattr filter"),
    ("numpy", "<", "1.22.0", "CVE-2021-41496", "warning", "Buffer overflow in array_from_pyobj"),
    ("sqlparse", "<", "0.4.4", "CVE-2023-30608", "warning", "ReDoS via crafted SQL"),
    ("aiohttp", "<", "3.9.0", "CVE-2023-49081", "critical", "HTTP request smuggling"),
    ("fastapi", "<", "0.109.0", "CVE-2024-24762", "warning", "DoS via multipart form data"),
    ("werkzeug", "<", "3.0.1", "CVE-2023-46136", "critical", "DoS via large multipart boundary"),
    ("tornado", "<", "6.4", "CVE-2023-28370", "warning", "Open redirect vulnerability"),
    ("paramiko", "<", "3.4.0", "CVE-2023-48795", "critical", "Terrapin SSH prefix truncation attack"),
    ("setuptools", "<", "65.5.1", "CVE-2022-40897", "warning", "ReDoS in package_index"),
    ("pip", "<", "23.3", "CVE-2023-5752", "info", "Dependency confusion via --extra-index-url"),
    ("starlette", "<", "0.36.2", "CVE-2024-24762", "warning", "DoS via multipart body"),
    ("twisted", "<", "23.10.0", "CVE-2023-46137", "critical", "HTTP request smuggling"),
    ("ansible", "<", "8.5.0", "CVE-2023-5764", "critical", "Template injection in tasks"),
    ("gunicorn", "<", "22.0.0", "CVE-2024-1135", "critical", "HTTP request smuggling via transfer-encoding"),
    ("lxml", "<", "4.9.3", "CVE-2022-2309", "warning", "NULL pointer dereference"),
]

_NPM_VULN_DB: list[tuple[str, str, str, str, str, str]] = [
    ("lodash", "<", "4.17.21", "CVE-2021-23337", "critical", "Command injection via template"),
    ("minimist", "<", "1.2.6", "CVE-2021-44906", "critical", "Prototype pollution"),
    ("follow-redirects", "<", "1.15.6", "CVE-2024-28849", "warning", "Authorization header leak"),
    ("semver", "<", "7.5.2", "CVE-2022-25883", "warning", "Regular expression denial of service"),
]


def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    clean = re.sub(r"^[~^>=<!=]+", "", version_str.strip())
    parts = []
    for p in clean.split("."):
        m = re.match(r"(\d+)", p)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)
    return tuple(parts)


def _version_matches(installed: str, op: str, vuln_version: str) -> bool:
    """Check if installed version is affected."""
    installed_t = _parse_version(installed)
    vuln_t = _parse_version(vuln_version)
    if op == "<":
        return installed_t < vuln_t
    if op == "<=":
        return installed_t <= vuln_t
    if op == "==":
        return installed_t == vuln_t
    return False


def _normalize_package_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _empty_facts() -> dict[str, Any]:
    return {
        "vulnerable_count": 0,
        "total_packages": 0,
        "unpinned_count": 0,
        "vulnerabilities": [],  # list of (pkg, version, cve, severity, desc)
        "has_vulnerable_packages": False,
        "has_unpinned_packages": False,
        "critical_vuln_count": 0,
    }


def _record_unpinned(facts: dict[str, Any]) -> None:
    facts["unpinned_count"] += 1
    facts["has_unpinned_packages"] = True


def _record_vulnerability(
    facts: dict[str, Any],
    package: str,
    version: str,
    advisory: str,
    severity: str,
    description: str,
) -> None:
    facts["vulnerable_count"] += 1
    facts["has_vulnerable_packages"] = True
    facts["vulnerabilities"].append((package, version, advisory, severity, description))
    if severity == "critical":
        facts["critical_vuln_count"] += 1


def _check_vulnerability_db(
    facts: dict[str, Any],
    package_name: str,
    package_version: str,
    db: list[tuple[str, str, str, str, str, str]],
) -> None:
    normalized = _normalize_package_name(package_name)
    for vuln_pkg, op, vuln_ver, advisory, severity, desc in db:
        if normalized == _normalize_package_name(vuln_pkg) and _version_matches(package_version, op, vuln_ver):
            _record_vulnerability(facts, package_name, package_version, advisory, severity, desc)


def extract_facts_from_requirements(content: str) -> dict[str, Any]:
    """Parse requirements.txt and check against vulnerability database."""
    facts = _empty_facts()

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue

        facts["total_packages"] += 1

        # Parse package==version, package>=version, package~=version, or just package.
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:(==|>=|<=|~=|!=|>|<)\s*(\S+))?", stripped)
        if not m:
            continue

        pkg_name = m.group(1)
        operator = m.group(2)
        pkg_version = m.group(3)

        if not pkg_version or operator != "==":
            _record_unpinned(facts)
            continue

        _check_vulnerability_db(facts, pkg_name, pkg_version, _VULN_DB)

    return facts


def extract_facts_from_pyproject(content: str) -> dict[str, Any]:
    facts = _empty_facts()
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return facts

    dependencies: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        project_deps = project.get("dependencies", [])
        if isinstance(project_deps, list):
            dependencies.extend(str(item) for item in project_deps)
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for items in optional.values():
                if isinstance(items, list):
                    dependencies.extend(str(item) for item in items)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(poetry_deps, dict):
        for name, version in poetry_deps.items():
            if name.lower() != "python":
                dependencies.append(f"{name}=={version}" if isinstance(version, str) else name)

    return extract_facts_from_requirements("\n".join(dependencies))


def extract_facts_from_package_json(content: str, locked: bool = False) -> dict[str, Any]:
    facts = _empty_facts()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return facts

    packages: dict[str, str] = {}
    if locked and isinstance(data.get("packages"), dict):
        for package_path, meta in data["packages"].items():
            if not package_path.startswith("node_modules/") or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                packages[package_path.removeprefix("node_modules/")] = version
    else:
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    if isinstance(version, str):
                        packages[name] = version

    for package, raw_version in packages.items():
        facts["total_packages"] += 1
        pinned = locked or re.match(r"^\d+(?:\.\d+){1,3}", raw_version.strip()) is not None
        clean_version = re.sub(r"^[~^=v<> ]+", "", raw_version.strip())
        if not pinned:
            _record_unpinned(facts)
            continue
        _check_vulnerability_db(facts, package, clean_version, _NPM_VULN_DB)

    return facts


def _merge_facts(items: list[dict[str, Any]]) -> dict[str, Any]:
    merged = _empty_facts()
    for facts in items:
        merged["vulnerable_count"] += facts["vulnerable_count"]
        merged["total_packages"] += facts["total_packages"]
        merged["unpinned_count"] += facts["unpinned_count"]
        merged["critical_vuln_count"] += facts["critical_vuln_count"]
        merged["vulnerabilities"].extend(facts["vulnerabilities"])
    merged["has_vulnerable_packages"] = merged["vulnerable_count"] > 0
    merged["has_unpinned_packages"] = merged["unpinned_count"] > 0
    return merged


def extract_facts_from_dependency_file(filename: str, content: str) -> dict[str, Any]:
    name = Path(filename).name.lower()
    if name == "pyproject.toml":
        return extract_facts_from_pyproject(content)
    if name == "package-lock.json":
        return extract_facts_from_package_json(content, locked=True)
    if name == "package.json":
        return extract_facts_from_package_json(content, locked=False)
    return extract_facts_from_requirements(content)


def load_dependency_files(path: str | Path) -> list[tuple[str, str]]:
    """Load dependency files."""
    path = Path(path)
    files: list[tuple[str, str]] = []
    dep_names = {
        "constraints.txt",
        "package-lock.json",
        "package.json",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements_dev.txt",
        "requirements.in",
        "requirements.txt",
    }

    if path.is_dir():
        has_npm_lock = (path / "package-lock.json").exists()
        for name in sorted(dep_names):
            if name == "package.json" and has_npm_lock:
                continue
            f = path / name
            if f.exists():
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        for f in sorted(path.glob("requirements*.txt")):
            if str(f) not in [x[0] for x in files]:
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
    elif path.is_file():
        files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))

    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run dependency vulnerability analysis."""
    files = load_dependency_files(path)
    rules = load_rules_for_analyzer(rules_dir, "deps")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts_from_dependency_file(source, content)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            if is_fixture_path(source):
                f.confidence = "low"
        all_findings.extend(findings)

        # Direct findings for each vulnerability
        for pkg, ver, cve, sev, desc in facts["vulnerabilities"]:
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.WARNING

            finding = Finding(
                rule_id=cve,
                rule_name=f"vuln_{pkg}",
                severity=severity,
                description=f"{pkg}=={ver}: {desc}",
                explanation=f"Installed version {ver} is affected by {cve}",
                suggestion=f"Upgrade {pkg} to the latest patched version. Run: pip install --upgrade {pkg}",
                location=source,
                context=f"{pkg}=={ver}",
                attack_vector=f"Exploiting {cve} in {pkg} {ver} - {desc}",
                cwe="CWE-1035",
                confidence="low" if is_fixture_path(source) else "high",
            )
            all_findings.append(finding)

    return all_findings
