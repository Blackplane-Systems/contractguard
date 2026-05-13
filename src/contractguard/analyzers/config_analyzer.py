"""Configuration File Security Analyzer.

Scans YAML, TOML, JSON, and .env config files for dangerous settings:
debug mode, exposed ports, insecure defaults, verbose error pages, etc.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import is_fixture_path, should_skip_large_file, should_skip_path

_SKIP_CONFIG_NAMES = {
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
}


def extract_facts(content: str, filename: str = "") -> dict[str, Any]:
    """Extract security-relevant facts from a config file."""
    facts: dict[str, Any] = {
        "debug_enabled": False,
        "verbose_errors": False,
        "cors_allow_all": False,
        "insecure_secret_key": False,
        "default_password": False,
        "exposed_admin_port": False,
        "ssl_disabled": False,
        "permissive_permissions": False,
        "wildcard_host": False,
        "root_user": False,
        "http_not_https": False,
        "missing_auth": False,
        "dangerous_settings_count": 0,
    }

    lower = content.lower()
    lines = content.splitlines()

    _debug_patterns = [
        r'debug\s*[=:]\s*(?:true|1|yes|on)',
        r'DEBUG\s*=\s*(?:True|1)',
        r'"debug"\s*:\s*true',
    ]
    for p in _debug_patterns:
        if re.search(p, content, re.I):
            facts["debug_enabled"] = True
            facts["dangerous_settings_count"] += 1
            break

    if re.search(r'(?:show_?errors?|display_?errors?|verbose_?errors?)\s*[=:]\s*(?:true|1|yes|on)', content, re.I):
        facts["verbose_errors"] = True
        facts["dangerous_settings_count"] += 1

    if re.search(r'(?:cors|allowed?_?origins?)\s*[=:]\s*[\'"]?\*[\'"]?', content, re.I) or \
       re.search(r'allow_all_origins\s*[=:]\s*(?:true|1)', content, re.I):
        facts["cors_allow_all"] = True
        facts["dangerous_settings_count"] += 1

    weak_secrets = ["changeme", "secret", "password", "12345", "default", "test", "dev", "insecure"]
    if re.search(r'(?:secret_?key|jwt_?secret|app_?secret|signing_?key)\s*[=:]\s*[\'"]?([^\s\'"]+)', content, re.I):
        match = re.search(r'(?:secret_?key|jwt_?secret|app_?secret|signing_?key)\s*[=:]\s*[\'"]?([^\s\'"]+)', content, re.I)
        if match and match.group(1).lower().strip("'\"") in weak_secrets:
            facts["insecure_secret_key"] = True
            facts["dangerous_settings_count"] += 1

    if re.search(r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?(?:admin|password|123456|root|default|test)[\'"]?', content, re.I) or \
       re.search(r'\$\{[^}]*?(?:password|passwd|pwd)[^}]*:-(?:admin|password|postgres|root|default|test)', content, re.I):
        facts["default_password"] = True
        facts["dangerous_settings_count"] += 1

    if re.search(r'(?:host|bind|listen)\s*[=:]\s*[\'"]?0\.0\.0\.0', content, re.I):
        facts["exposed_admin_port"] = True
        facts["dangerous_settings_count"] += 1

    ssl_disabled_lines = [
        line for line in lines
        if re.search(r'(?:ssl|tls|https)[_\w]*\s*[=:]\s*(?:false|0|off|no|disabled)', line, re.I)
    ]
    ssl_disabled_lines = [
        line for line in ssl_disabled_lines
        if not ("smtp" in line.lower() and re.search(r'smtp_use_starttls\s*[=:]\s*(?:true|1|yes|on)', content, re.I))
    ]
    if ssl_disabled_lines:
        facts["ssl_disabled"] = True
        facts["dangerous_settings_count"] += 1

    if re.search(r'(?:allowed_?hosts?|server_?name)\s*[=:]\s*[\'"]?\*', content, re.I):
        facts["wildcard_host"] = True
        facts["dangerous_settings_count"] += 1

    if re.search(r'(?:user|username)\s*[=:]\s*[\'"]?root[\'"]?', content, re.I) or \
       re.search(r'(?:run_?as|user)\s*[=:]\s*[\'"]?0[\'"]?', content, re.I):
        facts["root_user"] = True
        facts["dangerous_settings_count"] += 1

    http_urls = re.findall(r'http://[^\s\'"]+', content)
    localhost_or_local = [u for u in http_urls if "localhost" in u or "127.0.0.1" in u or "0.0.0.0" in u]
    if len(http_urls) > len(localhost_or_local):
        facts["http_not_https"] = True
        facts["dangerous_settings_count"] += 1

    if re.search(r'(?:chmod|permissions?|mode)\s*[=:]\s*[\'"]?(?:777|666)', content, re.I):
        facts["permissive_permissions"] = True
        facts["dangerous_settings_count"] += 1

    return facts


def load_config_files(path: str | Path) -> list[tuple[str, str]]:
    """Load config files from a file or directory."""
    path = Path(path)
    config_exts = {".yaml", ".yml", ".toml", ".json", ".env", ".ini", ".cfg", ".conf", ".properties"}
    config_names = {".env", "config", "settings"}
    files: list[tuple[str, str]] = []

    if path.is_dir():
        for f in sorted(path.rglob("*")):
            if should_skip_path(f) or should_skip_large_file(f) or f.name.casefold() in _SKIP_CONFIG_NAMES:
                continue
            if f.is_file() and (f.suffix.lower() in config_exts or f.stem.lower() in config_names):
                try:
                    files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
                except Exception:
                    continue
    elif path.is_file():
        if should_skip_path(path) or should_skip_large_file(path) or path.name.casefold() in _SKIP_CONFIG_NAMES:
            return files
        try:
            files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            pass
    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run configuration security analysis."""
    files = load_config_files(path)
    rules = load_rules_for_analyzer(rules_dir, "config")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts(content, source)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            f.context = f"Config file: {Path(source).name}"
            if is_fixture_path(source):
                f.confidence = "low"
        all_findings.extend(findings)

    return all_findings
