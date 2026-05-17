"""Secrets & Credential Leak Detector.

Scans any text file for hardcoded API keys, passwords, tokens, private keys,
and other secrets using pattern matching. This is a security-critical analyzer.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import (
    has_inline_ignore,
    is_documentation_file,
    is_fixture_path,
    is_source_file,
    should_skip_large_file,
    should_skip_path,
)

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key", re.compile(r"(?:^|[^A-Za-z0-9/+=])(?:AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)"), "block"),
    ("aws_secret_key", re.compile(r"(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), "block"),
    ("github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "block"),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"), "block"),
    ("generic_api_key", re.compile(r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.I), "critical"),
    ("generic_secret", re.compile(r"(?:secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?", re.I), "critical"),
    ("smtp_app_password", re.compile(r"(?:smtp[_-]?password|gmail[_-]?app[_-]?password)\s*[=:]\s*['\"]?([a-z]{4}\s+[a-z]{4}\s+[a-z]{4}\s+[a-z]{4})['\"]?", re.I), "critical"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "block"),
    ("stripe_key", re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"), "block"),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "block"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "critical"),
    ("gcp_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "block"),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"'), "critical"),
    ("database_url", re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", re.I), "block"),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "critical"),
    ("heroku_api_key", re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "warning"),
    ("high_entropy_assignment", re.compile(r"(?:KEY|SECRET|TOKEN|PASS|CREDENTIAL|AUTH)\s*[=:]\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", re.I), "critical"),
    ("env_secret", re.compile(r"^[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\s*=\s*['\"]?([^\s'\"]{8,})['\"]?", re.I | re.MULTILINE), "critical"),
    ("ssh_private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "block"),
    ("npm_token", re.compile(r"//registry\.npmjs\.org/:_authToken=[^\s]+"), "block"),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "block"),
    ("twilio_key", re.compile(r"SK[0-9a-fA-F]{32}"), "critical"),
]

# These file extensions are always skipped (binary / not useful)
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
    ".pdf", ".doc", ".docx",
}

_PLACEHOLDER_TOKENS = {
    "changeme",
    "change_me",
    "change-me",
    "dummy",
    "example",
    "fake",
    "not_a_real",
    "not-real",
    "placeholder",
    "replace",
    "sample",
    "test",
    "todo",
    "value",
    "your-",
    "your_",
}

_CODE_VALUE_PREFIXES = (
    "await ",
    "function",
    "header",
    "process.",
    "request.",
    "this.",
    "verify",
)


def _extract_match_value(match: re.Match[str]) -> str:
    if match.lastindex:
        for index in range(match.lastindex, 0, -1):
            value = match.group(index)
            if value:
                return value.strip().strip("'\"")
    return match.group(0).strip().strip("'\"")


def _looks_like_pattern_definition(line: str) -> bool:
    lowered = line.casefold()
    return "re.compile" in lowered or "regexp" in lowered or "regex" in lowered or "_patterns" in lowered


def _looks_like_code_expression(value: str) -> bool:
    lowered = value.strip().casefold()
    if lowered.startswith(_CODE_VALUE_PREFIXES):
        return True
    if "(" in value or ")" in value or "=>" in value or "${" in value or "}" in value:
        return True
    if "?." in value or value.endswith(".") or value.endswith(","):
        return True
    return False


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.casefold()
    if any(token in lowered for token in _PLACEHOLDER_TOKENS):
        return True
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if compact in {"admin", "admin123", "password", "password123", "secret", "token"}:
        return True
    if len(set(compact)) <= 2 and len(compact) >= 8:
        return True
    return False


def _is_plausible_secret(pattern_name: str, match: re.Match[str], line: str, filename: str) -> bool:
    if has_inline_ignore(line):
        return False
    if pattern_name == "heroku_api_key" and not re.search(r"\b(?:heroku|api[_-]?key|token|credential)\b", line, re.I):
        return False
    if pattern_name in {"private_key", "ssh_private_key"} and _looks_like_pattern_definition(line):
        return False
    if pattern_name in {"generic_api_key", "generic_secret", "env_secret", "high_entropy_assignment"}:
        value = _extract_match_value(match)
        if _looks_like_code_expression(value):
            return False
        if is_source_file(filename) and not _looks_like_placeholder(value):
            # Source assignments often reference variables/functions rather than literals.
            if not re.search(r"['\"][A-Za-z0-9_./+=:-]{16,}['\"]", line):
                return False
    return True


def _confidence_for_secret(pattern_name: str, match: re.Match[str], line: str, filename: str) -> str:
    if pattern_name in {
        "aws_access_key",
        "aws_secret_key",
        "database_url",
        "github_fine_grained",
        "github_token",
        "gcp_api_key",
        "npm_token",
        "private_key",
        "sendgrid_key",
        "slack_token",
        "slack_webhook",
        "smtp_app_password",
        "ssh_private_key",
        "stripe_key",
    }:
        base = "high"
    else:
        base = "medium"

    value = _extract_match_value(match)
    if is_fixture_path(filename):
        return "low"
    if is_documentation_file(filename) and _looks_like_placeholder(value):
        return "low"
    if _looks_like_placeholder(value):
        return "low"
    return base


def extract_facts(content: str, filename: str = "") -> dict[str, Any]:
    """Scan text content for secret patterns and build facts dict."""
    facts: dict[str, Any] = {
        "secret_count": 0,
        "has_aws_key": False,
        "has_private_key": False,
        "has_api_key": False,
        "has_database_url": False,
        "has_jwt": False,
        "has_generic_secret": False,
        "has_high_entropy": False,
        "secrets_found": [],  # list of (pattern_name, line_num, matched_text_preview)
        "secret_items": [],  # list of (pattern_name, line_num, preview, confidence)
        "max_severity": "info",
    }

    severity_order = {"info": 0, "warning": 1, "critical": 2, "block": 3}
    max_sev = 0

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        # Skip comment-only lines that are documenting patterns, not containing them
        if stripped.startswith("#") and "example" in stripped.lower():
            continue

        for pattern_name, regex, sev_hint in _SECRET_PATTERNS:
            match = regex.search(line)
            if match and _is_plausible_secret(pattern_name, match, line, filename):
                facts["secret_count"] += 1
                # Redact the match for safety - show only first/last 4 chars
                matched = _extract_match_value(match)
                if len(matched) > 12:
                    preview = matched[:4] + "****" + matched[-4:]
                else:
                    preview = "****"
                confidence = _confidence_for_secret(pattern_name, match, line, filename)
                facts["secrets_found"].append((pattern_name, line_num, preview))
                facts["secret_items"].append((pattern_name, line_num, preview, confidence))

                if "aws" in pattern_name:
                    facts["has_aws_key"] = True
                if "private_key" in pattern_name or "ssh" in pattern_name:
                    facts["has_private_key"] = True
                if "api_key" in pattern_name or "generic_api" in pattern_name:
                    facts["has_api_key"] = True
                if "database_url" in pattern_name:
                    facts["has_database_url"] = True
                if "jwt" in pattern_name:
                    facts["has_jwt"] = True
                if "generic_secret" in pattern_name or "env_secret" in pattern_name:
                    facts["has_generic_secret"] = True
                if "high_entropy" in pattern_name:
                    facts["has_high_entropy"] = True

                sev_val = severity_order.get(sev_hint, 0)
                if sev_val > max_sev:
                    max_sev = sev_val

    sev_names = {v: k for k, v in severity_order.items()}
    facts["max_severity"] = sev_names.get(max_sev, "info")

    return facts


def load_files(path: str | Path) -> list[tuple[str, str]]:
    """Load text files from a file or directory for scanning."""
    path = Path(path)
    files: list[tuple[str, str]] = []

    if path.is_dir():
        for root, dirnames, filenames in os.walk(path):
            root_path = Path(root)
            dirnames[:] = [
                name for name in dirnames if not should_skip_path(root_path / name)
            ]
            for name in sorted(filenames):
                file_path = root_path / name
                if (
                    file_path.suffix.lower() in _SKIP_EXTENSIONS
                    or should_skip_large_file(file_path)
                    or should_skip_path(file_path)
                ):
                    continue
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    files.append((str(file_path), content))
                except Exception:
                    continue
    elif path.is_file():
        if should_skip_large_file(path) or should_skip_path(path):
            return files
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            files.append((str(path), content))
        except Exception:
            pass

    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run secrets analysis on files at *path*."""
    files = load_files(path)
    rules = load_rules_for_analyzer(rules_dir, "secrets")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts(content, source)

        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            if is_fixture_path(source) or is_documentation_file(source):
                f.confidence = "low"

        all_findings.extend(findings)

        # Also generate direct findings for each secret found (bypass rule engine)
        for pattern_name, line_num, preview, confidence in facts["secret_items"]:
            sev_map = {n: s for n, _, s in _SECRET_PATTERNS for n2 in [n] if n2 == pattern_name}
            sev_str = sev_map.get(pattern_name, "critical")
            try:
                sev = Severity(sev_str)
            except ValueError:
                sev = Severity.CRITICAL

            finding = Finding(
                rule_id=f"SEC-{pattern_name.upper()[:8]}",
                rule_name=pattern_name,
                severity=sev,
                description=f"Detected {pattern_name.replace('_', ' ')} in source code.",
                explanation=f"Line {line_num}: matched {pattern_name} pattern",
                suggestion=f"Remove the secret, rotate it immediately, and use environment variables or a vault.",
                location=f"{source}:{line_num}",
                context=preview,
                attack_vector=f"Attacker clones repo -> extracts {pattern_name.replace('_', ' ')} -> gains unauthorized access",
                cwe="CWE-798",
                confidence=confidence,
            )
            all_findings.append(finding)

    return all_findings
