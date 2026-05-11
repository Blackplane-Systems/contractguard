"""Secrets & Credential Leak Detector.

Scans any text file for hardcoded API keys, passwords, tokens, private keys,
and other secrets using pattern matching. This is a security-critical analyzer.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import should_skip_path

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key", re.compile(r"(?:^|[^A-Za-z0-9/+=])(?:AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)"), "block"),
    ("aws_secret_key", re.compile(r"(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), "block"),
    ("github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "block"),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"), "block"),
    ("generic_api_key", re.compile(r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.I), "critical"),
    ("generic_secret", re.compile(r"(?:secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?", re.I), "critical"),
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
            if match:
                facts["secret_count"] += 1
                # Redact the match for safety — show only first/last 4 chars
                matched = match.group(0)
                if len(matched) > 12:
                    preview = matched[:4] + "****" + matched[-4:]
                else:
                    preview = "****"
                facts["secrets_found"].append((pattern_name, line_num, preview))

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
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix.lower() not in _SKIP_EXTENSIONS and not should_skip_path(f):
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    files.append((str(f), content))
                except Exception:
                    continue
    elif path.is_file():
        if should_skip_path(path):
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

        # Also generate direct findings for each secret found (bypass rule engine)
        for pattern_name, line_num, preview in facts["secrets_found"]:
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
                attack_vector=f"Attacker clones repo → extracts {pattern_name.replace('_', ' ')} → gains unauthorized access",
                cwe="CWE-798",
            )
            all_findings.append(finding)

        all_findings.extend(findings)

    return all_findings
