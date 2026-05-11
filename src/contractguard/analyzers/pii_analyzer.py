"""PII (Personally Identifiable Information) Detector.

Scans JSON payloads, CSV files, and text files for data that looks like
personal information: SSNs, credit card numbers, phone numbers, emails, DOBs.

Relevant for GDPR, CCPA, HIPAA compliance — a strong cybersecurity/privacy angle.
"""

from __future__ import annotations

import ipaddress
import json
import re
import os
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import should_skip_path

_PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "Social Security Number"),
    ("credit_card_visa", re.compile(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "Visa credit card number"),
    ("credit_card_mc", re.compile(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "Mastercard number"),
    ("credit_card_amex", re.compile(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b"), "AmEx card number"),
    ("phone_us", re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), "US phone number"),
    ("phone_intl", re.compile(r"\b\+\d{1,3}[\s.-]?\d{4,14}\b"), "International phone number"),
    ("email_address", re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"), "Email address"),
    ("date_of_birth", re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"), "Date of birth"),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP address"),
    ("passport", re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "Passport number pattern"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:\d{4}[\s]?){2,7}\d{1,4}\b"), "IBAN bank account"),
    ("drivers_license", re.compile(r"\b[A-Z]\d{3,8}\b"), "Possible driver's license number"),
    ("medical_record", re.compile(r"\bMRN[\s:-]*\d{6,}\b", re.I), "Medical Record Number"),
]

# Field names that suggest PII (even if values aren't directly pattern-matched)
_PII_FIELD_NAMES = {
    "ssn", "social_security", "social_security_number",
    "credit_card", "card_number", "cc_number", "ccn",
    "phone", "phone_number", "mobile", "cell",
    "email", "e-mail", "email_address",
    "dob", "date_of_birth", "birthday", "birth_date",
    "address", "street_address", "home_address",
    "passport", "passport_number",
    "license", "drivers_license", "dl_number",
    "name", "first_name", "last_name", "full_name",
    "ip", "ip_address",
}


def extract_facts(content: str, filename: str = "") -> dict[str, Any]:
    """Scan content for PII patterns."""
    facts: dict[str, Any] = {
        "pii_count": 0,
        "has_ssn": False,
        "has_credit_card": False,
        "has_phone": False,
        "has_email": False,
        "has_dob": False,
        "has_ip_address": False,
        "has_passport": False,
        "has_medical_record": False,
        "pii_field_names_count": 0,
        "pii_items": [],  # list of (type, line, preview)
    }

    for line_num, line in enumerate(content.splitlines(), 1):
        for pii_name, regex, desc in _PII_PATTERNS:
            for match in regex.finditer(line):
                matched = match.group(0)
                if pii_name == "ip_address" and _is_non_personal_ip(matched):
                    continue
                facts["pii_count"] += 1
                if len(matched) > 8:
                    preview = matched[:3] + "***" + matched[-2:]
                else:
                    preview = "***"
                facts["pii_items"].append((pii_name, line_num, preview, desc))

                if "ssn" in pii_name:
                    facts["has_ssn"] = True
                if "credit_card" in pii_name:
                    facts["has_credit_card"] = True
                if "phone" in pii_name:
                    facts["has_phone"] = True
                if pii_name == "email_address":
                    facts["has_email"] = True
                if "date_of_birth" in pii_name:
                    facts["has_dob"] = True
                if pii_name == "ip_address":
                    facts["has_ip_address"] = True
                if "passport" in pii_name:
                    facts["has_passport"] = True
                if "medical_record" in pii_name:
                    facts["has_medical_record"] = True

    lower_content = content.lower()
    for field_name in _PII_FIELD_NAMES:
        if f'"{field_name}"' in lower_content or f"'{field_name}'" in lower_content:
            facts["pii_field_names_count"] += 1

    return facts


def load_files(path: str | Path) -> list[tuple[str, str]]:
    """Load text files for PII scanning."""
    path = Path(path)
    files: list[tuple[str, str]] = []
    _skip = {".pyc", ".exe", ".dll", ".png", ".jpg", ".gif", ".zip", ".tar", ".gz"}

    if path.is_dir():
        for root, dirnames, filenames in os.walk(path):
            root_path = Path(root)
            dirnames[:] = [
                name for name in dirnames if not should_skip_path(root_path / name)
            ]
            for name in sorted(filenames):
                file_path = root_path / name
                if file_path.suffix.lower() in _skip or should_skip_path(file_path):
                    continue
                try:
                    files.append((str(file_path), file_path.read_text(encoding="utf-8", errors="replace")))
                except Exception:
                    continue
    elif path.is_file():
        if should_skip_path(path):
            return files
        try:
            files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            pass
    return files


def _is_non_personal_ip(value: str) -> bool:
    try:
        ip_value = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip_value.is_loopback
        or ip_value.is_unspecified
        or ip_value.is_reserved
        or ip_value.is_private
        or ip_value.is_link_local
        or ip_value.is_multicast
    )


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run PII detection on files at *path*."""
    files = load_files(path)
    rules = load_rules_for_analyzer(rules_dir, "pii")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts(content, source)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
        all_findings.extend(findings)

        # Direct findings for each PII match
        for pii_name, line_num, preview, desc in facts["pii_items"]:
            finding = Finding(
                rule_id=f"PII-{pii_name.upper()[:8]}",
                rule_name=pii_name,
                severity=Severity.CRITICAL,
                description=f"Detected {desc} in data.",
                explanation=f"Line {line_num}: matched {pii_name} pattern",
                suggestion="Remove PII from source/data files. Use tokenization, encryption, or a PII vault.",
                location=f"{source}:{line_num}",
                context=preview,
                attack_vector=f"Data breach exposes {desc} → identity theft, regulatory fines (GDPR/CCPA/HIPAA)",
                cwe="CWE-359",
            )
            all_findings.append(finding)

    return all_findings
