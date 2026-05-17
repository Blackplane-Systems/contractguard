"""Shared rule engine — loads YAML rules and evaluates analyzer facts against matchers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    BLOCK = "block"  # deployment must be stopped

    @property
    def weight(self) -> int:
        return {"info": 1, "warning": 3, "critical": 7, "block": 15}[self.value]


@dataclass
class Rule:
    """A single audit rule loaded from YAML."""

    id: str
    name: str
    analyzer: str  # json | sql | regex | secrets | pii | config | dockerfile | deps
    severity: Severity
    description: str
    matcher: str
    suggestion: str
    attack_vector: str = ""   # how an attacker could exploit this
    cwe: str = ""             # CWE ID for standards mapping
    example: list[str] | None = None


@dataclass
class Finding:
    """A concrete finding produced when a rule matches facts."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    explanation: str
    suggestion: str
    location: str = ""        # file path, line number, etc.
    context: str = ""         # snippet of the problematic input
    attack_vector: str = ""   # how an attacker could exploit this
    cwe: str = ""             # CWE ID
    confidence: str = "high"  # high | medium | low


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """Load all YAML rule files from *rules_dir* and return parsed Rule objects."""
    rules_dir = Path(rules_dir)
    rules: list[Rule] = []
    for yaml_path in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            data = [data]
        for entry in data:
            rules.append(
                Rule(
                    id=entry["id"],
                    name=entry["name"],
                    analyzer=entry["analyzer"],
                    severity=Severity(entry["severity"]),
                    description=entry["description"],
                    matcher=entry["matcher"],
                    suggestion=entry["suggestion"],
                    attack_vector=entry.get("attack_vector", ""),
                    cwe=entry.get("cwe", ""),
                    example=entry.get("example"),
                )
            )
    return rules


def load_rules_for_analyzer(rules_dir: str | Path, analyzer: str) -> list[Rule]:
    """Return only rules whose *analyzer* field matches."""
    return [r for r in load_rules(rules_dir) if r.analyzer == analyzer]


_FUNC_RE = re.compile(r"^(\w+)\('([^']*)'\)\s*(==|!=|>|>=|<|<=)\s*(.+)$")
_SIMPLE_RE = re.compile(r"^(\w+)\s*(==|!=|>|>=|<|<=)\s*(.+)$")
_TEXT_REPLACEMENTS = {
    "\u2192": "->",
    "\u2014": "-",
    "\u2013": "-",
    "\u2026": "...",
}


def normalize_output_text(value: str) -> str:
    """Return stable ASCII-safe text for machine-readable findings."""
    for source, replacement in _TEXT_REPLACEMENTS.items():
        value = value.replace(source, replacement)
    return value


def _coerce(raw: str) -> bool | int | float | str:
    """Coerce a string token to a Python literal."""
    raw = raw.strip()
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _compare(left: Any, op: str, right: Any) -> bool:
    """Safely compare two values with the given operator."""
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    return False


def evaluate(facts: dict[str, Any], rule: Rule) -> Finding | None:
    """Evaluate a single rule against analyzer facts.

    Returns a Finding if the rule matches, else None.
    """
    matcher = rule.matcher.strip()

    # Try function‐style matcher: func('arg') op value
    m = _FUNC_RE.match(matcher)
    if m:
        func_name, arg, op, raw_val = m.groups()
        fact_value = facts.get(f"{func_name}('{arg}')")
        if fact_value is None:
            func = facts.get(func_name)
            if callable(func):
                fact_value = func(arg)
            else:
                return None
        expected = _coerce(raw_val)
        if _compare(fact_value, op, expected):
            return _make_finding(rule, f"{func_name}('{arg}') is {fact_value}")
        return None

    # Try simple matcher: fact_name op value
    m = _SIMPLE_RE.match(matcher)
    if m:
        fact_name, op, raw_val = m.groups()
        fact_value = facts.get(fact_name)
        if fact_value is None:
            return None
        expected = _coerce(raw_val)
        if _compare(fact_value, op, expected):
            return _make_finding(rule, f"{fact_name} is {fact_value}")
        return None

    return None


def _make_finding(rule: Rule, explanation: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        attack_vector=normalize_output_text(rule.attack_vector),
        cwe=rule.cwe,
        rule_name=rule.name,
        severity=rule.severity,
        description=normalize_output_text(rule.description),
        explanation=normalize_output_text(explanation),
        suggestion=normalize_output_text(rule.suggestion),
    )


def run_rules(facts: dict[str, Any], rules: list[Rule]) -> list[Finding]:
    """Run all rules against the facts and return matching findings."""
    findings: list[Finding] = []
    for rule in rules:
        finding = evaluate(facts, rule)
        if finding is not None:
            findings.append(finding)
    return findings
