"""JSON Schema Inference Analyzer.

Reads one or more JSON files (or a directory of them), infers per-field type
distributions, and emits facts for the rule engine.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Rule, load_rules_for_analyzer, run_rules
from contractguard.analyzers.file_filters import should_skip_path

_SKIP_JSON_NAMES = {
    "composer.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "tsconfig.build.json",
}


def _type_label(val: Any) -> str:
    """Return a concise type label for a JSON value."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "number"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "array"
    if isinstance(val, dict):
        return "object"
    return type(val).__name__


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Recursively flatten a JSON object to (dotted_path, type_label) pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            pairs.append((full_key, _type_label(val)))
            if isinstance(val, (dict, list)):
                pairs.extend(_flatten(val, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            idx_key = f"{prefix}[]"
            pairs.append((idx_key, _type_label(item)))
            if isinstance(item, (dict, list)):
                pairs.extend(_flatten(item, idx_key))
    return pairs


def infer_facts(json_objects: list[dict]) -> dict[str, Any]:
    """Given a sample of JSON objects, build a fact dictionary for rule evaluation.

    Facts emitted:
      - field_types  : callable(field) -> int  (number of distinct types seen)
      - field_type_map : dict[field, Counter[type_label]]
      - field_presence : dict[field, int]  (count of objects containing the field)
      - total_samples  : int
      - optional_fields : int  (fields not present in every sample)
      - nullable_fields : int  (fields that were null at least once)
    """
    field_type_map: dict[str, Counter] = defaultdict(Counter)
    field_presence: dict[str, int] = defaultdict(int)

    for obj in json_objects:
        seen_fields: set[str] = set()
        for path, type_label in _flatten(obj):
            field_type_map[path][type_label] += 1
            if path not in seen_fields:
                field_presence[path] += 1
                seen_fields.add(path)

    total = len(json_objects)
    optional_count = sum(1 for f, c in field_presence.items() if c < total)
    nullable_count = sum(1 for f, types in field_type_map.items() if "null" in types)

    def _field_types(field_name: str) -> int:
        """Return the number of distinct types observed for *field_name*."""
        counter = field_type_map.get(field_name)
        if counter is None:
            return 0
        return len(counter)

    # Build fact dictionary with both callable and pre-evaluated forms
    facts: dict[str, Any] = {
        "field_types": _field_types,
        "field_type_map": dict(field_type_map),
        "field_presence": dict(field_presence),
        "total_samples": total,
        "optional_fields": optional_count,
        "nullable_fields": nullable_count,
    }

    # Pre-compute field_types('field') keys for each field the rule engine can look up
    for field_name in field_type_map:
        facts[f"field_types('{field_name}')"] = len(field_type_map[field_name])

    return facts


def load_json_samples(path: str | Path) -> list[dict]:
    """Load JSON samples from a file or directory.

    Supports: single JSON object file, JSON array file, or directory of .json files.
    """
    path = Path(path)
    objects: list[dict] = []

    if path.is_dir():
        for f in sorted(path.glob("*.json")):
            if f.name.casefold() in _SKIP_JSON_NAMES or should_skip_path(f):
                continue
            objects.extend(_load_single(f))
    else:
        if path.name.casefold() in _SKIP_JSON_NAMES or should_skip_path(path):
            return []
        objects.extend(_load_single(path))

    return objects


def _load_single(filepath: Path) -> list[dict]:
    """Load a single JSON file, handling both objects and arrays."""
    with open(filepath, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run JSON analysis on samples at *path* using rules from *rules_dir*."""
    samples = load_json_samples(path)
    if not samples:
        return []
    facts = infer_facts(samples)
    rules = load_rules_for_analyzer(rules_dir, "json")
    findings = run_rules(facts, rules)

    for f in findings:
        f.location = str(path)
        f.context = f"Analyzed {len(samples)} sample(s)"

    return findings
