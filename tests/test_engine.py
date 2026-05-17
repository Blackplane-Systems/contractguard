"""Tests for the ContractGuard rule engine."""

import pytest

from contractguard.engine import (
    Finding,
    Rule,
    Severity,
    evaluate,
    load_rules,
    normalize_output_text,
    run_rules,
    _coerce,
    _compare,
)


# ---- helpers ----

def _make_rule(**overrides) -> Rule:
    defaults = {
        "id": "TEST001",
        "name": "test_rule",
        "analyzer": "json",
        "severity": Severity.WARNING,
        "description": "Test rule description",
        "matcher": "some_fact == true",
        "suggestion": "Fix it.",
    }
    defaults.update(overrides)
    return Rule(**defaults)


# ---- _coerce tests ----

class TestCoerce:
    def test_true(self):
        assert _coerce("true") is True

    def test_false(self):
        assert _coerce("false") is False

    def test_int(self):
        assert _coerce("42") == 42

    def test_float(self):
        assert _coerce("3.14") == pytest.approx(3.14)

    def test_string(self):
        assert _coerce("hello") == "hello"


# ---- _compare tests ----

class TestCompare:
    def test_eq(self):
        assert _compare(1, "==", 1) is True
        assert _compare(1, "==", 2) is False

    def test_neq(self):
        assert _compare(1, "!=", 2) is True

    def test_gt(self):
        assert _compare(5, ">", 3) is True
        assert _compare(3, ">", 5) is False

    def test_gte(self):
        assert _compare(5, ">=", 5) is True

    def test_lt(self):
        assert _compare(3, "<", 5) is True

    def test_lte(self):
        assert _compare(5, "<=", 5) is True


# ---- evaluate() tests ----

class TestEvaluate:
    def test_simple_true_match(self):
        rule = _make_rule(matcher="contains_select_star == true")
        facts = {"contains_select_star": True}
        result = evaluate(facts, rule)
        assert result is not None
        assert result.rule_id == "TEST001"

    def test_simple_false_no_match(self):
        rule = _make_rule(matcher="contains_select_star == true")
        facts = {"contains_select_star": False}
        result = evaluate(facts, rule)
        assert result is None

    def test_numeric_comparison(self):
        rule = _make_rule(matcher="complexity_score > 25")
        facts = {"complexity_score": 30}
        result = evaluate(facts, rule)
        assert result is not None

    def test_numeric_no_match(self):
        rule = _make_rule(matcher="complexity_score > 25")
        facts = {"complexity_score": 10}
        result = evaluate(facts, rule)
        assert result is None

    def test_func_style_matcher(self):
        rule = _make_rule(matcher="field_types('price') > 1")
        facts = {"field_types('price')": 2}
        result = evaluate(facts, rule)
        assert result is not None
        assert "price" in result.explanation

    def test_func_style_callable(self):
        rule = _make_rule(matcher="field_types('price') > 1")
        facts = {"field_types": lambda f: 3 if f == "price" else 1}
        result = evaluate(facts, rule)
        assert result is not None

    def test_missing_fact_returns_none(self):
        rule = _make_rule(matcher="nonexistent_fact == true")
        facts = {}
        result = evaluate(facts, rule)
        assert result is None

    def test_finding_fields(self):
        rule = _make_rule(
            id="X001",
            name="x_rule",
            severity=Severity.CRITICAL,
            description="desc",
            suggestion="fix",
            matcher="flag == true",
        )
        result = evaluate({"flag": True}, rule)
        assert result is not None
        assert result.rule_id == "X001"
        assert result.severity == Severity.CRITICAL
        assert result.suggestion == "fix"


# ---- run_rules() tests ----

class TestRunRules:
    def test_multiple_rules(self):
        rules = [
            _make_rule(id="A", matcher="a == true"),
            _make_rule(id="B", matcher="b == true"),
            _make_rule(id="C", matcher="c == true"),
        ]
        facts = {"a": True, "b": False, "c": True}
        findings = run_rules(facts, rules)
        assert len(findings) == 2
        ids = {f.rule_id for f in findings}
        assert ids == {"A", "C"}

    def test_no_matches(self):
        rules = [_make_rule(matcher="x == true")]
        findings = run_rules({"x": False}, rules)
        assert findings == []


def test_normalize_output_text_uses_ascii_safe_symbols():
    assert normalize_output_text("repo → secret — risk…") == "repo -> secret - risk..."


# ---- load_rules() tests ----

class TestLoadRules:
    def test_load_from_directory(self, tmp_path):
        yaml_content = """
- id: T001
  name: test
  analyzer: json
  severity: info
  description: "Test"
  matcher: "x == true"
  suggestion: "Fix"
"""
        (tmp_path / "test.yaml").write_text(yaml_content)
        rules = load_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].id == "T001"
        assert rules[0].severity == Severity.INFO
