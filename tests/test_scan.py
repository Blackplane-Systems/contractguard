from pathlib import Path

from contractguard.scan import ScanTarget, list_analyzers, run_scan, scan_target, serialize_finding


def test_list_analyzers_contains_supported_security_analyzers():
    analyzers = list_analyzers()
    assert "json" in analyzers
    assert "secrets" in analyzers


def test_scan_target_returns_score_and_findings(tmp_path):
    data_file = tmp_path / "patterns.txt"
    data_file.write_text("(a+)+$\n")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "regex.yaml").write_text(
        """
- id: REG001
  name: nested_quantifiers
  analyzer: regex
  severity: critical
  description: "Nested quantifiers"
  matcher: "nested_quantifiers == true"
  suggestion: "Rewrite the pattern."
"""
    )

    result = scan_target(ScanTarget(path=data_file, analyzer="regex", rules_dir=rules_dir))
    assert result.score.total_findings == 1
    assert result.findings[0].rule_id == "REG001"


def test_serialize_finding_shape():
    findings = scan_target(
        ScanTarget(
            path=Path(__file__).resolve().parent.parent / "samples" / "secrets",
            analyzer="secrets",
            rules_dir=Path(__file__).resolve().parent.parent / "rules",
            min_confidence="low",
            include_fixtures=True,
        )
    ).findings
    payload = serialize_finding(findings[0])
    assert payload["rule_id"]
    assert payload["severity"]


def test_scan_filters_low_confidence_fixture_findings_by_default():
    findings = scan_target(
        ScanTarget(
            path=Path(__file__).resolve().parent.parent / "samples" / "secrets",
            analyzer="secrets",
            rules_dir=Path(__file__).resolve().parent.parent / "rules",
        )
    ).findings
    assert findings == []


def test_analyzer_runtime_error_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr("contractguard.scan._get_analyzer_registry", lambda: {"broken": "contractguard.missing"})
    findings = run_scan(tmp_path, analyzer="all", rules_dir=Path(__file__).resolve().parent.parent / "rules")
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-RUNTIME-BROKEN"
