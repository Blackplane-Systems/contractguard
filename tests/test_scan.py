from pathlib import Path

from contractguard.scan import ScanTarget, list_analyzers, scan_target, serialize_finding


def test_list_analyzers_excludes_csv():
    analyzers = list_analyzers()
    assert "csv" not in analyzers
    assert "json" in analyzers


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
        )
    ).findings
    payload = serialize_finding(findings[0])
    assert payload["rule_id"]
    assert payload["severity"]
