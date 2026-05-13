"""Tests for report generation."""

from contractguard import __version__
from contractguard.engine import Finding, Severity
from contractguard.reporter import render_html_report, render_sarif_report


class TestRenderHtmlReport:
    def test_renders_with_findings(self):
        findings = [
            Finding(
                rule_id="TEST001",
                rule_name="test",
                severity=Severity.CRITICAL,
                description="Bad thing",
                explanation="Matched",
                suggestion="Fix it",
                location="test.json",
                context='{"a": 1}',
            )
        ]
        html = render_html_report(findings, analyzer_type="json", source_path="test.json")
        assert "ContractGuard Security Report" in html
        assert "TEST001" in html
        assert "critical" in html.lower()
        assert "Fix it" in html

    def test_renders_empty(self):
        html = render_html_report([], analyzer_type="sql", source_path="test.sql")
        assert "All clear" in html

    def test_contains_metadata(self):
        html = render_html_report([], analyzer_type="regex", source_path="patterns.txt")
        assert "regex" in html
        assert "patterns.txt" in html

    def test_sarif_preserves_windows_drive_paths(self):
        findings = [
            Finding(
                rule_id="TEST002",
                rule_name="test",
                severity=Severity.WARNING,
                description="Needs attention",
                explanation="Matched",
                suggestion="Fix it",
                location=r"C:\repo\.env:12",
                context="API_KEY=example",
            )
        ]

        sarif = render_sarif_report(findings)
        location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "C:/repo/.env"
        assert location["region"]["startLine"] == 12

    def test_sarif_uses_package_version(self):
        sarif = render_sarif_report([])
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
