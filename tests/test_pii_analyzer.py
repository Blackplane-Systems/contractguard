"""Tests for the PII analyzer."""

from pathlib import Path
import tempfile

from contractguard.analyzers.pii_analyzer import analyze, extract_facts
from contractguard.engine import Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class TestExtractFacts:
    def test_detects_ssn(self):
        content = '{"ssn": "123-45-6789"}'
        facts = extract_facts(content)
        assert facts["has_ssn"] is True
        assert facts["pii_count"] >= 1

    def test_detects_credit_card_visa(self):
        content = "card: 4111111111111111"
        facts = extract_facts(content)
        assert facts["has_credit_card"] is True

    def test_detects_email(self):
        content = "contact: john@example.com"
        facts = extract_facts(content)
        assert facts["has_email"] is True

    def test_detects_dob(self):
        content = "born: 1990-01-15"
        facts = extract_facts(content)
        assert facts["has_dob"] is True

    def test_detects_medical_record(self):
        content = "Patient MRN: 123456"
        facts = extract_facts(content)
        # MRN pattern requires 6+ digits
        assert facts["has_medical_record"] is True

    def test_detects_pii_field_names(self):
        content = '{"ssn": "xxx", "credit_card": "yyy", "phone": "zzz"}'
        facts = extract_facts(content)
        assert facts["pii_field_names_count"] >= 2

    def test_clean_content_no_pii(self):
        content = "This is normal text with no PII at all."
        facts = extract_facts(content)
        assert facts["has_ssn"] is False
        assert facts["has_credit_card"] is False

    def test_suppresses_non_personal_ips(self):
        content = "bind 127.0.0.1\nlisten 0.0.0.0\nprivate 10.0.0.1\n"
        facts = extract_facts(content)
        assert facts["has_ip_address"] is False
        assert facts["pii_count"] == 0

    def test_does_not_treat_numeric_code_constants_as_phone(self):
        content = "this.state = (1664525 * this.state + 1013904223) >>> 0;\n"
        facts = extract_facts(content, "math.ts")
        assert facts["has_phone"] is False
        assert facts["pii_count"] == 0

    def test_does_not_treat_regular_dates_as_dob(self):
        content = '"dateadded","2026-05-13 08:25:10","last_online","2026-05-13 08:25:10"\n'
        facts = extract_facts(content, "feed.csv")
        assert facts["has_dob"] is False
        assert facts["pii_count"] == 0

    def test_credit_cards_require_luhn(self):
        content = '{"transitivity": 0.5191742775433075}\n'
        facts = extract_facts(content, "model.json")
        assert facts["has_credit_card"] is False
        assert facts["pii_count"] == 0

    def test_source_contact_email_is_low_confidence(self, tmp_path):
        source = tmp_path / "ProductDetail.tsx"
        source.write_text("Contact: atelier@example.com\n")
        findings = analyze(source, RULES_DIR)
        assert findings
        assert all(f.confidence == "low" for f in findings)

    def test_redacted_preview(self):
        content = '{"ssn": "123-45-6789"}'
        facts = extract_facts(content)
        for _, _, preview, _ in facts["pii_items"]:
            if "ssn" in _:
                assert "***" in preview


class TestAnalyze:
    def test_analyze_pii_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"ssn": "123-45-6789", "card": "4111111111111111"}')
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) > 0
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("No personal info here.\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            # May have some false positives on short patterns, but shouldn't flag SSN/CC
            ssn_findings = [f for f in findings if "ssn" in f.rule_id.lower()]
            assert len(ssn_findings) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_findings_have_compliance_info(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"ssn": "234-56-7890"}')
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert any(f.attack_vector and ("GDPR" in f.attack_vector or "identity" in f.attack_vector.lower()) for f in findings)
        finally:
            path.unlink(missing_ok=True)

    def test_skips_vendor_directories(self, tmp_path):
        skipped_dir = tmp_path / "node_modules"
        skipped_dir.mkdir()
        (skipped_dir / "pii.txt").write_text("ssn: 123-45-6789\n")
        (tmp_path / "safe.txt").write_text("No personal info here.\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert all("node_modules" not in f.location for f in findings)
