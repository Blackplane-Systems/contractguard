"""Tests for the secrets analyzer."""

from pathlib import Path
import tempfile

from contractguard.analyzers.secrets_analyzer import analyze, extract_facts
from contractguard.engine import Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def fake_aws_access_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def fake_github_token() -> str:
    return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"


def fake_private_key_block() -> str:
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    end = "-----END " + "RSA PRIVATE KEY-----"
    return f"{begin}\nMIIEp...\n{end}\n"


class TestExtractFacts:
    def test_detects_aws_access_key(self):
        content = f"key: {fake_aws_access_key()} \n"
        facts = extract_facts(content)
        assert facts["has_aws_key"] is True
        assert facts["secret_count"] >= 1

    def test_detects_github_token(self):
        content = f"GITHUB_TOKEN={fake_github_token()}\n"
        facts = extract_facts(content)
        assert facts["secret_count"] >= 1

    def test_detects_private_key(self):
        content = fake_private_key_block()
        facts = extract_facts(content)
        assert facts["has_private_key"] is True

    def test_detects_database_url(self):
        content = "DATABASE_URL=postgresql://admin:password@db.example.com:5432/prod\n"
        facts = extract_facts(content)
        assert facts["has_database_url"] is True

    def test_detects_stripe_key(self):
        content = "STRIPE_KEY=DEMO_FAKE_KEY_NOT_A_REAL_SECRET_0000000000000\n"
        facts = extract_facts(content)
        assert facts["secret_count"] >= 1

    def test_detects_jwt(self):
        content = "TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
        facts = extract_facts(content)
        assert facts["has_jwt"] is True

    def test_detects_smtp_app_password(self):
        content = "SMTP_PASSWORD=abcd efgh ijkl mnop\n"
        facts = extract_facts(content, ".env")
        assert facts["secret_count"] >= 1

    def test_plain_uuid_is_not_heroku_key(self):
        content = "request_id = '123e4567-e89b-12d3-a456-426614174000'\n"
        facts = extract_facts(content, "events.py")
        assert facts["secret_count"] == 0

    def test_clean_file_no_secrets(self):
        content = "# This is a clean config\nDEBUG=false\nPORT=8080\n"
        facts = extract_facts(content)
        assert facts["secret_count"] == 0

    def test_ignores_token_variable_expression(self):
        content = "const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;\n"
        facts = extract_facts(content, "api.ts")
        assert facts["secret_count"] == 0

    def test_redacted_preview(self):
        content = f"GITHUB_TOKEN={fake_github_token()}\n"
        facts = extract_facts(content)
        for _, _, preview in facts["secrets_found"]:
            assert "****" in preview


class TestAnalyze:
    def test_analyze_secrets_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"AWS_ACCESS_KEY_ID={fake_aws_access_key()}\n")
            f.write("DB_PASSWORD=admin123\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) > 0
            severities = {f.severity for f in findings}
            assert Severity.BLOCK in severities or Severity.CRITICAL in severities
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello world\nThis is a normal file\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_directory(self, tmp_path):
        (tmp_path / "safe.txt").write_text("Nothing here")
        (tmp_path / "leak.env").write_text("STRIPE_KEY=DEMO_FAKE_KEY_NOT_A_REAL_SECRET_0000000000000\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert len(findings) > 0

    def test_findings_have_attack_vector(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"GITHUB_TOKEN={fake_github_token()}\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert any(f.attack_vector for f in findings)
            assert all("→" not in f.attack_vector for f in findings)
        finally:
            path.unlink(missing_ok=True)

    def test_findings_have_cwe(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"AWS_ACCESS_KEY_ID={fake_aws_access_key()}\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert any(f.cwe for f in findings)
        finally:
            path.unlink(missing_ok=True)

    def test_skips_vendor_directories(self, tmp_path):
        skipped_dir = tmp_path / "node_modules"
        skipped_dir.mkdir()
        (skipped_dir / "secret.env").write_text("DB_PASSWORD=admin123\n")
        (tmp_path / "safe.txt").write_text("Nothing here\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert all("node_modules" not in f.location for f in findings)

    def test_fixture_findings_are_low_confidence(self, tmp_path):
        samples_dir = tmp_path / "samples"
        samples_dir.mkdir()
        (samples_dir / "leaked.env").write_text("DATABASE_URL=postgresql://user:pass@example/db\n")
        findings = analyze(samples_dir, RULES_DIR)
        assert findings
        assert all(f.confidence == "low" for f in findings)

    def test_readme_placeholder_token_is_low_confidence(self, tmp_path):
        readme = tmp_path / "README.md"
        readme.write_text("storefrontAccessToken: 'your-storefront-access-token'\n")
        findings = analyze(readme, RULES_DIR)
        assert findings
        assert all(f.confidence == "low" for f in findings)
