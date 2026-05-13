"""Tests for the config security analyzer."""

from pathlib import Path
import tempfile

import pytest

from contractguard.analyzers.config_analyzer import analyze, extract_facts

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class TestExtractFacts:
    def test_debug_enabled(self):
        content = "DEBUG=True\n"
        facts = extract_facts(content)
        assert facts["debug_enabled"] is True

    def test_debug_yaml_style(self):
        content = 'debug: true\n'
        facts = extract_facts(content)
        assert facts["debug_enabled"] is True

    def test_cors_wildcard(self):
        content = "CORS_ALLOW_ALL_ORIGINS=True\nallowed_origins: *\n"
        facts = extract_facts(content)
        assert facts["cors_allow_all"] is True

    def test_insecure_secret_key(self):
        content = "SECRET_KEY=changeme\n"
        facts = extract_facts(content)
        assert facts["insecure_secret_key"] is True

    def test_default_password(self):
        content = "DB_PASSWORD=admin\n"
        facts = extract_facts(content)
        assert facts["default_password"] is True

    def test_compose_default_password(self):
        content = "DATABASE_URL: postgresql://postgres:${POSTGRES_PASSWORD:-postgres}@db/app\n"
        facts = extract_facts(content)
        assert facts["default_password"] is True

    def test_ssl_disabled(self):
        content = "ssl_enabled: false\n"
        facts = extract_facts(content)
        assert facts["ssl_disabled"] is True

    def test_smtp_starttls_does_not_count_as_ssl_disabled(self):
        content = "SMTP_USE_STARTTLS=true\nSMTP_USE_SSL=false\n"
        facts = extract_facts(content)
        assert facts["ssl_disabled"] is False

    def test_wildcard_host(self):
        content = "ALLOWED_HOSTS=*\n"
        facts = extract_facts(content)
        assert facts["wildcard_host"] is True

    def test_root_user(self):
        content = "user: root\n"
        facts = extract_facts(content)
        assert facts["root_user"] is True

    def test_exposed_admin_port(self):
        content = "host: 0.0.0.0\n"
        facts = extract_facts(content)
        assert facts["exposed_admin_port"] is True

    def test_clean_config(self):
        content = "PORT=8080\nLOG_LEVEL=info\n"
        facts = extract_facts(content)
        assert facts["dangerous_settings_count"] == 0

    def test_counts_multiple_issues(self):
        content = "DEBUG=True\nSECRET_KEY=changeme\nPASSWORD=admin\nSSL=false\n"
        facts = extract_facts(content)
        assert facts["dangerous_settings_count"] >= 3


class TestAnalyze:
    def test_analyze_dangerous_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("DEBUG=True\nSECRET_KEY=changeme\nPASSWORD=admin\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) >= 2
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_safe_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("port: 8080\nlog_level: info\nworkers: 4\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) == 0
        finally:
            path.unlink(missing_ok=True)
