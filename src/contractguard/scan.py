from __future__ import annotations

import importlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from contractguard import __version__
from contractguard.engine import Finding, Severity
from contractguard.reporter import render_sarif_report
from contractguard.scorer import SecurityScore, compute_score

AnalyzerFn = Callable[..., list[Finding]]

ANALYZER_IDS = (
    "json",
    "sql",
    "regex",
    "secrets",
    "pii",
    "config",
    "dockerfile",
    "deps",
)

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    analyzer: str = "all"
    rules_dir: Path | None = None
    db_path: str | None = None


@dataclass
class ScanResult:
    target: str
    analyzer: str
    findings: list[Finding]
    score: SecurityScore
    sarif: dict[str, Any] | None = None
    generated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "analyzer": self.analyzer,
            "generated_at": self.generated_at,
            "engine_version": __version__,
            "score": asdict(self.score),
            "findings": [serialize_finding(item) for item in self.findings],
            "sarif": self.sarif,
        }


def resolve_rules_dir(rules_dir: Path | None = None) -> Path:
    if rules_dir and rules_dir.exists():
        return rules_dir
    cwd_rules = Path.cwd() / "rules"
    if cwd_rules.exists():
        return cwd_rules
    if DEFAULT_RULES_DIR.exists():
        return DEFAULT_RULES_DIR
    raise FileNotFoundError("Could not locate the ContractGuard rules directory.")


def _get_analyzer_registry() -> dict[str, str]:
    return {
        "json": "contractguard.analyzers.json_analyzer",
        "sql": "contractguard.analyzers.sql_analyzer",
        "regex": "contractguard.analyzers.regex_analyzer",
        "secrets": "contractguard.analyzers.secrets_analyzer",
        "pii": "contractguard.analyzers.pii_analyzer",
        "config": "contractguard.analyzers.config_analyzer",
        "dockerfile": "contractguard.analyzers.dockerfile_analyzer",
        "deps": "contractguard.analyzers.dependency_analyzer",
    }


def list_analyzers() -> tuple[str, ...]:
    return ANALYZER_IDS


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity.value,
        "description": finding.description,
        "explanation": finding.explanation,
        "suggestion": finding.suggestion,
        "location": finding.location,
        "context": finding.context,
        "attack_vector": finding.attack_vector,
        "cwe": finding.cwe,
        "confidence": finding.confidence,
    }


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([serialize_finding(item) for item in findings], indent=2)


def scan_target(target: ScanTarget, include_sarif: bool = False) -> ScanResult:
    path = target.path
    if not path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {path}")

    analyzer = target.analyzer
    if analyzer != "all" and analyzer not in ANALYZER_IDS:
        supported = ", ".join((*ANALYZER_IDS, "all"))
        raise ValueError(f"Unsupported analyzer '{analyzer}'. Supported values: {supported}")

    rules_dir = resolve_rules_dir(target.rules_dir)
    findings = run_scan(path=path, analyzer=analyzer, rules_dir=rules_dir, db_path=target.db_path)
    score = compute_score(findings)
    sarif = render_sarif_report(findings, analyzer_type=analyzer) if include_sarif else None
    return ScanResult(
        target=str(path),
        analyzer=analyzer,
        findings=findings,
        score=score,
        sarif=sarif,
    )


def run_scan(
    path: str | Path,
    analyzer: str = "all",
    rules_dir: str | Path | None = None,
    db_path: str | None = None,
) -> list[Finding]:
    registry = _get_analyzer_registry()
    rules_path = resolve_rules_dir(Path(rules_dir) if rules_dir else None)
    target_path = Path(path)

    if analyzer == "all":
        findings: list[Finding] = []
        for analyzer_id, module_path in registry.items():
            findings.extend(
                _invoke_analyzer(
                    analyzer_id=analyzer_id,
                    analyzer_fn=_load_analyzer(module_path),
                    path=target_path,
                    rules_path=rules_path,
                    db_path=db_path,
                )
            )
        return findings

    return _invoke_analyzer(
        analyzer_id=analyzer,
        analyzer_fn=_load_analyzer(registry[analyzer]),
        path=target_path,
        rules_path=rules_path,
        db_path=db_path,
    )


def _load_analyzer(module_path: str) -> AnalyzerFn:
    module = importlib.import_module(module_path)
    return getattr(module, "analyze")


def _invoke_analyzer(
    analyzer_id: str,
    analyzer_fn: AnalyzerFn,
    path: Path,
    rules_path: Path,
    db_path: str | None,
) -> list[Finding]:
    if analyzer_id == "sql":
        return analyzer_fn(path, rules_path, db_path=db_path)
    return analyzer_fn(path, rules_path)


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    return {
        "total": len(findings),
        "block": sum(1 for item in findings if item.severity == Severity.BLOCK),
        "critical": sum(1 for item in findings if item.severity == Severity.CRITICAL),
        "warning": sum(1 for item in findings if item.severity == Severity.WARNING),
        "info": sum(1 for item in findings if item.severity == Severity.INFO),
    }
