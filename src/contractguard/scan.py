from __future__ import annotations

import importlib
import json
import datetime
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from contractguard import __version__
from contractguard.engine import Finding, Severity
from contractguard.analyzers.file_filters import confidence_allowed, is_fixture_path
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
    min_confidence: str = "medium"
    include_fixtures: bool = False


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
    findings = run_scan(
        path=path,
        analyzer=analyzer,
        rules_dir=rules_dir,
        db_path=target.db_path,
        min_confidence=target.min_confidence,
        include_fixtures=target.include_fixtures,
    )
    score = compute_score(findings)
    sarif = render_sarif_report(findings, analyzer_type=analyzer) if include_sarif else None
    return ScanResult(
        target=str(path),
        analyzer=analyzer,
        findings=findings,
        score=score,
        sarif=sarif,
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def run_scan(
    path: str | Path,
    analyzer: str = "all",
    rules_dir: str | Path | None = None,
    db_path: str | None = None,
    min_confidence: str = "medium",
    include_fixtures: bool = False,
) -> list[Finding]:
    registry = _get_analyzer_registry()
    rules_path = resolve_rules_dir(Path(rules_dir) if rules_dir else None)
    target_path = Path(path)

    if analyzer == "all":
        findings: list[Finding] = []
        for analyzer_id, module_path in registry.items():
            findings.extend(
                _run_analyzer(
                    analyzer_id=analyzer_id,
                    module_path=module_path,
                    path=target_path,
                    rules_path=rules_path,
                    db_path=db_path,
                )
            )
        return _filter_findings_by_fixtures(
            _filter_findings_by_confidence(findings, min_confidence),
            include_fixtures,
        )

    return _filter_findings_by_fixtures(
        _filter_findings_by_confidence(
            _run_analyzer(
                analyzer_id=analyzer,
                module_path=registry[analyzer],
                path=target_path,
                rules_path=rules_path,
                db_path=db_path,
            ),
            min_confidence,
        ),
        include_fixtures,
    )


def _load_analyzer(module_path: str) -> AnalyzerFn:
    module = importlib.import_module(module_path)
    return getattr(module, "analyze")


def _run_analyzer(
    analyzer_id: str,
    module_path: str,
    path: Path,
    rules_path: Path,
    db_path: str | None,
) -> list[Finding]:
    try:
        return _invoke_analyzer(
            analyzer_id=analyzer_id,
            analyzer_fn=_load_analyzer(module_path),
            path=path,
            rules_path=rules_path,
            db_path=db_path,
        )
    except Exception as exc:
        return [
            Finding(
                rule_id=f"CG-RUNTIME-{analyzer_id.upper()}",
                rule_name=f"{analyzer_id}_runtime_error",
                severity=Severity.WARNING,
                description=f"{analyzer_id} analyzer failed to run.",
                explanation=str(exc),
                suggestion="Install runtime dependencies or disable this analyzer until the runtime is fixed.",
                location=str(path),
                context=type(exc).__name__,
                attack_vector="Analyzer failure may hide issues in this category.",
                cwe="",
                confidence="high",
            )
        ]


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


def _filter_findings_by_confidence(findings: list[Finding], min_confidence: str) -> list[Finding]:
    minimum = min_confidence if min_confidence in {"low", "medium", "high"} else "medium"
    return [finding for finding in findings if confidence_allowed(finding.confidence, minimum)]


def _location_to_path(location: str) -> str:
    if not location:
        return ""
    if ":" not in location:
        return location
    head, tail = location.rsplit(":", 1)
    if tail.isdigit():
        return head
    return location


def _filter_findings_by_fixtures(findings: list[Finding], include_fixtures: bool) -> list[Finding]:
    if include_fixtures:
        return findings
    filtered: list[Finding] = []
    for finding in findings:
        location_path = _location_to_path(finding.location)
        if location_path and is_fixture_path(location_path):
            continue
        filtered.append(finding)
    return filtered


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    return {
        "total": len(findings),
        "block": sum(1 for item in findings if item.severity == Severity.BLOCK),
        "critical": sum(1 for item in findings if item.severity == Severity.CRITICAL),
        "warning": sum(1 for item in findings if item.severity == Severity.WARNING),
        "info": sum(1 for item in findings if item.severity == Severity.INFO),
    }
