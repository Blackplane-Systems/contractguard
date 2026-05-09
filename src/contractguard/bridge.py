from __future__ import annotations

import json
from pathlib import Path

import typer

from contractguard.scan import ScanTarget, findings_to_json, scan_target

app = typer.Typer(
    name="contractguard-bridge",
    help="Machine-readable bridge used by the ContractGuard VS Code extension.",
    add_completion=False,
)


@app.command("scan")
def scan(
    path: Path = typer.Option(..., "--path", help="File or directory to scan."),
    analyzer: str = typer.Option("all", "--analyzer", help="Analyzer id or 'all'."),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Override rules directory."),
    db_path: str | None = typer.Option(None, "--db", help="SQLite database used for SQL EXPLAIN mode."),
    include_sarif: bool = typer.Option(False, "--include-sarif", help="Include SARIF payload in the response."),
) -> None:
    result = scan_target(
        ScanTarget(path=path, analyzer=analyzer, rules_dir=rules_dir, db_path=db_path),
        include_sarif=include_sarif,
    )
    typer.echo(json.dumps(result.to_dict(), indent=2))


@app.command("findings")
def findings(
    path: Path = typer.Option(..., "--path", help="File or directory to scan."),
    analyzer: str = typer.Option("all", "--analyzer", help="Analyzer id or 'all'."),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Override rules directory."),
    db_path: str | None = typer.Option(None, "--db", help="SQLite database used for SQL EXPLAIN mode."),
) -> None:
    result = scan_target(ScanTarget(path=path, analyzer=analyzer, rules_dir=rules_dir, db_path=db_path))
    typer.echo(findings_to_json(result.findings))


if __name__ == "__main__":
    app()
