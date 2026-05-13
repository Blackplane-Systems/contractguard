"""ContractGuard command-line interface."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from contractguard import __version__
from contractguard.engine import Finding, Severity
from contractguard.scan import list_analyzers, resolve_rules_dir, run_scan, serialize_finding

app = typer.Typer(
    name="contractguard",
    help="ContractGuard security analysis for code, config, and build assets.",
    add_completion=False,
)
console = Console()

_ANALYZER_TYPES = [*list_analyzers(), "all"]


def _severity_color(sev: Severity) -> str:
    return {
        "info": "blue",
        "warning": "yellow",
        "critical": "red",
        "block": "bright_red",
    }.get(sev.value, "white")


def _print_findings(findings: list[Finding], ci_mode: bool = False) -> bool:
    if not findings:
        console.print("[green]No issues found.[/green]")
        return False

    table = Table(title="ContractGuard Findings", show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Description", max_width=50)
    table.add_column("Location", max_width=40)
    table.add_column("Suggestion", max_width=50)

    for finding in findings:
        color = _severity_color(finding.severity)
        table.add_row(
            finding.rule_id,
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.description,
            finding.location,
            finding.suggestion,
        )

    console.print(table)

    blocks = sum(1 for item in findings if item.severity == Severity.BLOCK)
    critical = sum(1 for item in findings if item.severity == Severity.CRITICAL)
    warning = sum(1 for item in findings if item.severity == Severity.WARNING)
    info = sum(1 for item in findings if item.severity == Severity.INFO)
    console.print(
        f"\n[bold]Summary:[/bold] {len(findings)} finding(s) - "
        f"[bright_red]{blocks} block[/bright_red], "
        f"[red]{critical} critical[/red], [yellow]{warning} warning[/yellow], [blue]{info} info[/blue]"
    )

    if ci_mode and (blocks > 0 or critical > 0):
        console.print("[red bold]CI mode: failing due to critical or block findings.[/red bold]")
        return True
    return False


def _print_score(findings: list[Finding]) -> None:
    from contractguard.scorer import compute_score

    score = compute_score(findings)
    grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bright_red"}
    color = grade_colors.get(score.grade, "white")

    console.print()
    console.print(
        Panel(
            f"[{color} bold]  Grade: {score.grade}  |  Score: {score.score}/100  [/{color} bold]\n\n"
            f"  {score.risk_summary}\n\n"
            f"  Findings: {score.total_findings} total - "
            f"[bright_red]{score.block_count} BLOCK[/bright_red], "
            f"[red]{score.critical_count} CRITICAL[/red], "
            f"[yellow]{score.warning_count} WARNING[/yellow], "
            f"[blue]{score.info_count} INFO[/blue]"
            + (
                f"\n\n  [bold]Attack Surface:[/bold] {', '.join(score.attack_surface[:5])}"
                if score.attack_surface
                else ""
            )
            + (
                f"\n\n  [bold]Top Risks:[/bold]\n" + "\n".join(f"   - {risk}" for risk in score.top_risks)
                if score.top_risks
                else ""
            ),
            title="ContractGuard Security Score",
            border_style=color,
        )
    )


@app.command()
def analyze(
    type: str = typer.Option(..., "--type", "-t", help=f"Analyzer type: {', '.join(_ANALYZER_TYPES)}"),
    path: Path = typer.Option(..., "--path", "-p", help="File or directory to analyze"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r", help="Path to rules/ directory"),
    report: Optional[Path] = typer.Option(None, "--report", help="Write HTML report to this path"),
    report_json: Optional[Path] = typer.Option(None, "--report-json", help="Write JSON report"),
    report_sarif: Optional[Path] = typer.Option(None, "--report-sarif", help="Write SARIF report"),
    db: Optional[str] = typer.Option(None, "--db", help="SQLite DB path for EXPLAIN mode (sql only)"),
    min_confidence: str = typer.Option("medium", "--min-confidence", help="Minimum confidence: low, medium, high"),
    ci: bool = typer.Option(False, "--ci", help="CI mode: exit code 2 on critical or block findings"),
    show_score: bool = typer.Option(False, "--score", help="Show security grade after analysis"),
    record: bool = typer.Option(False, "--record", help="Record scan to history database"),
) -> None:
    try:
        rules_path = resolve_rules_dir(rules_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    if type not in _ANALYZER_TYPES:
        console.print(f"[red]Error:[/red] Unknown type '{type}'. Use: {', '.join(_ANALYZER_TYPES)}")
        raise typer.Exit(1)

    findings = run_scan(
        path=path,
        analyzer=type,
        rules_dir=rules_path,
        db_path=db,
        min_confidence=min_confidence,
    )
    ci_fail = _print_findings(findings, ci_mode=ci)

    if show_score or type == "all":
        _print_score(findings)

    if record:
        from contractguard.history import record_scan

        score = record_scan(findings, analyzer=type, source_path=str(path))
        console.print(f"[dim]Scan recorded. Grade: {score.grade} ({score.score}/100)[/dim]")

    if report:
        from contractguard.reporter import render_html_report

        html = render_html_report(findings, analyzer_type=type, source_path=str(path))
        report.write_text(html, encoding="utf-8")
        console.print(f"[green]HTML report written to {report}[/green]")

    if report_json:
        report_json.write_text(json.dumps([serialize_finding(item) for item in findings], indent=2), encoding="utf-8")
        console.print(f"[green]JSON report written to {report_json}[/green]")

    if report_sarif:
        from contractguard.reporter import render_sarif_report

        sarif = render_sarif_report(findings, analyzer_type=type)
        report_sarif.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        console.print(f"[green]SARIF report written to {report_sarif}[/green]")

    if ci_fail:
        raise typer.Exit(2)


@app.command()
def score(
    path: Path = typer.Option(".", "--path", "-p", help="Project root to scan"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r"),
    min_confidence: str = typer.Option("medium", "--min-confidence", help="Minimum confidence: low, medium, high"),
) -> None:
    try:
        rules_path = resolve_rules_dir(rules_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    console.print("[bold]Running full security scan...[/bold]")
    findings = run_scan(path=path, analyzer="all", rules_dir=rules_path, min_confidence=min_confidence)
    _print_score(findings)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
    db_path: Optional[Path] = typer.Option(None, "--db", help="History database path"),
) -> None:
    from contractguard.history import get_history, get_trend

    records = get_history(limit=limit, db_path=db_path)
    if not records:
        console.print("[yellow]No scan history found. Use --record with analyze to track scans.[/yellow]")
        return

    table = Table(title="Scan History", show_lines=True)
    table.add_column("Date", style="dim")
    table.add_column("Analyzer")
    table.add_column("Grade", style="bold")
    table.add_column("Score")
    table.add_column("Findings")
    table.add_column("Source", max_width=40)

    for record in records:
        grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bright_red"}
        color = grade_colors.get(record["grade"], "white")
        table.add_row(
            record["timestamp"][:19],
            record["analyzer"],
            f"[{color}]{record['grade']}[/{color}]",
            str(record["score"]),
            str(record["total_findings"]),
            record["source_path"],
        )
    console.print(table)

    trend = get_trend(db_path=db_path)
    if trend["trend"] != "no_data":
        trend_icons = {"improving": "+", "degrading": "-", "stable": "="}
        icon = trend_icons.get(trend["trend"], "")
        console.print(
            f"\n[bold]Trend:[/bold] {icon} {trend['trend'].upper()} - Latest: {trend['latest_grade']} ({trend['latest_score']}/100)"
        )


@app.command()
def watch(
    path: Path = typer.Option(".", "--path", "-p", help="Directory to watch"),
    type: str = typer.Option("all", "--type", "-t", help="Analyzer type to run"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r"),
    min_confidence: str = typer.Option("medium", "--min-confidence", help="Minimum confidence: low, medium, high"),
    interval: int = typer.Option(3, "--interval", help="Seconds between scans"),
) -> None:
    try:
        rules_path = resolve_rules_dir(rules_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if not path.exists():
        console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(1)

    console.print(f"[bold]Watching {path} (every {interval}s). Press Ctrl+C to stop.[/bold]")

    def get_mtimes() -> dict[str, float]:
        mtimes: dict[str, float] = {}
        target = path if path.is_dir() else path.parent
        for file_path in target.rglob("*"):
            if file_path.is_file() and not any(part.startswith(".") for part in file_path.parts):
                try:
                    mtimes[str(file_path)] = file_path.stat().st_mtime
                except OSError:
                    continue
        return mtimes

    last_mtimes = get_mtimes()

    try:
        while True:
            time.sleep(interval)
            current = get_mtimes()
            changed = {key for key in current if current.get(key) != last_mtimes.get(key)}
            new_files = set(current) - set(last_mtimes)

            if changed or new_files:
                console.print(f"\n[yellow]Change detected ({len(changed | new_files)} file(s)). Re-scanning...[/yellow]")
                findings = run_scan(path=path, analyzer=type, rules_dir=rules_path, min_confidence=min_confidence)
                _print_findings(findings)
                _print_score(findings)
                last_mtimes = current
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


@app.command()
def version() -> None:
    console.print(f"ContractGuard v{__version__}")


if __name__ == "__main__":
    app()
