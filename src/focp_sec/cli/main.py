"""FOCP Secure SDLC Assistant CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from focp_sec import __version__
from focp_sec.core.config import get_config
from focp_sec.core.database import ScanDatabase
from focp_sec.core.logging_setup import setup_logging
from focp_sec.core.orchestrator import ScanOrchestrator
from focp_sec.reports.generator import ReportGenerator

app = typer.Typer(
    name="focp-sec",
    help="FOCP Secure SDLC Assistant - Security analysis for software projects",
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold blue]FOCP Secure SDLC Assistant[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(None, "--version", "-v", callback=_version_callback, is_eager=True),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging"),
) -> None:
    """FOCP Secure SDLC Assistant CLI."""
    setup_logging("DEBUG" if verbose else get_config().log_level)


@app.command()
def scan(
    project_path: Path = typer.Argument(..., help="Path to project directory", exists=True, file_okay=False),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Report output directory"),
    format: Optional[str] = typer.Option(None, "--format", "-f", help="Report format: html,markdown,pdf,json"),
    no_report: bool = typer.Option(False, "--no-report", help="Skip report generation"),
) -> None:
    """Scan a project for security issues."""
    console.print(Panel.fit(
        "[bold blue]FOCP Secure SDLC Assistant[/]\nSecurity Scan Starting...",
        border_style="blue",
    ))

    orchestrator = ScanOrchestrator()
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )

    result = None
    with progress:
        task = progress.add_task("Initializing...", total=100)

        def callback(message: str, pct: float) -> None:
            progress.update(task, description=message, completed=int(pct * 100))

        try:
            result = orchestrator.scan(project_path, progress_callback=callback)
        except Exception as e:
            console.print(f"[bold red]Scan failed:[/] {e}")
            raise typer.Exit(1) from e

    _print_scan_summary(result)

    if not no_report:
        out_dir = output or get_config().report_output_dir
        generator = ReportGenerator(out_dir)
        if format:
            get_config()._config.setdefault("report", {})["formats"] = format.split(",")
        paths = generator.generate_all(result)
        console.print("\n[bold green]Reports generated:[/]")
        for fmt, path in paths.items():
            console.print(f"  [{fmt}] {path}")


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    format: str = typer.Option("html,markdown,pdf,json", "--format", "-f", help="Report formats"),
) -> None:
    """Generate report from a previous scan."""
    db = ScanDatabase()
    data = db.get_scan(scan_id)
    if not data:
        console.print(f"[red]Scan not found:[/] {scan_id}")
        raise typer.Exit(1)

    from focp_sec.core.models import ScanResult, ProjectInfo, SecurityScore
    from datetime import datetime

    project = ProjectInfo(**{k: v for k, v in data["project"].items()})
    score = SecurityScore(**data["score"])
    result = ScanResult(
        scan_id=data["scan_id"],
        project=project,
        score=score,
        scan_duration_seconds=data.get("scan_duration_seconds", 0),
        timestamp=datetime.fromisoformat(data["timestamp"]),
    )

    out_dir = output or get_config().report_output_dir
    get_config()._config.setdefault("report", {})["formats"] = format.split(",")
    generator = ReportGenerator(out_dir)
    paths = generator.generate_all(result)
    for fmt, path in paths.items():
        console.print(f"[green]Generated {fmt}:[/] {path}")


@app.command()
def score(
    project_path: Path = typer.Argument(..., help="Path to project", exists=True, file_okay=False),
) -> None:
    """Calculate security score for a project."""
    orchestrator = ScanOrchestrator()
    with console.status("[bold blue]Calculating security score..."):
        result = orchestrator.scan(project_path, save_to_db=False)

    score = result.score
    table = Table(title="Security Score", show_header=True)
    table.add_column("Category", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Bar", justify="left")

    categories = [
        ("Overall", score.overall, score.grade),
        ("Authentication", score.authentication, ""),
        ("Authorization", score.authorization, ""),
        ("Configuration", score.configuration, ""),
        ("Dependencies", score.dependencies, ""),
        ("Secrets", score.secrets, ""),
        ("Logging", score.logging, ""),
        ("Encryption", score.encryption, ""),
    ]

    for name, val, grade in categories:
        bar = "█" * int(val / 5) + "░" * (20 - int(val / 5))
        color = "green" if val >= 80 else "yellow" if val >= 60 else "red"
        display = f"[{color}]{val:.1f}/100[/{color}]"
        if grade:
            display += f" ([bold]{grade}[/])"
        table.add_row(name, display, f"[{color}]{bar}[/{color}]")

    console.print(table)


@app.command()
def checklist(
    project_path: Path = typer.Argument(..., help="Path to project", exists=True, file_okay=False),
    type: str = typer.Option("all", "--type", "-t", help="Checklist type: owasp, sdlc, deployment, all"),
) -> None:
    """Generate security checklists."""
    orchestrator = ScanOrchestrator()
    with console.status("[bold blue]Generating checklists..."):
        result = orchestrator.scan(project_path, save_to_db=False)

    checklists = result.checklists
    types = list(checklists.keys()) if type == "all" else [type]

    for cl_type in types:
        items = checklists.get(cl_type, [])
        if not items:
            continue
        table = Table(title=f"{cl_type.upper()} Checklist", show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Item")
        table.add_column("Status", justify="center")
        table.add_column("Notes", style="dim")

        for item in items:
            status_colors = {"pass": "green", "fail": "red", "warning": "yellow", "na": "dim"}
            color = status_colors.get(item.status, "white")
            table.add_row(item.category, item.item, f"[{color}]{item.status.upper()}[/{color}]", item.notes)

        console.print(table)
        console.print()


@app.command()
def threats(
    project_path: Path = typer.Argument(..., help="Path to project", exists=True, file_okay=False),
) -> None:
    """Generate STRIDE threat model."""
    orchestrator = ScanOrchestrator()
    with console.status("[bold blue]Generating threat model..."):
        result = orchestrator.scan(project_path, save_to_db=False)

    table = Table(title="STRIDE Threat Model", show_header=True)
    table.add_column("Asset", style="cyan")
    table.add_column("Threat")
    table.add_column("STRIDE", style="magenta")
    table.add_column("Surface")
    table.add_column("Likelihood")
    table.add_column("Impact")
    table.add_column("Mitigation", max_width=40)

    for tm in result.threat_model:
        lik_color = "red" if tm.likelihood == "High" else "yellow" if tm.likelihood == "Medium" else "green"
        imp_color = "red" if tm.impact == "Critical" else "yellow" if tm.impact == "High" else "green"
        table.add_row(
            tm.asset, tm.threat, tm.stride_category, tm.attack_surface,
            f"[{lik_color}]{tm.likelihood}[/{lik_color}]",
            f"[{imp_color}]{tm.impact}[/{imp_color}]",
            tm.mitigation[:40],
        )

    console.print(table)


@app.command()
def dependencies(
    project_path: Path = typer.Argument(..., help="Path to project", exists=True, file_okay=False),
) -> None:
    """Run dependency vulnerability analysis."""
    orchestrator = ScanOrchestrator()
    with console.status("[bold blue]Analyzing dependencies..."):
        result = orchestrator.scan(project_path, save_to_db=False)

    if not result.dependency_findings:
        console.print("[green]No dependency vulnerabilities found.[/]")
        return

    table = Table(title="Dependency Findings", show_header=True)
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("File")
    table.add_column("Recommendation", max_width=50)

    for f in result.dependency_findings:
        sev_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}
        color = sev_colors.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.title[:60],
            f.file_path or "N/A",
            f.recommendation[:50],
        )

    console.print(table)


@app.command()
def rbac(
    project_path: Path = typer.Argument(..., help="Path to project", exists=True, file_okay=False),
) -> None:
    """Generate RBAC matrix."""
    orchestrator = ScanOrchestrator()
    with console.status("[bold blue]Generating RBAC matrix..."):
        result = orchestrator.scan(project_path, save_to_db=False)

    table = Table(title="RBAC Matrix", show_header=True)
    table.add_column("Role", style="cyan")
    table.add_column("Resource")
    table.add_column("Permissions", style="green")
    table.add_column("Description", style="dim")

    for entry in result.rbac_matrix:
        table.add_row(entry.role, entry.resource, ", ".join(entry.permissions), entry.description)

    console.print(table)


@app.command(name="list-scans")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of scans to show"),
) -> None:
    """List recent scans."""
    db = ScanDatabase()
    scans = db.list_scans(limit)

    if not scans:
        console.print("[dim]No scans found.[/]")
        return

    table = Table(title="Recent Scans", show_header=True)
    table.add_column("Scan ID", style="cyan")
    table.add_column("Project")
    table.add_column("Date")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")

    for s in scans:
        score_color = "green" if s["score"] >= 80 else "yellow" if s["score"] >= 60 else "red"
        table.add_row(
            s["scan_id"], s["project_name"], s["timestamp"][:19],
            f"[{score_color}]{s['score']:.1f}[/{score_color}]",
            str(s["findings_count"]),
        )

    console.print(table)


@app.command()
def gui() -> None:
    """Launch the desktop GUI."""
    from focp_sec.gui.app import main as gui_main
    gui_main()


def _print_scan_summary(result) -> None:
    """Print scan summary to console."""
    summary = result.to_dict()["summary"]
    score = result.score

    console.print()
    console.print(Panel(
        f"[bold]Project:[/] {result.project.name}\n"
        f"[bold]Score:[/] [{'green' if score.overall >= 80 else 'yellow' if score.overall >= 60 else 'red'}]"
        f"{score.overall:.1f}/100 (Grade {score.grade})[/]\n"
        f"[bold]Findings:[/] {summary['total_findings']} total\n"
        f"  Critical: [red]{summary['critical']}[/] | "
        f"High: [orange1]{summary['high']}[/] | "
        f"Medium: [yellow]{summary['medium']}[/] | "
        f"Low: [green]{summary['low']}[/]\n"
        f"[bold]Duration:[/] {result.scan_duration_seconds:.1f}s\n"
        f"[bold]Scan ID:[/] {result.scan_id}",
        title="Scan Complete",
        border_style="green",
    ))

    if result.findings:
        table = Table(title="Top Findings", show_header=True)
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Category")
        table.add_column("File")

        for f in sorted(result.findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value))[:15]:
            colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}
            c = colors.get(f.severity.value, "white")
            table.add_row(
                f"[{c}]{f.severity.value.upper()}[/{c}]",
                f.title[:50],
                f.category,
                (f.file_path or "N/A")[:30],
            )

        console.print(table)


if __name__ == "__main__":
    app()
