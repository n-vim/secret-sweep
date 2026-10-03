from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import CONFIG_NAME, default_config_text, load_config
from .env_example import create_env_example
from .gitignore import append_secret_rules, missing_secret_rules
from .models import ProjectReport, Severity
from .reports import render_report
from .scanner import SecretScanner, scan_path
from .utils import ensure_inside_root

app = typer.Typer(
    name="secretsweep",
    help="Scan repositories for leaked secrets, risky files, and unsafe environment setup.",
    no_args_is_help=True,
)
console = Console()


def _load_report(path: Path, config: Optional[Path] = None) -> ProjectReport:
    root = path.resolve()
    if not root.exists():
        raise typer.BadParameter(f"Path does not exist: {path}")
    if not root.is_dir():
        raise typer.BadParameter(f"Path must be a directory: {path}")
    return scan_path(root, config)


def _print_summary(report: ProjectReport) -> None:
    risk_style = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }.get(report.risk_level, "white")
    body = (
        f"[bold]Project:[/bold] {report.root.name}\n"
        f"[bold]Risk:[/bold] [{risk_style}]{report.risk_level.upper()}[/{risk_style}]\n"
        f"[bold]Score:[/bold] {report.score}/100\n"
        f"[bold]Findings:[/bold] {len(report.findings)}\n"
        f"[bold]Files scanned:[/bold] {report.stats.files_scanned}"
    )
    console.print(Panel(body, title="SecretSweep", border_style="cyan"))


def _print_findings_table(report: ProjectReport, limit: int = 20) -> None:
    table = Table(title="Top Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Masked Value")
    table.add_column("Suggestion")
    for finding in report.top_findings(limit=limit):
        severity_style = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
        }[finding.severity]
        table.add_row(
            f"[{severity_style}]{finding.severity.value.upper()}[/{severity_style}]",
            finding.rule_id,
            finding.location.display(),
            finding.masked_value or "-",
            finding.suggestion or "-",
        )
    if report.findings:
        console.print(table)
    else:
        console.print("[green]No secret findings were detected.[/green]")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Repository path to scan."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Optional config file path."),
    limit: int = typer.Option(20, "--limit", help="Maximum findings to display."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Fail if findings at this severity or above exist."),
) -> None:
    """Scan a repository and print a terminal security summary."""
    report = _load_report(path, config)
    _print_summary(report)
    _print_findings_table(report, limit=limit)
    threshold = fail_on or load_config(path.resolve(), config).fail_on
    if _should_fail(report, threshold):
        raise typer.Exit(code=1)


@app.command(name="files")
def files_command(
    path: Path = typer.Argument(Path("."), help="Repository path to scan."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Optional config file path."),
) -> None:
    """Show risky secret-related files found in the repository."""
    report = _load_report(path, config)
    table = Table(title="Risky Files")
    table.add_column("Severity")
    table.add_column("Location")
    table.add_column("Message")
    for finding in report.findings:
        if finding.kind.value == "risky-file":
            table.add_row(finding.severity.value.upper(), finding.location.display(), finding.message)
    console.print(table)


@app.command()
def env(
    path: Path = typer.Argument(Path("."), help="Repository path."),
    source: str = typer.Option(".env", "--source", help="Source environment file."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing .env.example."),
) -> None:
    """Generate a safe .env.example file from a local .env-style file."""
    root = path.resolve()
    target = create_env_example(root, source_name=source, force=force)
    console.print(f"[green]Created or kept[/green] {target.relative_to(root)}")


@app.command()
def report(
    path: Path = typer.Argument(Path("."), help="Repository path to scan."),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format: markdown, json, html."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Optional config file path."),
) -> None:
    """Generate a Markdown, JSON, or HTML security report."""
    root = path.resolve()
    scan_report = _load_report(root, config)
    content = render_report(scan_report, format)
    if output is None:
        console.print(content)
        return
    target = ensure_inside_root(root / output if not output.is_absolute() else output, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    console.print(f"[green]Report written:[/green] {target}")


@app.command(name="clean-example")
def clean_example(
    path: Path = typer.Argument(Path("."), help="Repository path."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing .env.example."),
) -> None:
    """Create .env.example and append recommended secret rules to .gitignore."""
    root = path.resolve()
    config = load_config(root)
    create_env_example(root, force=force)
    missing = missing_secret_rules(root, config)
    if missing:
        append_secret_rules(root, config)
        console.print("[green]Updated .gitignore with recommended secret rules.[/green]")
    else:
        console.print("[green].gitignore already contains recommended secret rules.[/green]")
    console.print("[green].env.example is ready.[/green]")


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Repository path."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
) -> None:
    """Create a default .secretsweep.yaml config file."""
    root = path.resolve()
    target = root / CONFIG_NAME
    if target.exists() and not force:
        console.print(f"[yellow]{CONFIG_NAME} already exists. Use --force to overwrite.[/yellow]")
        return
    target.write_text(default_config_text(), encoding="utf-8")
    console.print(f"[green]Created[/green] {target.relative_to(root)}")


@app.command()
def config(
    path: Path = typer.Argument(Path("."), help="Repository path."),
) -> None:
    """Print the active SecretSweep configuration."""
    cfg = load_config(path.resolve())
    table = Table(title="SecretSweep Config")
    table.add_column("Key")
    table.add_column("Value")
    for key, value in cfg.to_dict().items():
        table.add_row(key, str(value))
    console.print(table)


def _should_fail(report: ProjectReport, threshold: str) -> bool:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        threshold_severity = Severity(threshold.lower())
    except ValueError:
        return False
    threshold_index = order.index(threshold_severity)
    return any(order.index(finding.severity) >= threshold_index for finding in report.findings)
