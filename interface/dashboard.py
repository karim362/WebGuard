"""Rich-based UI: banner, live events, final results table."""
from __future__ import annotations
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from models.result import Finding, Severity

console = Console()

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold magenta",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold green",
}

BANNER = r"""
 ██╗    ██╗███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║███╗██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚███╔███╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""

def show_banner(stage: str = "V0.2 Plugin Engine") -> None:
    text = Text(BANNER, style="bold green")
    text.append("\n  Advanced Web Security Testing Framework", style="cyan")
    text.append(f"  ·  {stage}", style="dim cyan")
    console.print(text)
    console.print()

def module_started(name: str) -> None:
    console.print(f"  [cyan]→[/cyan] [white]{name}[/white]: [dim]running[/dim]")

def module_finished(name: str, status: str, duration: float) -> None:
    mark = {"success": "[green]✓[/green]", "failed": "[red]✗[/red]",
            "partial": "[yellow]≈[/yellow]"}.get(status, "·")
    console.print(f"  {mark} [white]{name}[/white]: [dim]{status}[/dim] "
                  f"[dim]({duration:.2f}s)[/dim]")

def show_finding(f: Finding) -> None:
    style = SEVERITY_STYLE.get(f.severity, "green")
    body = Text()
    body.append(f"[{f.severity.value.upper()}] ", style=style)
    body.append(f"{f.title}\n", style="bold white")
    body.append(f"  module: {f.module}\n", style="dim")
    body.append(f"  url: {f.affected_url}\n", style="dim")
    body.append(f"  {f.description}", style="white")
    console.print(Panel(body, border_style=style.split()[-1], expand=False))

def show_results_table(report, findings: list[Finding]) -> None:
    table = Table(title="Scan Results", box=box.ROUNDED,
                  show_lines=True, title_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Title", overflow="fold")
    table.add_column("Module", style="dim")
    table.add_column("URL", overflow="fold", style="dim")

    for i, f in enumerate(findings, 1):
        style = SEVERITY_STYLE.get(f.severity, "green")
        table.add_row(str(i), Text(f.severity.value.upper(), style=style),
                      f.title, f.module, f.affected_url)

    console.print()
    if findings:
        console.print(table)
    else:
        console.print("[dim]No findings.[/dim]")

    summary = Text()
    summary.append(f"scan_id: {report.scan_id}\n", style="dim")
    summary.append(f"modules: {len(report.results)}  ", style="white")
    summary.append(f"findings: {len(findings)}  ", style="bold white")
    summary.append(f"duration: {report.total_duration:.2f}s", style="dim")
    console.print(Panel(summary, title="Summary", border_style="green", expand=False))
