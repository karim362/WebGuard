"""Target form — collect URL, scope, cookies, mode, modules."""
from __future__ import annotations
from rich.prompt import Prompt, Confirm
from rich.table import Table
from models.module import ScanMode
from models.scan_config import ScanConfig
from models.scope import Scope
from services.scope_store import ScopeStore
from interface import dashboard

def _collect_scope(url: str) -> Scope:
    console = dashboard.console
    store = ScopeStore()
    saved = store.load(url)
    if saved:
        prev_scope, notes = saved
        console.print(f"[dim]Found saved scope: {prev_scope.domains} (notes: {notes or '-'})[/dim]")
        if Confirm.ask("Use saved scope?", default=True):
            return prev_scope

    extra = Prompt.ask(
        "[bold]Extra scope domains[/bold] (comma separated, empty = target only)",
        default="",
    )
    domains = [d.strip() for d in extra.split(",") if d.strip()]
    return Scope(domains=domains, allow_subdomains=True)

def _collect_cookies() -> str | None:
    choice = Prompt.ask(
        "[bold]Cookies[/bold]: [white]skip[/white] / [white]header[/white] / [white]file[/white]",
        choices=["skip", "header", "file"], default="skip",
    )
    if choice == "skip":
        return None
    if choice == "header":
        return Prompt.ask("Cookie header (hidden after entry)", password=True)
    return Prompt.ask("Cookie file path (.json or .txt)")

def _collect_mode() -> ScanMode:
    choice = Prompt.ask(
        "[bold]Scan mode[/bold]",
        choices=["passive", "active", "advanced"], default="passive",
    )
    return ScanMode(choice)

def collect() -> ScanConfig | None:
    console = dashboard.console
    url = Prompt.ask("[bold]Target URL[/bold]", default="")
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scope = _collect_scope(url)
    cookies = _collect_cookies()
    mode = _collect_mode()

    console.print()
    table = Table(title="Review", box=None, show_header=False)
    table.add_column(style="dim", width=12)
    table.add_column()
    table.add_row("Target", url)
    table.add_row("Scope", ", ".join(scope.domains) or "(target only)")
    table.add_row("Cookies", "provided" if cookies else "none")
    table.add_row("Mode", mode.value)
    console.print(table)
    console.print()

    if not Confirm.ask(
        "[yellow]Confirm authorization to test this target[/yellow]",
        default=False,
    ):
        console.print("[red]Aborted.[/red]")
        return None

    # Save scope for next time
    try:
        ScopeStore().save(url, scope)
    except Exception:
        pass

    return ScanConfig(
        target_url=url, mode=mode, scope=scope,
        cookies_header=cookies, authorization_confirmed=True,
    )
