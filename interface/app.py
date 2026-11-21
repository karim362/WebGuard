"""Creative, clean vertical CLI for WebGuard (hackrw)."""
from __future__ import annotations
from pathlib import Path
from ai.analyzer import triage_findings
from core.engine import Engine
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.result import Finding, Severity
from models.scan_config import ScanConfig
from models.scope import Scope
from models.target import Target
from reporting import (
    build_html_report,
    build_json_report,
    collect_findings,
    export_html_to_hack_wed,
)
from services.http_client import HttpClient
import config

G = "\033[38;5;48m"
E = "\033[38;5;42m"
C = "\033[38;5;45m"
V = "\033[38;5;141m"
A = "\033[38;5;214m"
R = "\033[38;5;203m"
D = "\033[2m"
B = "\033[1m"
X = "\033[0m"

SEV_COLOR = {
    Severity.CRITICAL: R,
    Severity.HIGH: "\033[38;5;208m",
    Severity.MEDIUM: A,
    Severity.LOW: C,
    Severity.INFO: E,
}

MODE_BUDGET = {
    ScanMode.PASSIVE: 60,
    ScanMode.ACTIVE: 140,
    ScanMode.ADVANCED: 450,
}


def _header() -> None:
    print(f"\n{G}{B}  ✦ HACKRW · WEBGUARD{X}")
    print(f"  {V}Creative Security Studio{X} {D}// Termux{X}")
    print(f"  {D}{'═' * 44}{X}")


def _print_menu() -> None:
    print(f"  {G}{B}[1]{X} {B}New Scan{X}       {D}Launch target assessment{X}")
    print(f"  {C}{B}[2]{X} {B}Reports{X}        {D}Browse HTML & hack wed{X}")
    print(f"  {A}{B}[3]{X} {B}Clean Cache{X}    {D}Clear old scan files{X}")
    print(f"  {V}{B}[4]{X} {B}hackrwed Web{X}   {D}Open browser dashboard{X}")
    print(f"  {D}{'─' * 44}{X}")


def _normalize_url(raw: str) -> str:
    u = raw.strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        return "https://" + u
    return u


def _quick_target_and_mode() -> tuple[ScanConfig, Target] | None:
    print(f"\n  {C}{B}Target URL{X} {D}(Enter to exit){X}")
    raw = input(f"  {G}▸{X} ")
    url = _normalize_url(raw)
    if not url:
        return None

    print(f"\n  {V}{B}Scan Mode{X}")
    print(f"  {E}[1]{X} Passive   {D}OSINT & headers only{X}")
    print(f"  {C}[2]{X} Active    {D}Standard probes (default){X}")
    print(f"  {A}[3]{X} Advanced  {D}Deep checks in scope{X}")
    m_in = input(f"  {G}▸{X} ").strip()
    mode = {
        "1": ScanMode.PASSIVE,
        "2": ScanMode.ACTIVE,
        "3": ScanMode.ADVANCED,
    }.get(m_in, ScanMode.ACTIVE)

    print(f"\n  {C}{B}Extra Scope Domains{X} {D}(comma-separated, Enter = target host){X}")
    extra_in = input(f"  {G}▸{X} ").strip()
    extra_domains = [d.strip() for d in extra_in.split(",") if d.strip()]

    target = Target(
        url=url,
        scope_domains=extra_domains,
        allow_subdomains=True,
        authorization_confirmed=True,
    )
    cfg = ScanConfig(
        target_url=url,
        mode=mode,
        scope=Scope(domains=extra_domains, allow_subdomains=True),
        authorization_confirmed=True,
    )
    return cfg, target


def _print_finding(f: Finding) -> None:
    col = SEV_COLOR.get(f.severity, E)
    print(
        f"    {col}{B}◆ {f.severity.value.upper()}{X} "
        f"{B}{f.title}{X} {D}[{f.module}]{X}"
    )
    print(f"      {D}{f.affected_url} — {f.description}{X}")


def cleanup_old_artifacts(
    results_dir: Path | None = None,
    reports_dir: Path | None = None,
) -> int:
    removed = 0
    for folder in (
        Path(results_dir or config.RESULTS_DIR),
        Path(reports_dir or config.REPORTS_DIR),
    ):
        if not folder.exists():
            continue
        for item in folder.iterdir():
            if item.is_file():
                item.unlink()
                removed += 1
    return removed


def _show_reports() -> None:
    print(f"\n  {C}{B}Saved Reports{X}")
    for label, folder in (
        ("reports", Path(config.REPORTS_DIR)),
        ("hack wed", Path(config.HACK_WED_DIR)),
    ):
        files = sorted(folder.glob("*.html")) if folder.exists() else []
        print(f"  {E}✦ {label}{X} {D}({folder}){X} — {len(files)} file(s)")
        for f in files[-5:]:
            print(f"    {D}• {f.name}{X}")


def _extract_module_name(args: tuple, kwargs: dict) -> str:
    for key in ("module_name", "name", "module"):
        val = kwargs.get(key)
        if isinstance(val, str) and val:
            return val
    for item in args:
        if isinstance(item, str) and item:
            return item
    res = kwargs.get("result")
    m = getattr(res, "module_name", "")
    return str(m) if m else "module"


def run_scan_target(
    engine: Engine,
    raw_url: str,
    mode: ScanMode = ScanMode.ACTIVE,
    extra_domains: list[str] | None = None,
) -> None:
    url = _normalize_url(raw_url)
    if not url:
        return
    extras = extra_domains or []
    target = Target(
        url=url,
        scope_domains=extras,
        allow_subdomains=True,
        authorization_confirmed=True,
    )
    cfg = ScanConfig(
        target_url=url,
        mode=mode,
        scope=Scope(domains=extras, allow_subdomains=True),
        authorization_confirmed=True,
    )
    guard = ScopeGuard(target)
    budget = MODE_BUDGET.get(cfg.mode, 140)
    engine.services["http"] = HttpClient(guard, max_requests=budget)

    print(
        f"\n  {C}{B}✦ Scanning{X} {B}{cfg.target_url}{X} "
        f"{D}({cfg.mode.value} · budget={budget}){X}"
    )
    print(f"  {D}{'─' * 44}{X}")
    counter = {"n": 0}

    def _on_mod_start(*args, **kwargs) -> None:
        mname = _extract_module_name(args, kwargs)
        print(f"  {C}▸{X} {mname} {D}[running]{X}")

    def _on_mod_done(*args, **kwargs) -> None:
        mname = _extract_module_name(args, kwargs)
        res = kwargs.get("result") or (args[1] if len(args) > 1 else None)
        st = getattr(getattr(res, "status", None), "value", "done")
        col = E if st == "success" else (A if st == "partial" else R)
        print(f"  {col}●{X} {mname} {D}[{st}]{X}")

    def _on_finding(*args, **kwargs) -> None:
        finding = kwargs.get("finding") or (args[0] if args else None)
        if isinstance(finding, Finding):
            counter["n"] += 1
            _print_finding(finding)

    bus = getattr(engine, "events", None)
    if bus is not None and hasattr(bus, "on"):
        bus.on("module_started", _on_mod_start)
        bus.on("module_finished", _on_mod_done)
        bus.on("finding", _on_finding)

    try:
        report = engine.run(cfg)
    except Exception as e:
        print(f"\n  {R}{B}✕ Scan error:{X} {e}\n")
        return

    ordered = collect_findings(report)
    triaged = triage_findings(ordered)
    json_path = build_json_report(report)
    html_path = build_html_report(report)
    hack_wed_path = export_html_to_hack_wed(html_path)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in ordered:
        s_val = str(getattr(getattr(f, "severity", None), "value", getattr(f, "severity", ""))).upper()
        if s_val in sev_counts:
            sev_counts[s_val] += 1
    print(
        f"  {A}Severity  :{X} CRIT={sev_counts['CRITICAL']}  "
        f"HIGH={sev_counts['HIGH']}  MED={sev_counts['MEDIUM']}  "
        f"LOW={sev_counts['LOW']}  INFO={sev_counts['INFO']}"
    )
    print(f"\n  {D}{'═' * 44}{X}")
    print(f"  {G}{B}✦ Scan Complete{X} {D}({report.total_duration:.2f}s){X}")
    print(f"  {C}Scan ID   :{X} {report.scan_id}")
    print(f"  {C}Findings  :{X} {counter['n']}  {D}|  Triaged: {len(triaged)}{X}")
    print(f"  {E}JSON      :{X} {json_path}")
    print(f"  {E}HTML      :{X} {html_path}")
    print(f"  {V}hack wed  :{X} {hack_wed_path}\n")


def run_app(engine: Engine, direct_url: str | None = None) -> None:
    if direct_url:
        _header()
        run_scan_target(engine, direct_url, mode=ScanMode.ACTIVE)
        return
    _header()
    _print_menu()
    choice = input(f"  {G}{B}Select{X} {D}[1-4, Enter=1]{X}: ").strip() or "1"

    if choice == "2":
        _show_reports()
        return
    if choice == "3":
        removed = cleanup_old_artifacts()
        print(f"\n  {E}✦ Cleaned {removed} old file(s).{X}\n")
        return
    if choice == "4":
        from interface.web_ui import serve_hackrwed
        serve_hackrwed()
        return

    built = _quick_target_and_mode()
    if built is None:
        return
    cfg, target = built

    guard = ScopeGuard(target)
    budget = MODE_BUDGET.get(cfg.mode, 140)
    engine.services["http"] = HttpClient(guard, max_requests=budget)

    print(
        f"\n  {C}{B}✦ Scanning{X} {B}{cfg.target_url}{X} "
        f"{D}({cfg.mode.value} · budget={budget}){X}"
    )
    print(f"  {D}{'─' * 44}{X}")
    counter = {"n": 0}

    def _on_mod_start(*args, **kwargs) -> None:
        mname = _extract_module_name(args, kwargs)
        print(f"  {C}▸{X} {mname} {D}[running]{X}")

    def _on_mod_done(*args, **kwargs) -> None:
        mname = _extract_module_name(args, kwargs)
        res = kwargs.get("result") or (args[1] if len(args) > 1 else None)
        st = getattr(getattr(res, "status", None), "value", "done")
        col = E if st == "success" else (A if st == "partial" else R)
        print(f"  {col}●{X} {mname} {D}[{st}]{X}")

    def _on_finding(*args, **kwargs) -> None:
        finding = kwargs.get("finding") or (args[0] if args else None)
        if isinstance(finding, Finding):
            counter["n"] += 1
            _print_finding(finding)

    bus = getattr(engine, "events", None)
    if bus is not None and hasattr(bus, "on"):
        bus.on("module_started", _on_mod_start)
        bus.on("module_finished", _on_mod_done)
        bus.on("finding", _on_finding)

    try:
        report = engine.run(cfg)
    except Exception as e:
        print(f"\n  {R}{B}✕ Scan error:{X} {e}\n")
        return

    ordered = collect_findings(report)
    triaged = triage_findings(ordered)
    json_path = build_json_report(report)
    html_path = build_html_report(report)
    hack_wed_path = export_html_to_hack_wed(html_path)

    print(f"\n  {D}{'═' * 44}{X}")
    print(f"  {G}{B}✦ Scan Complete{X} {D}({report.total_duration:.2f}s){X}")
    print(f"  {C}Scan ID   :{X} {report.scan_id}")
    print(f"  {C}Findings  :{X} {counter['n']}  {D}|  Triaged: {len(triaged)}{X}")
    print(f"  {E}JSON      :{X} {json_path}")
    print(f"  {E}HTML      :{X} {html_path}")
    print(f"  {V}hack wed  :{X} {hack_wed_path}\n")
