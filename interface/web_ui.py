"""Mobile-friendly WebGuard web UI (hackrwed) with direct scan launch."""
from __future__ import annotations
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from ai.analyzer import triage_findings
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.scan_config import ScanConfig
from models.scope import Scope
from models.target import Target
from reporting import (
    build_html_report,
    build_json_report,
    collect_findings,
    export_html_to_hack_wed,
)
from reporting.risk_assessment import score_finding
from services.http_client import HttpClient
import config


def _normalize_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        return "https://" + u
    return u


def _collect_html_reports() -> list[Path]:
    files: list[Path] = []
    for folder in (Path(config.REPORTS_DIR), Path(config.HACK_WED_DIR)):
        if folder.exists():
            files.extend(folder.glob("*.html"))
    seen: dict[str, Path] = {}
    for p in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
        seen.setdefault(p.name, p)
    return list(seen.values())


def _collect_json_scans() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rdir = Path(config.RESULTS_DIR)
    if not rdir.exists():
        return out
    for jf in sorted(rdir.glob("*.json"), reverse=True)[:12]:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            out.append({
                "file": jf.name,
                "scan_id": data.get("scan_id", jf.stem),
                "target": data.get("target", ""),
                "mode": data.get("mode", ""),
                "duration": data.get("duration", 0),
            })
        except Exception:
            continue
    return out


def execute_web_scan(
    engine: Any,
    target_url: str,
    mode_str: str = "active",
    extra_scope_str: str = "",
) -> dict[str, Any]:
    url = _normalize_url(target_url)
    if not url:
        raise ValueError("Target URL is required.")

    mode_map = {
        "passive": ScanMode.PASSIVE,
        "active": ScanMode.ACTIVE,
        "advanced": ScanMode.ADVANCED,
    }
    mode = mode_map.get((mode_str or "active").strip().lower(), ScanMode.ACTIVE)
    extra_domains = [
        d.strip() for d in (extra_scope_str or "").split(",") if d.strip()
    ]

    target = Target(
        url=url,
        scope_domains=extra_domains,
        allow_subdomains=True,
        authorization_confirmed=True,
    )
    if not target.is_valid():
        raise ValueError("Invalid target URL or host format.")

    guard = ScopeGuard(target)
    engine.services["http"] = HttpClient(guard)

    cfg = ScanConfig(
        target_url=url,
        mode=mode,
        scope=Scope(domains=extra_domains, allow_subdomains=True),
        authorization_confirmed=True,
    )
    report = engine.run(cfg)
    ordered = collect_findings(report)
    triaged = triage_findings(ordered)
    json_path = build_json_report(report)
    html_path = build_html_report(report)
    hack_wed_path = export_html_to_hack_wed(html_path)

    finding_cards = [
        {
            "severity": f.severity.value.upper(),
            "title": f.title,
            "module": f.module,
            "url": f.affected_url,
            "description": f.description,
            "score": score_finding(f),
            "status": f.verification_status.value,
        }
        for f in ordered
    ]

    return {
        "scan_id": report.scan_id,
        "target_url": url,
        "mode": mode.value,
        "duration": round(report.total_duration, 2),
        "findings_count": len(ordered),
        "triaged_count": len(triaged),
        "json_path": str(json_path),
        "html_path": str(html_path),
        "hack_wed_path": str(hack_wed_path),
        "html_name": html_path.name,
        "findings": finding_cards,
    }


def render_hackrwed_html(
    scan_result: dict[str, Any] | None = None,
    error_msg: str | None = None,
    last_url: str = "",
    last_mode: str = "active",
    last_scope: str = "",
) -> str:
    html_reports = _collect_html_reports()
    scans = _collect_json_scans()

    alert_html = ""
    if error_msg:
        alert_html = (
            f"<div class='alert err'>{html.escape(error_msg)}</div>"
        )

    live_section = ""
    if scan_result:
        cards = []
        for item in scan_result.get("findings", []):
            sev = item["severity"]
            cls = sev.lower()
            cards.append(
                f"<div class='fcard' data-sev='{html.escape(sev)}'>"
                f"<div class='fhead'>"
                f"<span class='sev sev-{cls}'>{html.escape(sev)}</span>"
                f"<strong>{html.escape(item['title'])}</strong>"
                f"<span class='score'>score {item['score']}</span>"
                f"</div>"
                f"<div class='fmeta'>{html.escape(item['module'])} · "
                f"{html.escape(item['status'])}</div>"
                f"<div class='fdesc'>{html.escape(item['description'])}</div>"
                f"</div>"
            )
        cards_html = "".join(cards) or (
            "<div class='empty'>No findings reported for this scan.</div>"
        )
        rep_link = (
            f"/hackrwed/report?name={html.escape(scan_result['html_name'])}"
        )
        live_section = f"""
        <div class="card highlight">
          <div class="row-between">
            <div>
              <div class="tag">SCAN COMPLETED</div>
              <h2>{html.escape(scan_result['target_url'])}</h2>
            </div>
            <a class="btn-link" href="{rep_link}">Open HTML Report</a>
          </div>
          <div class="stats">
            <div class="stat"><span>Findings</span><b>{scan_result['findings_count']}</b></div>
            <div class="stat"><span>Mode</span><b>{html.escape(scan_result['mode'])}</b></div>
            <div class="stat"><span>Duration</span><b>{scan_result['duration']}s</b></div>
          </div>
          <div class="paths">
            <div><small>hack wed:</small> {html.escape(scan_result['hack_wed_path'])}</div>
            <div><small>JSON:</small> {html.escape(scan_result['json_path'])}</div>
          </div>
          <div class='fbar'><button type='button' class='fbtn active' data-sev='ALL'>ALL</button><button type='button' class='fbtn' data-sev='HIGH'>HIGH</button><button type='button' class='fbtn' data-sev='MEDIUM'>MEDIUM</button><button type='button' class='fbtn' data-sev='LOW'>LOW</button><button type='button' class='fbtn' data-sev='INFO'>INFO</button></div>
          <div class='fbar'><button type='button' class='fbtn active' data-sev='ALL' onclick="filterFindings('ALL')">ALL</button><button type='button' class='fbtn' data-sev='HIGH' onclick="filterFindings('HIGH')">HIGH</button><button type='button' class='fbtn' data-sev='MEDIUM' onclick="filterFindings('MEDIUM')">MEDIUM</button><button type='button' class='fbtn' data-sev='LOW' onclick="filterFindings('LOW')">LOW</button><button type='button' class='fbtn' data-sev='INFO' onclick="filterFindings('INFO')">INFO</button></div>
          <div class="flist">{cards_html}</div>
        </div>
        """

    rep_items = "".join(
        "<a class='item' href='/hackrwed/report?name="
        f"{html.escape(p.name)}'>"
        f"<span class='fname'>{html.escape(p.name)}</span>"
        f"<span class='fdir'>{html.escape(p.parent.name)}</span>"
        "</a>"
        for p in html_reports
    ) or "<div class='empty'>No HTML reports generated yet.</div>"

    scan_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(s['scan_id']))}</td>"
        f"<td>{html.escape(str(s['target']))}</td>"
        f"<td><span class='badge'>{html.escape(str(s['mode']))}</span></td>"
        f"<td>{html.escape(str(s['duration']))}s</td>"
        "</tr>"
        for s in scans
    ) or "<tr><td colspan='4' class='empty'>No scans yet.</td></tr>"

    sel_p = "selected" if last_mode == "passive" else ""
    sel_a = "selected" if last_mode == "active" else ""
    sel_v = "selected" if last_mode == "advanced" else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>hackrwed · WebGuard Mobile & Web Studio</title>
<style>
:root{{
  --bg:#060a12;--panel:#0d1524;--panel2:#121d32;--line:#1e2f4d;
  --fg:#edf2f7;--mut:#8da2c0;--pri:#10b981;--pri2:#059669;
  --acc:#38bdf8;--pur:#a78bfa;--warn:#f59e0b;--err:#f43f5e;
}}
*{{box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
body{{
  margin:0;padding:16px;
  background:radial-gradient(circle at 15% 0%,#13294b 0%,var(--bg) 52%);
  color:var(--fg);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  line-height:1.45;
}}
.app{{max-width:860px;margin:0 auto}}
.hero{{
  display:flex;justify-content:space-between;align-items:center;gap:12px;
  padding:16px 18px;border-radius:18px;
  background:linear-gradient(135deg,rgba(16,185,129,.14),rgba(56,189,248,.08));
  border:1px solid var(--line);margin-bottom:16px;
}}
.brand{{font-size:21px;font-weight:800;color:var(--pri);letter-spacing:.4px}}
.sub{{font-size:12px;color:var(--mut)}}
.pill{{
  padding:6px 11px;border-radius:999px;font-size:11px;font-weight:700;
  background:rgba(167,139,250,.16);color:var(--pur);border:1px solid rgba(167,139,250,.35);
  white-space:nowrap;
}}
.card{{
  background:var(--panel);border:1px solid var(--line);border-radius:18px;
  padding:16px;margin-bottom:16px;box-shadow:0 14px 34px rgba(0,0,0,.38);
}}
.highlight{{border-color:rgba(16,185,129,.5)}}
h2{{margin:0 0 12px;font-size:15px;font-weight:700;color:var(--fg)}}
.form-grid{{display:grid;grid-template-columns:1fr;gap:12px}}
@media(min-width:640px){{.form-grid{{grid-template-columns:1.6fr 1fr}}}}
label{{display:block;font-size:12px;color:var(--mut);margin-bottom:6px;font-weight:600}}
input,select{{
  width:100%;padding:12px 14px;border-radius:12px;
  background:var(--panel2);border:1px solid var(--line);color:var(--fg);
  font-size:14px;outline:none;
}}
input:focus,select:focus{{border-color:var(--acc)}}
.full{{grid-column:1 / -1}}
.btn{{
  width:100%;padding:13px 18px;border:0;border-radius:13px;
  background:linear-gradient(135deg,var(--pri),var(--pri2));
  color:#04110b;font-weight:800;font-size:14px;cursor:pointer;
  box-shadow:0 8px 22px rgba(16,185,129,.28);
}}
.btn:active{{transform:scale(.99)}}
.btn-link{{
  display:inline-block;padding:8px 12px;border-radius:10px;
  background:rgba(56,189,248,.14);color:var(--acc);text-decoration:none;
  font-size:12px;font-weight:700;border:1px solid rgba(56,189,248,.3);
}}
.row-between{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}}
.tag{{font-size:10px;font-weight:800;letter-spacing:.8px;color:var(--pri)}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:12px 0}}
.stat{{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center}}
.stat span{{display:block;font-size:11px;color:var(--mut)}}
.stat b{{font-size:16px;color:var(--acc)}}
.paths{{font-size:11px;color:var(--mut);background:var(--panel2);padding:10px 12px;border-radius:12px;margin-bottom:12px;word-break:break-all}}
.flist{{display:flex;flex-direction:column;gap:10px}}
.fcard{{background:var(--panel2);border:1px solid var(--line);border-radius:13px;padding:12px}}
.fhead{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.sev{{font-size:10px;font-weight:800;padding:3px 8px;border-radius:999px;background:rgba(56,189,248,.15);color:var(--acc)}}
.sev-high,.sev-critical{{background:rgba(244,63,94,.18);color:var(--err)}}
.sev-medium{{background:rgba(245,158,11,.18);color:var(--warn)}}
.sev-info,.sev-low{{background:rgba(16,185,129,.16);color:var(--pri)}}
.score{{margin-left:auto;font-size:11px;color:var(--mut)}}
.fmeta{{font-size:11px;color:var(--mut);margin-top:4px}}
.fdesc{{font-size:13px;margin-top:6px;color:#d6e0f0}}
.item{{
  display:flex;justify-content:space-between;align-items:center;gap:10px;
  padding:11px 13px;border-radius:12px;background:var(--panel2);
  border:1px solid var(--line);text-decoration:none;margin-bottom:8px;
}}
.fname{{color:var(--acc);font-weight:700;font-size:13px;word-break:break-all}}
.fdir{{font-size:11px;color:var(--mut);background:#09101c;padding:3px 8px;border-radius:999px}}
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}}
th{{color:var(--mut);font-size:11px}}
.badge{{background:rgba(16,185,129,.15);color:var(--pri);padding:2px 8px;border-radius:999px;font-weight:700}}
.alert{{padding:12px 14px;border-radius:12px;margin-bottom:14px;font-size:13px;font-weight:600}}
.err{{background:rgba(244,63,94,.15);border:1px solid rgba(244,63,94,.4);color:#fecdd3}}
.empty{{color:var(--mut);font-size:13px;padding:6px 0}}
.fbar{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}}
.fbtn{{padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:var(--panel2);color:var(--mut);font-size:11px;font-weight:700;cursor:pointer}}
.fbtn.active{{background:rgba(16,185,129,.2);color:var(--pri);border-color:var(--pri)}}
</style>
</head>
<body>
<div class="app">
  <div class="hero">
    <div>
      <div class="brand">✦ hackrwed</div>
      <div class="sub">WebGuard Mobile & Browser Scan Console</div>
    </div>
    <div class="pill">LIVE ENGINE</div>
  </div>

  {alert_html}

  <div class="card">
    <h2>Launch Security Scan</h2>
    <form class="form-grid" method="POST" action="/hackrwed/scan">
      <div>
        <label for="target_url">Target URL</label>
        <input id="target_url" name="target_url" type="text"
               value="{html.escape(last_url)}"
               placeholder="https://example.com" required>
      </div>
      <div>
        <label for="mode">Scan Mode</label>
        <select id="mode" name="mode">
          <option value="passive" {sel_p}>Passive</option>
          <option value="active" {sel_a}>Active (Recommended)</option>
          <option value="advanced" {sel_v}>Advanced</option>
        </select>
      </div>
      <div class="full">
        <label for="extra_scope">Extra Scope Domains (optional, comma-separated)</label>
        <input id="extra_scope" name="extra_scope" type="text"
               value="{html.escape(last_scope)}"
               placeholder="api.example.com, app.example.com">
      </div>
      <div class="full">
        <button class="btn" type="submit">▶ Run Scan & Export to hack wed</button>
      </div>
    </form>
  </div>

  {live_section}

  <div class="card">
    <h2>HTML Reports ({len(html_reports)})</h2>
    {rep_items}
  </div>

  <div class="card">
    <h2>Recent Scans ({len(scans)})</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Scan ID</th><th>Target</th><th>Mode</th><th>Time</th></tr></thead>
        <tbody>{scan_rows}</tbody>
      </table>
    </div>
  </div>
</div>

<script>
function filterFindings(sev) {{
  document.querySelectorAll('.fbtn').forEach(function(b) {{
    b.classList.toggle('active', b.getAttribute('data-sev') === sev);
  }});
  document.querySelectorAll('.fcard').forEach(function(card) {{
    var csev = card.getAttribute('data-sev') || '';
    card.style.display = (sev === 'ALL' || csev === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def _make_handler(engine: Any | None = None):
    class HackRwHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _send_html(self, body: str, status: int = 200) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/hackrwed"):
                self._send_html(render_hackrwed_html(), 200)
                return
            if parsed.path == "/hackrwed/report":
                qs = parse_qs(parsed.query)
                name = Path((qs.get("name") or [""])[0]).name
                for folder in (
                    Path(config.HACK_WED_DIR),
                    Path(config.REPORTS_DIR),
                ):
                    candidate = folder / name
                    if name and candidate.is_file():
                        self._send_html(
                            candidate.read_text(encoding="utf-8"), 200
                        )
                        return
                self._send_html("<h1>Report not found</h1>", 404)
                return
            self._send_html("<h1>404 Not Found</h1>", 404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/hackrwed/scan":
                self._send_html("<h1>404 Not Found</h1>", 404)
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            form = parse_qs(raw_body)
            target_url = (form.get("target_url") or [""])[0]
            mode_str = (form.get("mode") or ["active"])[0]
            extra_scope = (form.get("extra_scope") or [""])[0]

            if engine is None:
                from main import build_engine
                active_engine = build_engine()
            else:
                active_engine = engine

            try:
                result = execute_web_scan(
                    active_engine,
                    target_url=target_url,
                    mode_str=mode_str,
                    extra_scope_str=extra_scope,
                )
                page = render_hackrwed_html(
                    scan_result=result,
                    last_url=target_url,
                    last_mode=mode_str,
                    last_scope=extra_scope,
                )
                self._send_html(page, 200)
            except Exception as exc:
                page = render_hackrwed_html(
                    error_msg=str(exc),
                    last_url=target_url,
                    last_mode=mode_str,
                    last_scope=extra_scope,
                )
                self._send_html(page, 400)

    return HackRwHandler


def serve_hackrwed(
    host: str = "127.0.0.1",
    port: int = 8765,
    engine: Any | None = None,
) -> None:
    server = ThreadingHTTPServer((host, port), _make_handler(engine=engine))
    print(f"hackrwed mobile/web UI running at http://{host}:{port}/hackrwed")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
