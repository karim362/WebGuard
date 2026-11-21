"""Deep path probing, JS endpoint/leak extraction, and exposed artifact checks."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
from core.execution_manager import ModuleContext
from models.module import (
    BaseModule,
    ModuleResult,
    ModuleStatus,
    ScanMode,
)
from models.result import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)

DEEP_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/config.php",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/server-status",
    "/swagger.json",
    "/openapi.json",
    "/api",
    "/api/v1",
    "/graphql",
    "/backup.zip",
    "/db.sql",
    "/debug",
)

_HREF_SRC_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#?]+(?:\?[^"']*)?)["']""",
    re.I,
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_KEY_HINT_RE = re.compile(
    r"""(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|aws_secret_access_key|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-\.\/+=]{10,})["']?"""
)
_API_PATH_RE = re.compile(
    r"""["']((?:/api/|/v[1-9]/|/admin|/graphql|/auth|/user)[A-Za-z0-9_./-]{1,80})["']"""
)


def _redact_secret(val: str) -> str:
    s = val.strip()
    if len(s) <= 8:
        return "***"
    return f"{s[:4]}...{s[-3:]}"


def _is_real_sensitive_hit(path: str, status: int, body: str) -> tuple[bool, str, Severity]:
    if status != 200 or not body:
        return False, "", Severity.INFO
    low = body.lower()
    if path == "/.git/HEAD" and "ref: refs/" in low:
        return True, "Exposed .git/HEAD repository reference.", Severity.HIGH
    if path == "/.env" and any(k in low for k in ("db_password", "app_key", "secret_key", "api_key", "database_url")):
        return True, "Exposed .env configuration containing sensitive keys.", Severity.CRITICAL
    if "phpinfo()" in low or "zend engine" in low:
        return True, "PHP info diagnostic output exposed.", Severity.MEDIUM
    if path in ("/swagger.json", "/openapi.json") and ('"openapi"' in low or '"swagger"' in low or '"paths"' in low):
        return True, "API schema definition publicly exposed.", Severity.LOW
    if path in ("/backup.zip", "/db.sql") and len(body) > 20 and "<html" not in low:
        return True, "Potentially sensitive backup/dump artifact reachable.", Severity.HIGH
    return False, "", Severity.INFO


class DeepSurfaceAndLeaksModule(BaseModule):
    name = "deep_surface_and_leaks"
    version = "1.0.0"
    description = "Inspects discovered links/JS, sensitive paths, and leak patterns in scope."
    required_mode = ScanMode.ADVANCED
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        http = context.services["http"]
        guard = context.scope_guard
        base_url = context.target.url

        try:
            root_resp = http.get(base_url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"root fetch failed: {e}")
            return result

        root_html = getattr(root_resp, "text", "") or ""
        candidate_urls: list[str] = []
        seen_urls: set[str] = set()

        def _add_url(u: str) -> None:
            full = urljoin(base_url, u.strip())
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return
            if guard is not None and hasattr(guard, "is_allowed"):
                if not guard.is_allowed(full):
                    return
            if full not in seen_urls:
                seen_urls.add(full)
                candidate_urls.append(full)

        for m in _HREF_SRC_RE.finditer(root_html):
            _add_url(m.group(1))
            if len(candidate_urls) >= 35:
                break

        for p in DEEP_PATHS:
            _add_url(urljoin(base_url.rstrip("/") + "/", p.lstrip("/")))

        emails: set[str] = set()
        leaks: list[tuple[str, str]] = []
        api_routes: set[str] = set()
        js_urls: list[str] = []

        for u in candidate_urls:
            if u.lower().endswith(".js") and len(js_urls) < 8:
                js_urls.append(u)

        for p in DEEP_PATHS:
            probe_url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
            if guard is not None and hasattr(guard, "is_allowed") and not guard.is_allowed(probe_url):
                continue
            try:
                resp = http.get(probe_url)
            except Exception:
                continue
            code = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "") or ""
            matched, desc, sev = _is_real_sensitive_hit(p, code, body)
            if matched:
                result.findings.append(Finding(
                    title=f"Sensitive path exposed ({code}): {p}",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    category="exposure",
                    target=context.target.host,
                    affected_url=str(getattr(resp, "url", probe_url)),
                    description=desc,
                    module=self.name,
                    scan_id=context.scan_id,
                    verification_status=VerificationStatus.CONFIRMED,
                ))

        scan_corpus = [root_html]
        for ju in js_urls:
            try:
                jr = http.get(ju)
                jtxt = getattr(jr, "text", "") or ""
                if jtxt:
                    scan_corpus.append(jtxt[:120000])
            except Exception:
                continue

        for blob in scan_corpus:
            for em in _EMAIL_RE.findall(blob):
                if not em.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
                    emails.add(em)
                    if len(emails) >= 15:
                        break
            for km in _KEY_HINT_RE.finditer(blob):
                red = _redact_secret(km.group(1))
                leaks.append((km.group(0).split("=")[0].strip(), red))
                if len(leaks) >= 10:
                    break
            for ap in _API_PATH_RE.finditer(blob):
                api_routes.add(ap.group(1))
                if len(api_routes) >= 20:
                    break

        if emails:
            sample = ", ".join(sorted(emails)[:5])
            result.findings.append(Finding(
                title=f"Discovered {len(emails)} email address(es) in surface",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=context.target.host,
                affected_url=base_url,
                description=f"Sample addresses: {sample}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if leaks:
            summary = ", ".join(f"{k}={v}" for k, v in leaks[:4])
            result.findings.append(Finding(
                title=f"Potential key/token patterns ({len(leaks)}) in response/JS",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                category="exposure",
                target=context.target.host,
                affected_url=base_url,
                description=f"Redacted matches: {summary} — verify manually.",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.NEEDS_REVIEW,
            ))

        if api_routes:
            sample_routes = ", ".join(sorted(api_routes)[:6])
            result.findings.append(Finding(
                title=f"Extracted {len(api_routes)} API/app route candidate(s)",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="recon",
                target=context.target.host,
                affected_url=base_url,
                description=f"Candidates: {sample_routes}",
                module=self.name,
                scan_id=context.scan_id,
                verification_status=VerificationStatus.CONFIRMED,
            ))

        if not result.findings:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no deep exposure or leak indicators found")
        return result
