"""Technology fingerprinting from headers + HTML meta (passive)."""
from __future__ import annotations
import re
from core.execution_manager import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (
    Confidence, Evidence, EvidenceType, Finding, Severity, VerificationStatus,
)

FRAMEWORK_HINTS = {
    "wordpress": r"wp-content|wp-includes",
    "drupal": r"sites/default|drupal",
    "joomla": r"/media/system/js/|joomla",
    "react": r"__REACT_DEVTOOLS|react-dom",
    "vue": r"__VUE__|vue\.js",
    "angular": r"ng-version|angular",
    "nextjs": r"__NEXT_DATA__|_next/static",
    "nuxt": r"__NUXT__|_nuxt/",
    "shopify": r"cdn\.shopify\.com|shopify",
    "cloudflare": r"cloudflare",
}

SERVER_HINTS = {
    "nginx": r"nginx",
    "apache": r"apache",
    "iis": r"microsoft-iis",
    "cloudflare": r"cloudflare",
    "vercel": r"vercel",
    "netlify": r"netlify",
}

class TechnologyModule(BaseModule):
    name = "technology_detect"
    version = "0.4.0"
    description = "Fingerprints frameworks and servers from headers/HTML."
    required_mode = ScanMode.PASSIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        try:
            response = context.services["http"].get(context.target.url)
        except Exception as e:
            result.status = ModuleStatus.FAILED
            result.errors.append(f"request failed: {e}")
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = ""
        try:
            body = response.text[:200_000]
        except Exception:
            pass

        detected: list[str] = []

        # Server header
        server = headers.get("server", "").lower()
        for name, pat in SERVER_HINTS.items():
            if re.search(pat, server):
                detected.append(f"server:{name}")

        # X-Powered-By
        powered = headers.get("x-powered-by", "").lower()
        if powered:
            detected.append(f"x-powered-by:{powered}")

        # HTML meta generator
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                      body, re.IGNORECASE)
        if m:
            detected.append(f"generator:{m.group(1)[:80]}")

        # Framework hints from body
        body_lower = body.lower()
        for name, pat in FRAMEWORK_HINTS.items():
            if re.search(pat, body_lower):
                detected.append(f"framework:{name}")

        if not detected:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("No technologies fingerprinted.")
            return result

        result.findings.append(Finding(
            title=f"Detected technologies ({len(detected)})",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            category="reconnaissance",
            target=context.target.host,
            affected_url=str(response.url),
            description="Technologies inferred from headers and HTML content.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
            evidence=[Evidence(
                type=EvidenceType.LOG,
                content="\n".join(detected),
                note="Passive fingerprint",
            )],
        ))
        return result
