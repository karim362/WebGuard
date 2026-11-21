"""GraphQL endpoint presence and introspection review."""
from __future__ import annotations
import re
from urllib.parse import urljoin
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

GQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")


def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class GraphqlReviewModule(BaseModule):
    name = "graphql_review"
    version = "0.7.0"
    description = "Checks GraphQL endpoints and introspection."
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        base = context.target.url.rstrip("/") + "/"
        http = context.services["http"]
        found = 0

        for path in GQL_PATHS:
            url = urljoin(base, path.lstrip("/"))
            try:
                r = http.get(url)
            except Exception as e:
                result.errors.append(f"{path}: {e}")
                continue
            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""
            low = body.lower()
            is_gql = code in (200, 400, 405) and (
                "graphql" in low
                or "errors" in low
                or "__schema" in low
                or code == 405
            )
            if not is_gql:
                continue
            found += 1
            intro = "__schema" in body or "__type" in body
            sev = Severity.MEDIUM if intro else Severity.INFO
            ver = (
                VerificationStatus.CONFIRMED
                if intro
                else VerificationStatus.POTENTIAL
            )
            desc = (
                "Schema markers visible."
                if intro
                else f"Endpoint responded with {code}."
            )
            result.findings.append(Finding(
                title=f"GraphQL endpoint detected: {path}",
                severity=sev,
                confidence=Confidence.MEDIUM,
                category="api_security",
                target=context.target.host,
                affected_url=_first_direct_url(str(desc), ""),
                description=desc,
                module=self.name,
                scan_id=context.scan_id,
                verification_status=ver,
            ))

        if found == 0:
            result.status = ModuleStatus.PARTIAL
            result.errors.append("no GraphQL endpoint detected")
        return result
