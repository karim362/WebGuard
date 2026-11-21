import re
"""Example passive module — proves engine + scope + DI loop. No network."""
from core.engine import ModuleContext
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import Confidence, Finding, Severity, VerificationStatus

def _first_direct_url(text: str, fallback: str) -> str:
    m = re.search(r"https?://[^\s|\"';<>)]+", text or "")
    return m.group(0) if m else fallback


class ExamplePassiveModule(BaseModule):
    name = "example_passive"
    version = "0.1.0"
    description = "Smoke-test module: reports target host as info finding."
    required_mode = ScanMode.PASSIVE
    required_capabilities = []
    requires_auth = False

    def run(self, context: ModuleContext) -> ModuleResult:
        finding = Finding(
            title="Target host identified",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="reconnaissance",
            target=context.target.host,
            affected_url=_first_direct_url(str(f"Target host is {context.target.host}."), ""),
            description=f"Target host is {context.target.host}.",
            module=self.name,
            scan_id=context.scan_id,
            verification_status=VerificationStatus.CONFIRMED,
        )
        return ModuleResult(module_name=self.name,
                            status=ModuleStatus.SUCCESS,
                            findings=[finding])
