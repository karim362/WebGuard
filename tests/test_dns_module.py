from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.reconnaissance.dns import DnsReconModule

class _FakeDns:
    def available(self): return True
    def all(self, name):
        return {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": ["a.iana-servers.net"], "TXT": []}
    def resolve_exists(self, name): return False

def _ctx(dns):
    t = Target(url="https://example.com", authorization_confirmed=True)
    return ModuleContext(
        target=t, scope_guard=ScopeGuard(t),
        services={"dns": dns}, scan_id="s", mode=ScanMode.PASSIVE,
        events=EventBus(),
    )

def test_dns_module_reports_records():
    m = DnsReconModule()
    r = m.run(_ctx(_FakeDns()))
    titles = [f.title for f in r.findings]
    assert any("DNS records" in t for t in titles)
    # SPF missing -> finding
    assert any("SPF" in t for t in titles)
