from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.discovery import DiscoveredURL, DiscoveryResult
from models.module import ScanMode
from models.target import Target
from modules.discovery.endpoints import EndpointsModule


def _ctx(discovery):
    t = Target(
        url="https://example.com/",
        authorization_confirmed=True,
    )
    return ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"discovery": discovery},
        scan_id="s",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )


def test_flags_sensitive_paths():
    d = DiscoveryResult(urls=[
        DiscoveredURL(url="https://example.com/admin"),
        DiscoveredURL(url="https://example.com/api/v1/users"),
        DiscoveredURL(url="https://example.com/about"),
    ])
    r = EndpointsModule().run(_ctx(d))
    titles = [f.title for f in r.findings]
    assert any("Sensitive" in t for t in titles)
