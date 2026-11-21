from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.reporting.results_organizer_and_deduplicator import ResultsOrganizerAndDeduplicatorModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://org.test/login"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_results_organizer_and_deduplicator():
    def _route(u, kw):
        return _Resp(
            200,
            "<html>login</html>",
            {"Set-Cookie": "XSRF-TOKEN=abc; Path=/", "Cache-Control": "no-cache"},
            "https://org.test/login",
        )

    t = Target(url="https://org.test/login", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_org42", ScanMode.ADVANCED, EventBus())
    ctx.findings = [
        {"title": "XSRF-TOKEN missing HttpOnly", "description": "dup 1"},
        {"title": "XSRF-TOKEN missing HttpOnly", "description": "dup 2"},
        {"title": "SQL syntax error near id", "description": "high cue"},
        {"title": "Target host identified", "description": "host org.test"},
    ]
    res = ResultsOrganizerAndDeduplicatorModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    med_desc = " ".join(f.description for f in res.findings if "MEDIUM" in f.title)
    assert "Organized HIGH priority signals (1 unique)" in titles
    assert "Organized MEDIUM priority & hardening signals (1 unique)" in titles
    assert "Organized INFO & surface notes (1 unique)" in titles
    assert med_desc.lower().count("xsrf-token missing httponly") == 1
