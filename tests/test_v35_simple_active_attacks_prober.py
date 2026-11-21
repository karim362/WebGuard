from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.simple_active_attacks_prober import SimpleActiveAttacksProberModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://atk.test/item?id=1&next=/home"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_simple_active_attacks_prober():
    def _route(u, kw):
        if "wg_xss<img/src=x>" in u:
            return _Resp(200, "<div>wg_xss<img/src=x></div>", {}, u)
        if u.endswith("id=%27") or u.endswith("id='"):
            return _Resp(500, "SQL syntax error near '''", {}, u)
        if "etc/passwd" in u or "etc%2Fpasswd" in u:
            return _Resp(200, "root:x:0:0:root:/root:/bin/bash", {}, u)
        if "example.invalid/wg_redir" in u:
            return _Resp(302, "", {"Location": "https://example.invalid/wg_redir"}, u)
        if u.endswith("/.env"):
            return _Resp(200, "APP_ENV=prod", {}, u)
        return _Resp(200, "<html>ok</html>", {}, "https://atk.test/item?id=1&next=/home")

    t = Target(url="https://atk.test/item?id=1&next=/home", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_atk1", ScanMode.ACTIVE, EventBus())
    res = SimpleActiveAttacksProberModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Simple active probe hits on parameter(s)" in titles
    assert "Simple XSS, redirect, or path signals" in titles
