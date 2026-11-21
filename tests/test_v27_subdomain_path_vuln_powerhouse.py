from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.subdomain_path_and_vuln_powerhouse import SubdomainPathAndVulnPowerhouseModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://pwr.test/search?q=1"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_subdomain_path_and_vuln_powerhouse():
    def _route(u, kw):
        hdrs = kw.get("headers") or {}
        if u.endswith("/.git/HEAD"):
            return _Resp(200, "ref: refs/heads/main", {}, u)
        if u.endswith("/admin"):
            if hdrs.get("X-Forwarded-For") == "127.0.0.1":
                return _Resp(200, "<html>Admin Console</html>", {}, u)
            return _Resp(403, "forbidden", {}, u)
        if "wg_inj_77" in u:
            return _Resp(200, "wg_inj_77'\"<> SQL syntax error near wg_inj_77", {}, u)
        return _Resp(
            200,
            "<html>ok</html>",
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "https://pwr.test/search?q=1",
        )

    t = Target(url="https://pwr.test/search?q=1", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_pwr1", ScanMode.ADVANCED, EventBus())
    res = SubdomainPathAndVulnPowerhouseModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    assert "Permissive CORS wildcard combined with credentials" in titles
    assert "High-signal exposure/listing cues on paths" in titles
    assert "Access status shift on restricted path(s)" in titles
    assert "SQL/template error or evaluation cue on param(s): q" in titles
    assert "Raw special chars reflected on param(s): q" in titles
