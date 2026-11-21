from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.version_targeted_probe import VersionTargetedProbeModule


class _Resp:
    def __init__(self, code=200, text="", headers=None, url="https://phpapp.test/item?id=5"):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_version_targeted_probe_detects_php_info_and_errors():
    def _route(u, kw):
        if u.endswith("/phpinfo.php"):
            return _Resp(200, "<html><h1>PHP Version 8.2.36</h1><p>Zend Engine</p></html>", {}, u)
        if "id=1%27" in u or "id=1'" in u:
            return _Resp(200, "Warning: mysqli_fetch_array() expects parameter 1 in /var/www/html/app.php on line 42", {}, u)
        return _Resp(
            200,
            '<meta name="generator" content="CustomCMS 3.4"><div>ok</div>',
            {"X-Powered-By": "PHP/8.2.36"},
            "https://phpapp.test/item?id=5",
        )

    t = Target(url="https://phpapp.test/item?id=5", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_vtp1", ScanMode.ACTIVE, EventBus())
    res = VersionTargetedProbeModule().run(ctx)

    titles = " ".join(f.title for f in res.findings)
    assert "PHP diagnostic page exposed with PHP/8.2.36" in titles
    assert "PHP runtime error output triggered on PHP/8.2.36" in titles
    assert "Site/generator version identified: CustomCMS 3.4" in titles
