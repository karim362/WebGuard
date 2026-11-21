from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.omni_identity_and_secret_radar import OmniIdentityAndSecretRadarModule


class _Resp:
    def __init__(self, code=200, text="", url="https://radar.test/"):
        self.status_code = code
        self.text = text
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_omni_identity_and_secret_radar():
    def _route(u, kw):
        if u.endswith("/app.js"):
            return _Resp(200, 'const cfg = { username: "root_ops", api_key: "sk_live_999888" };', u)
        if u.endswith("/login"):
            return _Resp(
                200,
                '<form><input name="email" value="team@radar.test"><input type="hidden" name="hidden_user" value="sec_bot"><input type="password" name="pass" value="P@ss1234"></form>',
                u,
            )
        return _Resp(
            200,
            '<html><body><script src="/app.js"></script><a href="/login">Login</a><link rel="stylesheet" href="/theme.css"></body></html>',
            "https://radar.test/",
        )

    t = Target(url="https://radar.test/", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_rad47", ScanMode.ADVANCED, EventBus())
    res = OmniIdentityAndSecretRadarModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    info_f = [f for f in res.findings if f.title.startswith("Omni radar captured")][0]
    high_f = [f for f in res.findings if f.title.startswith("Exposed visible/hidden")][0]
    assert "Omni radar captured emails, usernames, and password/secret cues" in titles
    assert "Exposed visible/hidden passwords, secrets, or tokens" in titles
    assert "email:team@radar.test @ https://radar.test/login" in info_f.description
    assert "kv_user(username: \"root_ops\") @ https://radar.test/app.js" in info_f.description
    assert "pass/secret[visible:password:pass=P@ss1234] @ https://radar.test/login" in info_f.description
    assert "https://radar.test/login" in info_f.affected_url
    assert "https://radar.test/app.js" in high_f.description
