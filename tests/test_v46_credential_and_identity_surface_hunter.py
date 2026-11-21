from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard
from models.module import ScanMode
from models.target import Target
from modules.vulnerability.credential_and_identity_surface_hunter import CredentialAndIdentitySurfaceHunterModule


class _Resp:
    def __init__(self, code=200, text="", url="https://idlab.test/login"):
        self.status_code = code
        self.text = text
        self.url = url


class _Http:
    def __init__(self, fn):
        self.fn = fn

    def get(self, url, **kw):
        return self.fn(url, kw)


def test_credential_and_identity_surface_hunter():
    def _route(u, kw):
        if u.endswith("/account"):
            return _Resp(
                200,
                '<div>admin@idlab.test <input type="hidden" name="username" value="ops_admin"><input type="hidden" name="secret_pin" value="987654"></div>',
                u,
            )
        return _Resp(
            200,
            '<html><body><form><input type="text" name="username"><input type="password" name="password"></form><link rel="stylesheet" href="/style.css"></body></html>',
            "https://idlab.test/login",
        )

    t = Target(url="https://idlab.test/login", authorization_confirmed=True)
    ctx = ModuleContext(t, ScopeGuard(t), {"http": _Http(_route)}, "s_id46", ScanMode.ADVANCED, EventBus())
    res = CredentialAndIdentitySurfaceHunterModule().run(ctx)
    titles = " ".join(f.title for f in res.findings)
    info_f = [f for f in res.findings if f.title.startswith("Captured emails")][0]
    high_f = [f for f in res.findings if f.title.startswith("Exposed password")][0]
    assert "Captured emails, usernames, and password/credential fields" in titles
    assert "Exposed password or credential cues detected" in titles
    assert "admin@idlab.test" in info_f.description
    assert "user[hidden:username=ops_admin]" in info_f.description
    assert "pass(visible:password)" in info_f.description
    assert "https://idlab.test/login" in info_f.affected_url
    assert "https://idlab.test/account" in high_f.description
