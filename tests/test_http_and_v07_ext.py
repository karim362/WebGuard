import base64
import json
from urllib.parse import urlparse
import pytest
from core.event_bus import EventBus
from core.execution_manager import ModuleContext
from core.scope_guard import ScopeGuard, ScopeViolation
from models.module import ScanMode
from models.target import Target
from modules.authentication.jwt_review import JwtReviewModule
from modules.api_security.graphql_review import GraphqlReviewModule
from services.http_client import HttpClient


def _b64(obj: dict) -> str:
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_http_client_blocks_out_of_scope():
    t = Target(url="https://example.com", authorization_confirmed=True)
    client = HttpClient(ScopeGuard(t), rate_limit=0)
    with pytest.raises(ScopeViolation):
        client.get("https://evil.com/steal")


def test_http_client_validate_hops_blocks_redirect():
    t = Target(url="https://example.com", authorization_confirmed=True)
    client = HttpClient(ScopeGuard(t), rate_limit=0)

    class _Hop:
        url = "https://example.com/login"

    class _Resp:
        history = [_Hop()]
        headers = {}
        url = "https://evil.com/phish"

    with pytest.raises(ScopeViolation):
        client._validate_hops(_Resp())


def test_jwt_review_detects_none_alg():
    hdr = _b64({"alg": "none", "typ": "JWT"})
    pay = _b64({"sub": "user_42", "role": "guest"})
    token = f"{hdr}.{pay}.sig_placeholder_123"

    class _R:
        status_code = 200
        url = "https://x.com/"
        headers = {}
        text = f"bearer {token}"

    class _Http:
        def get(self, url, **kw):
            return _R()

    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http()},
        scan_id="s_jwt",
        mode=ScanMode.PASSIVE,
        events=EventBus(),
    )
    res = JwtReviewModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].severity.value == "high"


def test_graphql_review_detects_endpoint():
    class _R:
        def __init__(self, code, text=""):
            self.status_code = code
            self.text = text
            self.url = "https://x.com/graphql"

    class _Http:
        def get(self, url, **kw):
            path = urlparse(url).path.rstrip("/")
            if path == "/graphql":
                return _R(
                    200,
                    '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                )
            return _R(404)

    t = Target(url="https://x.com/", authorization_confirmed=True)
    ctx = ModuleContext(
        target=t,
        scope_guard=ScopeGuard(t),
        services={"http": _Http()},
        scan_id="s_gql",
        mode=ScanMode.ACTIVE,
        events=EventBus(),
    )
    res = GraphqlReviewModule().run(ctx)
    assert len(res.findings) == 1
    assert res.findings[0].severity.value == "medium"
