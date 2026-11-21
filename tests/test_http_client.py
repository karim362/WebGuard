"""Tests for HttpClient scope enforcement — no real network."""
import pytest
from core.scope_guard import ScopeGuard, ScopeViolation
from models.target import Target
from services.http_client import HttpClient

def _client(scope_domains=None):
    t = Target(url="https://example.com", scope_domains=scope_domains or [],
               authorization_confirmed=True)
    g = ScopeGuard(t)
    return HttpClient(scope_guard=g, rate_limit=0, max_requests=10)

def test_rejects_out_of_scope_url():
    c = _client()
    with pytest.raises(ScopeViolation):
        c.get("https://evil.com/")

def test_safe_headers_strip_cookies_out_of_scope():
    c = _client()
    c.cookies = {"session": "secret"}
    assert "Cookie" in c._safe_headers_for("https://example.com/")
    assert "Cookie" not in c._safe_headers_for("https://evil.com/")

def test_redirect_to_out_of_scope_blocked():
    """Mock via monkeypatch: simulate 302 -> evil.com and expect ScopeViolation."""
    import httpx
    c = _client()

    class FakeResponse:
        def __init__(self, status, headers=None):
            self.status_code = status
            self.headers = headers or {}
            self.is_redirect = 300 <= status < 400
        def json(self): return {}
    real_client = httpx.Client
    calls = {"n": 0}
    def fake_request(self, method, url, headers=None, **kw):
        calls["n"] += 1
        return FakeResponse(302, {"location": "https://evil.com/"})
    monkeypatch_ok = True
    old = httpx.Client.request
    httpx.Client.request = fake_request
    try:
        with pytest.raises(ScopeViolation):
            c.get("https://example.com/")
    finally:
        httpx.Client.request = old
