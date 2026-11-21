import pytest
from core.scope_guard import ScopeGuard, ScopeViolation
from models.target import Target

def _target(url="https://example.com", scope=None, confirm=True, sub=True):
    return Target(url=url, scope_domains=scope or [],
                  allow_subdomains=sub, authorization_confirmed=confirm)

def test_requires_authorization():
    with pytest.raises(ScopeViolation):
        ScopeGuard(_target(confirm=False))

def test_rejects_invalid_scheme():
    with pytest.raises(ScopeViolation):
        ScopeGuard(Target(url="ftp://example.com", authorization_confirmed=True))

def test_allows_target_host():
    g = ScopeGuard(_target())
    assert g.is_url_allowed("https://example.com/path")
    assert g.is_host_allowed("example.com")

def test_allows_subdomain_by_default():
    g = ScopeGuard(_target())
    assert g.is_url_allowed("https://api.example.com/v1")
    assert g.is_host_allowed("deep.api.example.com")

def test_blocks_outside_domain():
    g = ScopeGuard(_target())
    assert not g.is_url_allowed("https://evil.com/")
    assert not g.is_url_allowed("https://notexample.com/")

def test_subdomain_off():
    g = ScopeGuard(_target(sub=False))
    assert g.is_url_allowed("https://example.com/")
    assert not g.is_url_allowed("https://api.example.com/")

def test_extra_scope_domain():
    g = ScopeGuard(_target(scope=["api.example.com"]))
    assert g.is_host_allowed("api.example.com")

def test_assert_raises():
    g = ScopeGuard(_target())
    with pytest.raises(ScopeViolation):
        g.assert_url_allowed("https://evil.com/")
