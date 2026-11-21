from models.scope import Scope

def test_normalize_strips_wildcards():
    s = Scope(domains=["*.Example.com", "API.example.org", "*.example.com"])
    s.normalize()
    assert s.domains == ["example.com", "api.example.org"]

def test_is_empty():
    assert Scope().is_empty()
    assert not Scope(domains=["a.com"]).is_empty()
