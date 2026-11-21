from services.scope_store import ScopeStore
from models.scope import Scope

def test_save_load_roundtrip(tmp_path):
    store = ScopeStore(base_dir=tmp_path)
    scope = Scope(domains=["api.example.com"], allow_subdomains=True)
    store.save("https://example.com", scope, notes="test")
    loaded = store.load("https://example.com")
    assert loaded is not None
    s2, notes = loaded
    assert "api.example.com" in s2.domains
    assert notes == "test"

def test_list_saved(tmp_path):
    store = ScopeStore(base_dir=tmp_path)
    store.save("https://example.com", Scope(domains=[]))
    store.save("https://foo.org", Scope(domains=[]))
    assert len(store.list_saved()) == 2
