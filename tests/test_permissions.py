from core.permissions import module_allowed
from models.module import BaseModule, ScanMode

class _M(BaseModule):
    name = "m"
    required_mode = ScanMode.ACTIVE
    required_capabilities = ["http"]

def test_mode_ok():
    ok, _ = module_allowed(_M(), ScanMode.ACTIVE, {"http"})
    assert ok

def test_mode_too_low():
    ok, reason = module_allowed(_M(), ScanMode.PASSIVE, {"http"})
    assert not ok
    assert "mode" in reason

def test_missing_capability():
    ok, reason = module_allowed(_M(), ScanMode.ADVANCED, set())
    assert not ok
    assert "missing" in reason
