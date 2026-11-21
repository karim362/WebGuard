from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.result import (Confidence, Evidence, EvidenceType, Finding,
                           Severity, VerificationStatus)
from models.scan_config import ScanConfig
from models.scope import Scope
from models.target import Target

def test_target_host_parsing():
    t = Target(url="https://example.com/path?q=1", authorization_confirmed=True)
    assert t.host == "example.com"
    assert t.is_valid()

def test_finding_defaults():
    f = Finding(title="t", severity=Severity.LOW, confidence=Confidence.MEDIUM,
                category="c", target="example.com", affected_url="/",
                description="d", module="m")
    assert f.id and f.verification_status == VerificationStatus.POTENTIAL

def test_scan_config_defaults():
    c = ScanConfig(target_url="https://example.com", authorization_confirmed=True)
    assert c.mode == ScanMode.PASSIVE
    assert c.extra_scope == []

def test_engine_end_to_end():
    from core.engine import Engine
    from core.event_bus import EventBus
    from core.module_manager import ModuleManager
    manager = ModuleManager("modules"); manager.discover()
    bus = EventBus()
    seen = {"started": False, "finished": False, "findings": 0}
    bus.on("scan_started", lambda **kw: seen.update(started=True))
    bus.on("scan_finished", lambda **kw: seen.update(finished=True))
    bus.on("finding", lambda **kw: seen.update(findings=seen["findings"] + 1))
    from services.dns_service import DnsService
    engine = Engine(module_manager=manager, services={"dns": DnsService()}, events=bus)
    report = engine.run(ScanConfig(
        target_url="https://example.com",
        authorization_confirmed=True,
        scope=Scope(domains=[]),
    ))
    assert report.scan_id
    assert seen["started"] and seen["finished"]
