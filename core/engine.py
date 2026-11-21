"""Engine — orchestrates a scan."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from core.dispatcher import Dispatcher
from core.event_bus import EventBus
from core.execution_manager import ExecutionManager, ModuleContext
from core.module_manager import ModuleManager
from core.scope_guard import ScopeGuard, ScopeViolation
from models.module import ModuleResult, ScanMode
from models.scan_config import ScanConfig
from models.target import Target
from services.cookie_manager import CookieError, load_cookies
from services.dns_service import DnsService
from services.evidence_collector import EvidenceCollector
from services.http_client import HttpClient
from services.logger import get_logger
from services.storage import Storage

@dataclass
class ScanReport:
    scan_id: str
    target_url: str
    mode: ScanMode
    results: list[ModuleResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    total_duration: float = 0.0

class Engine:
    def __init__(self, module_manager: ModuleManager, services: dict[str, Any],
                 storage: Optional[Storage] = None,
                 events: Optional[EventBus] = None):
        self.module_manager = module_manager
        self.services = services
        self.storage = storage or Storage()
        self.events = events or EventBus()
        self.dispatcher = Dispatcher(module_manager)
        self.executor = ExecutionManager(self.events)
        self.logger = get_logger("webguard.engine")

    def run(self, config: ScanConfig) -> ScanReport:
        target = Target(
            url=config.target_url,
            scope_domains=config.scope.domains,
            allow_subdomains=config.scope.allow_subdomains,
            authorization_confirmed=config.authorization_confirmed,
        )
        scope_guard = ScopeGuard(target)
        if not scope_guard.is_url_allowed(target.url):
            raise ScopeViolation(f"Target URL outside scope: {target.url}")

        scan_id = self.storage.new_scan_id()
        report = ScanReport(scan_id=scan_id, target_url=target.url, mode=config.mode)

        cookies_dict: dict[str, str] = {}
        if config.cookies_header:
            try:
                cookies_dict = load_cookies(config.cookies_header)
                self.logger.info("Loaded %d cookie(s) (values redacted)",
                                 len(cookies_dict))
            except (CookieError, Exception) as e:
                self.logger.warning("Cookie load failed: %s", e)

        http_service = HttpClient(
            scope_guard=scope_guard, timeout=config.timeout,
            rate_limit=config.rate_limit, max_requests=config.max_requests,
            default_headers=config.headers or None,
            cookies=cookies_dict or None,
        )
        services = dict(self.services)
        services["http"] = http_service
        services["evidence"] = EvidenceCollector(scan_id)
        services.setdefault("dns", DnsService(timeout=config.timeout))

        context = ModuleContext(
            target=target, scope_guard=scope_guard, services=services,
            scan_id=scan_id, mode=config.mode, events=self.events,
        )
        available = set(services.keys())
        modules = self.dispatcher.select(config, available)
        self.logger.info("Scan %s starting | selected=%d | mode=%s | scope=%s",
                         scan_id, len(modules), config.mode.value,
                         ",".join(scope_guard.allowed_domains()))
        self.events.emit("scan_started", scan_id=scan_id,
                         target=target.url, mode=config.mode.value,
                         module_count=len(modules))

        t0 = time.time()
        results = self.executor.execute(modules, context)
        report.results = results
        report.total_duration = time.time() - t0

        try:
            self.storage.save_scan(scan_id, {
                "scan_id": scan_id, "target": target.url,
                "mode": config.mode.value, "scope": config.scope.domains,
                "results": results, "duration": report.total_duration,
            })
        except Exception as e:
            self.logger.warning("Persist failed for %s: %s", scan_id, e)

        self.logger.info("Scan %s finished | %.2fs", scan_id, report.total_duration)
        self.events.emit("scan_finished", report=report)
        return report
