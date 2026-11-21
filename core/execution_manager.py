"""
execution_manager — runs selected modules and emits lifecycle events.
The engine delegates to this so the engine stays small and testable.
"""
from __future__ import annotations
import time
from typing import Any
from core.event_bus import EventBus
from core.scope_guard import ScopeGuard
from models.module import BaseModule, ModuleResult, ModuleStatus, ScanMode
from models.scan_config import ScanConfig
from models.target import Target
from services.evidence_collector import EvidenceCollector
from services.logger import get_logger

class ModuleContext:
    def __init__(self, target: Target, scope_guard: ScopeGuard,
                 services: dict[str, Any], scan_id: str, mode: ScanMode,
                 events: EventBus):
        self.target = target
        self.scope_guard = scope_guard
        self.services = services
        self.scan_id = scan_id
        self.mode = mode
        self.events = events

    def has_service(self, name: str) -> bool:
        return name in self.services

    def emit(self, event: str, **payload: Any) -> None:
        self.events.emit(event, **payload)

class ExecutionManager:
    def __init__(self, events: EventBus):
        self.events = events
        self.logger = get_logger("webguard.execution")

    def execute(self, modules: list[BaseModule], context: ModuleContext) -> list[ModuleResult]:
        results: list[ModuleResult] = []
        for module in modules:
            if not module.validate(context):
                self.events.emit("module_skipped", name=module.name,
                                 reason="validation failed")
                continue
            self.events.emit("module_started", name=module.name)
            t0 = time.time()
            try:
                result = module.run(context)
            except Exception as e:
                self.logger.exception("Module %s failed: %s", module.name, e)
                result = ModuleResult(module_name=module.name,
                                      status=ModuleStatus.FAILED,
                                      errors=[str(e)],
                                      duration=time.time() - t0)
            else:
                result.duration = time.time() - t0

            collector = context.services.get("evidence")
            for finding in result.findings:
                if collector is not None:
                    try:
                        collector.attach(finding, None)
                    except Exception:
                        pass
                self.events.emit("finding", finding=finding)
            self.events.emit("module_finished", name=module.name,
                             status=result.status.value,
                             duration=result.duration)
            results.append(result)
        return results
