"""Module contracts: ScanMode, BaseModule, ModuleResult."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    ADVANCED = "advanced"

class ModuleStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class ModuleResult:
    module_name: str
    status: ModuleStatus = ModuleStatus.SUCCESS
    findings: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

class BaseModule:
    name: str = "base"
    version: str = "0.1.0"
    description: str = "Base module"
    required_mode: ScanMode = ScanMode.PASSIVE
    required_capabilities: list[str] = []
    requires_auth: bool = False

    def validate(self, context) -> bool:
        for cap in self.required_capabilities:
            if not context.has_service(cap):
                return False
        return True

    def run(self, context) -> ModuleResult:
        raise NotImplementedError("Modules must implement run(context)")
