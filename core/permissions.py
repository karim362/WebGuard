"""
permissions — decides whether a module is allowed to run in a given mode
and with the available capabilities. Separate from ScopeGuard (which is
about target scope, not module permission).
"""
from __future__ import annotations
from models.module import BaseModule, ScanMode

_MODE_ORDER = {ScanMode.PASSIVE: 0, ScanMode.ACTIVE: 1, ScanMode.ADVANCED: 2}

def module_allowed(module: BaseModule, mode: ScanMode,
                   available_services: set[str]) -> tuple[bool, str]:
    if _MODE_ORDER[module.required_mode] > _MODE_ORDER[mode]:
        return False, f"requires mode >= {module.required_mode.value}"
    missing = [c for c in module.required_capabilities if c not in available_services]
    if missing:
        return False, f"missing capabilities: {','.join(missing)}"
    return True, ""
