"""Compares two scan finding lists to highlight new and resolved items."""
from __future__ import annotations
from typing import Any


def _finding_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("module", "")),
        str(item.get("severity", "")),
        str(item.get("title", "")),
    )


def compare_scan_reports(
    previous_findings: list[dict[str, Any]],
    current_findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    prev_keys = {_finding_key(x) for x in previous_findings}
    curr_keys = {_finding_key(x) for x in current_findings}

    new_items = [x for x in current_findings if _finding_key(x) not in prev_keys]
    resolved_items = [x for x in previous_findings if _finding_key(x) not in curr_keys]
    return {
        "new": new_items,
        "resolved": resolved_items,
    }
