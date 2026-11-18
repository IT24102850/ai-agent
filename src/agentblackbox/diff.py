"""Deterministic structured diffs."""

from __future__ import annotations

from typing import Any


def structured_diff(before: Any, after: Any, path: str = "$") -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            child = f"{path}.{key}"
            if key not in before:
                changes.append({"op": "add", "path": child, "value": after[key]})
            elif key not in after:
                changes.append({"op": "remove", "path": child, "value": before[key]})
            else:
                changes.extend(structured_diff(before[key], after[key], child))
        return changes
    if isinstance(before, list) and isinstance(after, list):
        common = min(len(before), len(after))
        for index in range(common):
            changes.extend(structured_diff(before[index], after[index], f"{path}[{index}]"))
        for index in range(common, len(before)):
            changes.append({"op": "remove", "path": f"{path}[{index}]", "value": before[index]})
        for index in range(common, len(after)):
            changes.append({"op": "add", "path": f"{path}[{index}]", "value": after[index]})
        return changes
    if before != after:
        changes.append({"op": "replace", "path": path, "before": before, "after": after})
    return changes
