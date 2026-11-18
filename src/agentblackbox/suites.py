"""Portable regression-suite support for SDK and CLI users."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .diff import structured_diff


def execute_suite(suite: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for case in suite.get("test_cases", []):
        name = str(case.get("name", "unnamed"))
        try:
            baseline = case.get("baseline_events", case.get("expected", []))
            candidate = case.get("candidate_events", case.get("actual", []))
            diff = structured_diff({"events": baseline}, {"events": candidate})
            status = "changed" if diff else "passed"
            results.append({
                "name": name,
                "status": status,
                "diff": diff,
                "baseline_events": baseline,
                "candidate_events": candidate,
            })
        except Exception as exc:
            results.append({
                "name": name,
                "status": "errored",
                "diff": [],
                "error": f"{type(exc).__name__}: {exc}",
            })
    counts = {status: sum(r["status"] == status for r in results)
              for status in ("passed", "changed", "failed", "errored")}
    return {
        "name": suite.get("name", "regression suite"),
        "status": "passed" if counts["changed"] == counts["failed"] == counts["errored"] == 0 else (
            "failed" if counts["failed"] or counts["errored"] else "changed"
        ),
        "counts": counts,
        "results": results,
    }


def load_suite(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def suite_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def suite_junit(report: dict[str, Any]) -> str:
    suite = ET.Element(
        "testsuite",
        name=report["name"],
        tests=str(len(report["results"])),
        failures=str(report["counts"]["failed"]),
        errors=str(report["counts"]["errored"]),
    )
    for result in report["results"]:
        case = ET.SubElement(suite, "testcase", name=result["name"])
        if result["status"] in ("failed", "changed"):
            tag = "failure" if result["status"] == "failed" else "skipped"
            node = ET.SubElement(case, tag)
            node.text = json.dumps(result.get("diff", []), sort_keys=True)
        elif result["status"] == "errored":
            node = ET.SubElement(case, "error")
            node.text = result.get("error", "unknown error")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True)
