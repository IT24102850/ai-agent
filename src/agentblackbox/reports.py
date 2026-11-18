"""Deterministic JSON audit reports and optional PDF rendering."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .export import verify_export_bundle
from .signing import verify_bundle_signature


class PdfUnavailableError(RuntimeError):
    pass


def deterministic_audit_report(
    bundle: dict[str, Any],
    public_key: Any | None = None,
) -> dict[str, Any]:
    integrity = verify_export_bundle(bundle)
    signature = verify_bundle_signature(bundle, public_key)
    return {
        "schema": "agentblackbox/audit-report",
        "version": 1,
        "bundle_format": bundle.get("format"),
        "bundle_version": bundle.get("version"),
        "session_id": (
            bundle.get("session", {}).get("id") if isinstance(bundle.get("session"), dict) else None
        ),
        "integrity": integrity,
        "signature": signature,
        "overall_valid": bool(integrity["valid"])
        and (not signature["signed"] or signature["valid"] is True),
    }


def write_json_audit_report(
    bundle: dict[str, Any], output: str | Path, public_key: Any | None = None
) -> Path:
    report = deterministic_audit_report(bundle, public_key)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def report_html(report: dict[str, Any]) -> str:
    rows = [
        "<tr><td>Bundle format</td><td>{}</td></tr>".format(
            html.escape(str(report.get("bundle_format")))
        ),
        "<tr><td>Session ID</td><td>{}</td></tr>".format(
            html.escape(str(report.get("session_id")))
        ),
        "<tr><td>Overall valid</td><td>{}</td></tr>".format(
            "yes" if report["overall_valid"] else "no"
        ),
        "<tr><td>Signature status</td><td>{}</td></tr>".format(
            html.escape(str(report["signature"]["status"]))
        ),
    ]
    integrity = report["integrity"]
    for name in ("chain_valid", "merkle_valid", "proofs_valid"):
        rows.append(
            "<tr><td>{}</td><td>{}</td></tr>".format(
                html.escape(name), "yes" if integrity[name] else "no"
            )
        )
    style = (
        "body{font-family:sans-serif;margin:2rem}"
        "table{border-collapse:collapse}"
        "td{border:1px solid #ccc;padding:.5rem}"
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>AgentBlackbox Audit Report</title>"
        f"<style>{style}</style></head><body>"
        f"<h1>AgentBlackbox Audit Report</h1><table>{''.join(rows)}</table></body></html>"
    )


def write_pdf_report(report: dict[str, Any], output: str | Path) -> Path:
    """Write a PDF if WeasyPrint is installed; otherwise fail explicitly."""
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise PdfUnavailableError(
            "PDF reports require the optional 'weasyprint' dependency; "
            "install with 'pip install agentblackbox[pdf]'"
        ) from exc
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=report_html(report)).write_pdf(str(destination))
    return destination


def pdf_report_bytes(report: dict[str, Any]) -> bytes:
    """Render a PDF in memory, or raise PdfUnavailableError if WeasyPrint is absent."""
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise PdfUnavailableError(
            "PDF reports require the optional 'weasyprint' dependency; "
            "install with 'pip install agentblackbox[pdf]'"
        ) from exc
    return HTML(string=report_html(report)).write_pdf()
