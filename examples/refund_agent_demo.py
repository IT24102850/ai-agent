"""Offline refund-agent demo: chain, export, verify, and report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentblackbox import (
    deterministic_audit_report,
    export_session_bundle,
    verify_export_bundle,
)
from agentblackbox.hashchain import create_chain


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    session = {
        "id": "offline-refund-demo",
        "name": "Refund policy offline demo",
        "metadata": {"mode": "offline"},
        "status": "ended",
        "created_at": "2026-01-01T00:00:00+00:00",
        "ended_at": "2026-01-01T00:00:01+00:00",
    }
    payloads = [
        {"event_type": "decision", "data": {"action": "refund", "amount": 600, "approved": False}},
        {"event_type": "policy.violation", "data": {"violations": ["refund_threshold"]}},
        {"event_type": "completion", "data": {"status": "rejected"}},
    ]
    chain = create_chain(payloads)
    events = [
        {
            "id": f"offline-event-{index}",
            "session_id": session["id"],
            "sequence": entry.sequence,
            "event_type": payload["event_type"],
            "payload": entry.payload,
            "previous_hash": entry.previous_hash,
            "hash": entry.hash,
            "timestamp": f"2026-01-01T00:00:0{index}+00:00",
        }
        for index, (entry, payload) in enumerate(zip(chain, payloads, strict=True))
    ]
    bundle = export_session_bundle(session, events)
    report = deterministic_audit_report(bundle)
    print(json.dumps({"integrity": verify_export_bundle(bundle), "report": report},
                     sort_keys=True, indent=2))
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "bundle.json").write_text(
            json.dumps(bundle, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (args.output / "audit-report.json").write_text(
            json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
