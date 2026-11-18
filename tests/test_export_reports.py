import json

import pytest

from agentblackbox import (
    CRYPTOGRAPHY_AVAILABLE,
    deterministic_audit_report,
    export_session_bundle,
    generate_ed25519_keypair,
    sign_bundle,
    verify_bundle_signature,
    verify_export_bundle,
)


def sample_bundle():
    session = {"id": "session-1", "name": "refund"}
    events = [
        {
            "id": "event-1",
            "sequence": 0,
            "event_type": "decision",
            "payload": {"event_type": "decision", "data": {"action": "refund"}},
            "previous_hash": "0" * 64,
            "hash": "0" * 64,
            "timestamp": "2026-01-01T00:00:00+00:00",
        }
    ]
    from agentblackbox.hashchain import create_chain

    chain = create_chain([events[0]["payload"]])
    events[0]["previous_hash"] = chain[0].previous_hash
    events[0]["hash"] = chain[0].hash
    return export_session_bundle(session, events)


def test_export_verify_and_deterministic_report():
    bundle = sample_bundle()
    assert verify_export_bundle(bundle)["valid"] is True
    report = deterministic_audit_report(bundle)
    assert report["session_id"] == "session-1"
    assert report["overall_valid"] is True
    assert json.dumps(report, sort_keys=True) == json.dumps(
        deterministic_audit_report(bundle), sort_keys=True
    )


def test_tampered_export_is_invalid():
    bundle = sample_bundle()
    bundle["chain"][0]["payload"]["data"]["action"] = "block"
    assert verify_export_bundle(bundle)["valid"] is False


@pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography is optional")
def test_optional_ed25519_signature_round_trip():
    bundle = sample_bundle()
    private_key, public_key = generate_ed25519_keypair()
    signed = sign_bundle(bundle, private_key)
    assert verify_bundle_signature(signed, public_key)["valid"] is True
    signed["chain"][0]["payload"]["data"]["action"] = "tampered"
    assert verify_bundle_signature(signed, public_key)["valid"] is False
