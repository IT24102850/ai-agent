"""Anchoring and portable export primitives."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .hashchain import ChainEntry, verify_chain
from .merkle import inclusion_proof, merkle_root

EXPORT_FORMAT = "agentblackbox/export"
EXPORT_VERSION = 1


def export_session_bundle(
    session: dict[str, Any],
    events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Build a standalone JSON bundle from a session and its persisted events."""
    event_list = list(events)
    entries: list[ChainEntry] = []
    exported_events: list[dict[str, Any]] = []
    for expected_sequence, event in enumerate(event_list):
        try:
            sequence = int(event["sequence"])
            previous_hash = event["previous_hash"]
            hash_ = event["hash"]
            payload = event["payload"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("event is missing export integrity fields") from exc
        if sequence != expected_sequence:
            raise ValueError("event sequences must be contiguous and ordered")
        entries.append(
            ChainEntry(
                sequence,
                payload,
                previous_hash,
                hash_,
                session_id=str(session.get("id", "")),
                event_type=str(event.get("event_type", "event")),
            )
        )
        exported_events.append(dict(event))

    if entries and not verify_chain(entries):
        # Bundles created before contextual hash fields were introduced remain
        # readable, but new application events always use the contextual form.
        legacy_entries = [
            ChainEntry(entry.sequence, entry.payload, entry.previous_hash, entry.hash)
            for entry in entries
        ]
        if verify_chain(legacy_entries):
            entries = legacy_entries
        else:
            raise ValueError("cannot export: session hash chain is invalid")

    merkle_inputs = [entry.to_dict() for entry in entries]
    root = merkle_root(merkle_inputs)
    proofs = [inclusion_proof(merkle_inputs, index).to_dict() for index in range(len(entries))]
    head, count = (entries[-1].hash, len(entries)) if entries else ("0" * 64, 0)

    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "session": dict(session),
        "events": exported_events,
        "chain": [entry.to_dict() for entry in entries],
        "merkle": {
            "algorithm": "sha256",
            "root": root,
            "proofs": proofs,
        },
        "anchor": {
            "kind": "sha256-chain-and-merkle",
            "chain_head": head,
            "chain_count": count,
            "merkle_root": root,
        },
    }


def verify_export_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Verify structural chain/Merkle integrity without requiring external trust."""
    if not isinstance(bundle, dict):
        return {
            "valid": False,
            "chain_valid": False,
            "merkle_valid": False,
            "proofs_valid": False,
            "anchor_valid": False,
            "signature": "invalid_bundle",
        }
    if bundle.get("format") != EXPORT_FORMAT or bundle.get("version") != EXPORT_VERSION:
        return {
            "valid": False,
            "chain_valid": False,
            "merkle_valid": False,
            "proofs_valid": False,
            "anchor_valid": False,
            "signature": "invalid_bundle",
        }

    chain_data = bundle.get("chain")
    if not isinstance(chain_data, list):
        return {
            "valid": False,
            "chain_valid": False,
            "merkle_valid": False,
            "proofs_valid": False,
            "anchor_valid": False,
            "signature": "invalid_chain",
        }
    entries: list[ChainEntry] = []
    try:
        for item in chain_data:
            entries.append(
                ChainEntry(
                    sequence=item["sequence"],
                    payload=item["payload"],
                    previous_hash=item["previous_hash"],
                    hash=item["hash"],
                    tenant_id=str(item.get("tenant_id", "")),
                    session_id=str(item.get("session_id", "")),
                    event_type=str(item.get("event_type", "event")),
                    payload_hash=str(item.get("payload_hash", "")),
                    hash_version=int(item.get("hash_version", 1)),
                )
            )
    except (KeyError, TypeError):
        entries = []
    chain_valid = bool(entries) and verify_chain(entries) if chain_data else True

    merkle = bundle.get("merkle")
    merkle_valid = isinstance(merkle, dict) and isinstance(merkle.get("root"), str)
    proofs_valid = isinstance(merkle, dict) and isinstance(merkle.get("proofs"), list)
    root = merkle.get("root") if isinstance(merkle, dict) else None
    if merkle_valid:
        merkle_valid = merkle_root([entry.to_dict() for entry in entries]) == root
        proofs_valid = len(merkle["proofs"]) == len(entries)
        if proofs_valid:
            from .merkle import MerkleProof, verify_inclusion

            proof_pairs = zip(entries, merkle["proofs"], strict=True)
            for index, (entry, proof_data) in enumerate(proof_pairs):
                try:
                    proof = MerkleProof(
                        index=int(proof_data["index"]),
                        leaves_count=int(proof_data["leaves_count"]),
                        siblings=tuple(proof_data["siblings"]),
                    )
                except (KeyError, TypeError, ValueError):
                    proofs_valid = False
                    break
                if proof.index != index or not verify_inclusion(entry.to_dict(), proof, root):
                    proofs_valid = False
                    break

    anchor_valid = isinstance(bundle.get("anchor"), dict)
    if anchor_valid:
        anchor = bundle["anchor"]
        expected_head = entries[-1].hash if entries else ("0" * 64)
        anchor_valid = (
            anchor.get("kind") == "sha256-chain-and-merkle"
            and anchor.get("chain_head") == expected_head
            and anchor.get("chain_count") == len(entries)
            and anchor.get("merkle_root") == root
        )

    signature_state = "not_signed"
    if isinstance(bundle.get("signature"), dict):
        signature_state = "signature_present"
    valid = chain_valid and merkle_valid and proofs_valid and anchor_valid
    return {
        "valid": valid,
        "chain_valid": chain_valid,
        "merkle_valid": merkle_valid,
        "proofs_valid": proofs_valid,
        "anchor_valid": anchor_valid,
        "signature": signature_state,
    }
