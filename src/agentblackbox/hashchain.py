"""SHA-256 hash chains for ordered audit events."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_json

GENESIS_HASH = "0" * 64
HASH_VERSION = 1
HASH_DOMAIN = b"agentblackbox/event/v1"


@dataclass(frozen=True)
class ChainEntry:
    sequence: int
    payload: Any
    previous_hash: str
    hash: str
    hash_version: int = HASH_VERSION
    tenant_id: str = ""
    session_id: str = ""
    event_type: str = "event"
    payload_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ChainVerification:
    """Structured chain verification result."""

    valid: bool
    sequence: int | None = None
    reason: str | None = None


def _field(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def entry_hash(
    sequence: int,
    payload: Any,
    previous_hash: str,
    *,
    tenant_id: str = "",
    session_id: str = "",
    event_type: str = "event",
    payload_hash: str = "",
) -> str:
    """Hash a versioned, length-prefixed event record.

    Length prefixes prevent field-boundary ambiguity and the domain prefix
    prevents cross-protocol hash reuse.
    """
    parts = (
        HASH_DOMAIN,
        _field(tenant_id.encode("utf-8")),
        _field(session_id.encode("utf-8")),
        _field(str(sequence).encode("ascii")),
        _field(event_type.encode("utf-8")),
        _field(canonical_json(payload)),
        _field(payload_hash.encode("ascii")),
        _field(previous_hash.encode("ascii")),
    )
    return hashlib.sha256(b"".join(parts)).hexdigest()


def create_chain(
    payloads: Iterable[Any],
    genesis_hash: str = GENESIS_HASH,
) -> list[ChainEntry]:
    if not isinstance(genesis_hash, str) or len(genesis_hash) != 64:
        raise ValueError("genesis_hash must be a 64-character hexadecimal SHA-256 hash")
    int(genesis_hash, 16)
    entries: list[ChainEntry] = []
    previous = genesis_hash
    for sequence, payload in enumerate(payloads):
        digest = entry_hash(sequence, payload, previous)
        entries.append(ChainEntry(sequence, payload, previous, digest, HASH_VERSION))
        previous = digest
    return entries


def verify_chain(entries: Iterable[ChainEntry], genesis_hash: str = GENESIS_HASH) -> bool:
    return verify_chain_result(entries, genesis_hash).valid


def verify_chain_result(
    entries: Iterable[ChainEntry], genesis_hash: str = GENESIS_HASH
) -> ChainVerification:
    previous = genesis_hash
    for expected_sequence, entry in enumerate(entries):
        if not isinstance(entry, ChainEntry):
            return ChainVerification(False, expected_sequence, "invalid_entry_type")
        if entry.sequence != expected_sequence:
            return ChainVerification(False, expected_sequence, "sequence_mismatch")
        if entry.previous_hash != previous:
            return ChainVerification(False, expected_sequence, "previous_hash_mismatch")
        if entry.hash_version != HASH_VERSION:
            return ChainVerification(False, expected_sequence, "unsupported_hash_version")
        if (
            entry_hash(
                entry.sequence,
                entry.payload,
                entry.previous_hash,
                tenant_id=entry.tenant_id,
                session_id=entry.session_id,
                event_type=entry.event_type,
                payload_hash=entry.payload_hash,
            )
            != entry.hash
        ):
            return ChainVerification(False, expected_sequence, "hash_mismatch")
        previous = entry.hash
    return ChainVerification(True)
