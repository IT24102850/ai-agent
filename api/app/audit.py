"""Tamper-evident administrative audit log primitives."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

ADMIN_AUDIT_ACTIONS = frozenset(
    {
        "key.create",
        "key.rotate",
        "key.revoke",
        "policy.edit",
        "export.create",
        "login.success",
        "login.failure",
        "config.update",
        "tenant.create",
        "tenant.retention.update",
        "tenant.payload.purge",
        "session.create",
    }
)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def audit_event_hash(previous_hash: str, event: dict[str, Any]) -> str:
    payload = dict(event)
    payload["previous_hash"] = previous_hash
    return hashlib.sha256(_canonical(payload)).hexdigest()


@dataclass(frozen=True)
class AdminAuditEvent:
    id: str
    tenant_id: str
    actor_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    metadata: dict[str, Any]
    created_at: str
    previous_hash: str
    hash: str


class AdminAuditLogService:
    """Append and verify an audit-log hash chain stored by a repository."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    def append(
        self,
        tenant_id: str,
        actor_id: str | None,
        action: str,
        target_type: str | None,
        target_id: str | None,
        metadata: dict[str, Any],
        created_at: str,
    ) -> dict[str, Any]:
        if action not in ADMIN_AUDIT_ACTIONS:
            raise ValueError(f"unknown administrative audit action: {action}")
        return self.repository.add_audit(
            tenant_id, actor_id, action, target_type, target_id, metadata, created_at
        )

    def verify(self, tenant_id: str) -> dict[str, Any]:
        rows = self.repository.list_audit(tenant_id)
        previous = "0" * 64
        for row in rows:
            event = {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "actor_id": row["actor_key_id"],
                "action": row["action"],
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "metadata": json.loads(row["metadata"]),
                "created_at": row["created_at"],
            }
            if row["previous_hash"] != previous:
                return {"valid": False, "reason": "previous_hash_mismatch"}
            if row["hash"] != audit_event_hash(previous, event):
                return {"valid": False, "reason": "hash_mismatch"}
            previous = row["hash"]
        return {"valid": True, "count": len(rows), "head": previous}
