"""Deny-by-default role and permission definitions."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR_READONLY = "auditor_readonly"
    SERVICE = "service"


PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.OWNER: frozenset(
        {"sessions.read", "sessions.ingest", "policies.read", "policies.edit",
         "exports.read", "admin.users", "admin.keys", "admin.audit", "admin.config"}
    ),
    Role.ADMIN: frozenset(
        {"sessions.read", "sessions.ingest", "policies.read", "policies.edit",
         "exports.read", "admin.keys", "admin.audit", "admin.config"}
    ),
    Role.ANALYST: frozenset(
        {"sessions.read", "sessions.ingest", "policies.read", "exports.read"}
    ),
    Role.AUDITOR_READONLY: frozenset(
        {"sessions.read", "policies.read", "exports.read", "admin.audit"}
    ),
    Role.SERVICE: frozenset(
        {"sessions.read", "sessions.ingest", "exports.read"}
    ),
}


def role_from_name(name: str | None) -> Role | None:
    if not name:
        return None
    try:
        return Role(name)
    except ValueError:
        return None


def has_permission(role: Role | str | None, permission: str) -> bool:
    """Permission checks deny unknown roles and every unlisted permission."""
    resolved = role if isinstance(role, Role) else role_from_name(role)
    if resolved is None:
        return False
    return permission in PERMISSIONS.get(resolved, frozenset())


def require_permission(role: Role | str | None, required: Iterable[str]) -> bool:
    return all(has_permission(role, permission) for permission in required)
