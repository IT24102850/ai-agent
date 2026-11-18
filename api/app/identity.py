"""Human identity foundations.

This module provides password and identity interfaces only.  Production session,
OIDC, TOTP and WebAuthn deployments need their provider-specific implementation;
the classes below intentionally do not claim those flows are complete.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Protocol


class Argon2UnavailableError(RuntimeError):
    """Raised when Argon2id support is not installed."""


def hash_password(password: str) -> str:
    """Hash a password with Argon2id, or fail clearly if unavailable."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    try:
        from argon2 import PasswordHasher
    except ImportError as exc:
        raise Argon2UnavailableError(
            "Argon2id password hashing is unavailable; install the 'argon2-cffi' dependency"
        ) from exc

    return PasswordHasher().hash(password)


def verify_password(encoded_hash: str, password: str) -> bool:
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
    except ImportError as exc:
        raise Argon2UnavailableError(
            "Argon2id password hashing is unavailable; install the 'argon2-cffi' dependency"
        ) from exc

    try:
        return PasswordHasher().verify(encoded_hash, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


@dataclass(frozen=True)
class HumanIdentity:
    id: str
    tenant_id: str
    display_name: str
    role: str
    mfa_enabled: bool = False


class SessionCookieIdentityProvider(Protocol):
    """Interface for a production secure-cookie session provider."""

    def create_session(self, identity: HumanIdentity) -> str: ...

    def resolve_session(self, cookie_value: str) -> HumanIdentity | None: ...

    def revoke_session(self, cookie_value: str) -> bool: ...


class OIDCIdentityProvider(Protocol):
    """Interface for an external OIDC browser or bearer identity provider."""

    def authorization_url(self, state: str, nonce: str) -> str: ...

    def exchange_code(self, code: str, state: str) -> HumanIdentity: ...


class TOTPEnrollmentInterface(Protocol):
    """Extension point for TOTP.  No cryptographic enrollment is implemented here."""

    def begin_enrollment(self, identity: HumanIdentity) -> dict[str, str]:
        raise NotImplementedError("TOTP enrollment is not implemented")

    def verify_and_enable(self, identity: HumanIdentity, code: str) -> bool:
        raise NotImplementedError("TOTP verification is not implemented")


class WebAuthnInterface(Protocol):
    """Extension point for WebAuthn.  No ceremony is implemented here."""

    def begin_registration(self, identity: HumanIdentity) -> dict[str, object]:
        raise NotImplementedError("WebAuthn registration is not implemented")

    def finish_registration(self, identity: HumanIdentity, response: dict[str, object]) -> bool:
        raise NotImplementedError("WebAuthn registration is not implemented")


def safe_cookie_value() -> str:
    """Generate a cryptographically-random opaque cookie/session identifier."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
