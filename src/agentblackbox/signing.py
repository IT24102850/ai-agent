"""Optional Ed25519 signing using the cryptography package."""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    InvalidSignature = Exception
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate a private/public key seed pair encoded as hex."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError(
            "Ed25519 signing requires the optional 'cryptography' dependency; "
            "install with 'pip install agentblackbox[signing]'"
        )
    private_key = Ed25519PrivateKey.generate()
    private_seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_seed.hex(), public_key.hex()


def _private_key(private_key: Any):
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("Ed25519 signing is unavailable: cryptography is not installed")
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key
    if isinstance(private_key, (bytes, bytearray)):
        raw = bytes(private_key)
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
        if raw.startswith(b"-----"):
            return serialization.load_pem_private_key(raw, password=None)
    if isinstance(private_key, str):
        if private_key.startswith("-----"):
            return serialization.load_pem_private_key(private_key.encode(), password=None)
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    raise TypeError("private key must be an Ed25519 key, 32-byte seed, PEM, or hex seed")


def _public_key(public_key: Any):
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("Ed25519 verification is unavailable: cryptography is not installed")
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
        if raw.startswith(b"-----"):
            return serialization.load_pem_public_key(raw)
    if isinstance(public_key, str):
        if public_key.startswith("-----"):
            return serialization.load_pem_public_key(public_key.encode())
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
    raise TypeError("public key must be an Ed25519 key, 32-byte raw key, PEM, or hex key")


def sign_payload(payload: Any, private_key: Any) -> dict[str, str]:
    """Sign canonical JSON and return an Ed25519 signature descriptor."""
    key = _private_key(private_key)
    signature = key.sign(canonical_json(payload)).hex()
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )
    return {"algorithm": "ed25519", "public_key": public_key, "signature": signature}


def sign_bundle(bundle: dict[str, Any], private_key: Any) -> dict[str, Any]:
    """Return a copy of a bundle carrying a signature over all unsigned fields."""
    unsigned = dict(bundle)
    unsigned.pop("signature", None)
    signed = dict(unsigned)
    signed["signature"] = sign_payload(unsigned, private_key)
    return signed


def verify_payload(payload: Any, descriptor: dict[str, str], public_key: Any | None = None) -> bool:
    if descriptor.get("algorithm") != "ed25519":
        return False
    try:
        key = _public_key(public_key or descriptor["public_key"])
        key.verify(bytes.fromhex(descriptor["signature"]), canonical_json(payload))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def verify_bundle_signature(
    bundle: dict[str, Any],
    public_key: Any | None = None,
) -> dict[str, Any]:
    descriptor = bundle.get("signature")
    if not isinstance(descriptor, dict):
        return {"signed": False, "valid": None, "status": "not_signed"}
    unsigned = dict(bundle)
    unsigned.pop("signature", None)
    valid = verify_payload(unsigned, descriptor, public_key)
    return {"signed": True, "valid": valid, "status": "valid" if valid else "invalid"}
