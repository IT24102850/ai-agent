"""Application payload envelope encryption and key-provider interfaces."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class DataKey:
    key_id: str
    key: bytes


class KeyProvider(Protocol):
    def encrypt_data_key(self, key_id: str) -> bytes: ...
    def decrypt_data_key(self, wrapped_key: bytes) -> bytes: ...
    def active_key(self) -> DataKey: ...


class LocalDevelopmentKeyProvider:
    """Deterministic local-only key provider. Never use for production."""

    def __init__(self, key_material: str | bytes | None = None) -> None:
        raw = key_material or os.getenv("AGENTBLACKBOX_PAYLOAD_KEY")
        if raw:
            if isinstance(raw, str):
                try:
                    material = base64.b64decode(raw, validate=True)
                except Exception:
                    material = raw.encode("utf-8")
            else:
                material = raw
            if len(material) not in (16, 24, 32):
                material = hashlib.sha256(material).digest()
        else:
            material = hashlib.sha256(b"agentblackbox-local-development-only").digest()
        self._key = material
        self._kid = "local-" + hashlib.sha256(material).hexdigest()[:12]

    def active_key(self) -> DataKey:
        return DataKey(self._kid, self._key)

    def encrypt_data_key(self, key_id: str) -> bytes:
        return self._key

    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        return wrapped_key


class ProductionKMSRequired(KeyProvider):
    """Fail-closed provider for production configurations without KMS."""

    def active_key(self) -> DataKey:
        raise KeyProviderError("Production payload encryption requires a configured KMS provider")

    def encrypt_data_key(self, key_id: str) -> bytes:
        raise KeyProviderError("Production payload encryption requires a configured KMS provider")

    def decrypt_data_key(self, wrapped_key: bytes) -> bytes:
        raise KeyProviderError("Production payload encryption requires a configured KMS provider")


class EnvelopeEncryptor:
    def __init__(self, provider: KeyProvider) -> None:
        self.provider = provider

    def encrypt(self, value: Any) -> dict[str, Any]:
        key = self.provider.active_key()
        plaintext = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        nonce = os.urandom(12)
        ciphertext = AESGCM(key.key).encrypt(nonce, plaintext, key.key_id.encode("ascii"))
        return {
            "_agentblackbox_envelope": "v1",
            "kid": key.key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def decrypt(self, envelope: dict[str, Any]) -> Any:
        if envelope.get("_agentblackbox_envelope") != "v1":
            raise KeyProviderError("Unsupported payload envelope")
        if envelope.get("kid") != getattr(self.provider.active_key(), "key_id", None):
            raise KeyProviderError("Payload encryption key is not the active local key")
        try:
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            plaintext = AESGCM(self.provider.active_key().key).decrypt(
                nonce, ciphertext, envelope["kid"].encode("ascii")
            )
            return json.loads(plaintext.decode("utf-8"))
        except (KeyError, InvalidTag, ValueError, json.JSONDecodeError) as exc:
            raise KeyProviderError("Unable to decrypt payload envelope") from exc


def is_payload_envelope(value: Any) -> bool:
    return isinstance(value, dict) and value.get("_agentblackbox_envelope") == "v1"

