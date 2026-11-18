import asyncio
import hashlib

import httpx
import pytest

from api.app.config import Settings
from api.app.encryption import EnvelopeEncryptor, LocalDevelopmentKeyProvider
from api.app.main import create_app
from api.app.object_store import LocalFilesystemObjectStore
from api.app.redaction import luhn_valid, redact_stable
from api.app.sandbox import Sandbox, SandboxDeniedError

HEADERS = {"X-API-Key": "test-key"}


async def request(app, method, path, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_luhn_iban_and_stable_secret_redaction():
    assert luhn_valid("4242-4242-4242-4242")
    text = (
        "GB82 WEST 1234 5698 7654 32 "
        "sk_test_abcdefghijklmnop "
        "eyJhbGciOiJIUzI1NiJ9.e30.signature"
    )
    first = redact_stable(text, "pepper")
    second = redact_stable(text, "pepper")
    assert first == second
    assert "[REDACTED_IBAN:" not in first  # spaces are deliberately not an IBAN
    assert "[REDACTED_API_KEY:" in first
    assert "[REDACTED_JWT:" in first


def test_payload_envelope_round_trip_and_object_store(tmp_path):
    encryptor = EnvelopeEncryptor(LocalDevelopmentKeyProvider("development-envelope-key"))
    envelope = encryptor.encrypt({"secret": "value"})
    assert envelope["_agentblackbox_envelope"] == "v1"
    assert encryptor.decrypt(envelope) == {"secret": "value"}

    store = LocalFilesystemObjectStore(tmp_path / "objects")
    content = b"large-payload"
    metadata = store.put("ignored", content)
    assert metadata["sha256"] == hashlib.sha256(content).hexdigest()
    assert store.get(metadata["key"]) == content


def test_production_requires_kms_and_sandbox_never_executes(tmp_path):
    with pytest.raises(ValueError, match="KMS"):
        Settings(
            environment="production",
            database_url=f"sqlite:///{tmp_path / 'prod.db'}",
            api_key="secret",
            api_key_pepper="configured-production-pepper",
        ).validate()

    sandbox = Sandbox()
    with pytest.raises(SandboxDeniedError):
        sandbox.execute(lambda: (_ for _ in ()).throw(AssertionError("real tool executed")))
    with pytest.raises(SandboxDeniedError):
        sandbox.open_network("https://example.invalid")
    with pytest.raises(SandboxDeniedError):
        sandbox.get_credentials("database")


def test_retention_purge_preserves_hash_and_marks_purged(tmp_path):
    app = create_app(
        Settings(
            api_key="test-key",
            database_url=f"sqlite:///{tmp_path / 'retention.db'}",
            payload_key="local-test-key",
            object_store_root=str(tmp_path / "objects"),
        )
    )

    async def run():
        created = await request(
            app,
            "POST",
            "/v1/sessions",
            headers=HEADERS,
            json={"name": "retention"},
        )
        session_id = created.json()["id"]
        ingested = await request(
            app,
            "POST",
            f"/v1/sessions/{session_id}/events",
            headers=HEADERS,
            json={"event_type": "llm.call", "payload": {"prompt": "private content"}},
        )
        original_hash = ingested.json()["hash"]

        purge = await request(
            app,
            "POST",
            "/v1/admin/tenants/local/purge",
            headers=HEADERS,
        )
        assert purge.status_code == 200

        listed = await request(
            app,
            "GET",
            f"/v1/sessions/{session_id}/events",
            headers=HEADERS,
        )
        event = listed.json()["events"][0]
        assert event["payload_purged"] is True
        assert event["payload"] == {
            "purged": True,
            "payload_hash": event["payload_content_hash"],
        }
        assert event["hash"] == original_hash

        verified = await request(
            app,
            "GET",
            f"/v1/sessions/{session_id}/verify",
            headers=HEADERS,
        )
        assert verified.status_code == 200
        assert verified.json()["valid"] is True

    asyncio.run(run())
