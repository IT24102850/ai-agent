import asyncio
import json

import httpx
import pytest

from api.app.audit import AdminAuditLogService
from api.app.config import Settings
from api.app.db import SQLiteRepository
from api.app.identity import Argon2UnavailableError, hash_password, verify_password
from api.app.main import create_app
from api.app.rbac import Role, has_permission
from api.app.redaction import safe_log_context
from api.app.webhooks import (
    SignedWebhookSender,
    WebhookValidationError,
    sign_payload,
    validate_webhook_url,
    verify_signature,
)


async def request(app, method, path, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_password_hash_is_optional_and_argon2_when_available():
    try:
        encoded = hash_password("correct horse battery staple")
    except Argon2UnavailableError as exc:
        assert "argon2-cffi" in str(exc)
    else:
        assert encoded.startswith("$argon2")
        assert verify_password(encoded, "correct horse battery staple")
        assert not verify_password(encoded, "wrong")


def test_rbac_is_deny_by_default_and_roles_are_distinct():
    assert has_permission(Role.OWNER, "admin.users")
    assert has_permission(Role.ADMIN, "admin.config")
    assert not has_permission(Role.ANALYST, "admin.keys")
    assert has_permission(Role.AUDITOR_READONLY, "admin.audit")
    assert not has_permission(Role.SERVICE, "policies.edit")
    assert not has_permission("unknown-role", "sessions.read")


def test_admin_audit_log_is_hash_chained(tmp_path):
    repository = SQLiteRepository(f"sqlite:///{tmp_path / 'audit.db'}")
    service = AdminAuditLogService(repository)
    first = service.append("local", "key-1", "key.create", "api_key", "key-1", {}, "2026-01-01")
    service.append("local", "key-1", "config.update", "config", "global", {}, "2026-01-02")
    assert first["hash"]
    verification = service.verify("local")
    assert verification["valid"] is True
    assert verification["count"] == 2


def test_webhook_signature_timestamp_and_replay_window():
    body = b'{"event":"test"}'
    timestamp = "1700000000"
    secret = "long-random-webhook-secret"
    signature = sign_payload(secret, int(timestamp), body)
    assert verify_signature(
        secret, timestamp, body, signature, replay_window_seconds=300, now=1700000001
    )
    assert not verify_signature(
        secret, timestamp, b'{"event":"changed"}', signature,
        replay_window_seconds=300, now=1700000001,
    )
    assert not verify_signature(
        secret, timestamp, body, signature,
        replay_window_seconds=300, now=1700001000,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/hook",
        "https://127.0.0.1/hook",
        "https://10.0.0.1/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/hook",
        "https://example.com/hook#fragment",
    ],
)
def test_webhook_url_validation_blocks_insecure_and_internal_targets(url):
    with pytest.raises(WebhookValidationError):
        validate_webhook_url(url)


def test_signed_sender_rejects_redirect_and_https_only():
    sender = SignedWebhookSender("secret")
    with pytest.raises(WebhookValidationError):
        asyncio.run(sender.send_async("http://example.com/hook", b"{}"))


def test_canary_log_context_has_no_secret_values():
    safe = safe_log_context({
        "route": "/v1/admin/api-keys",
        "X-API-Key": "abb_supersecretvalue",
        "password": "secret-password",
        "email": "person@example.com",
    })
    encoded = json.dumps(safe)
    assert "abb_supersecretvalue" not in encoded
    assert "secret-password" not in encoded
    assert "[REDACTED]" in encoded


def test_sensitive_routes_and_audit_export_are_checked(tmp_path):
    app = create_app(Settings(
        api_key="test-key",
        database_url=f"sqlite:///{tmp_path / 'rbac.db'}",
        payload_key="local-test-key",
    ))

    async def run():
        missing = await request(app, "GET", "/v1/admin/audit-log")
        assert missing.status_code == 401

        reader = await request(app, "POST", "/v1/admin/api-keys", headers={
            "X-API-Key": "test-key"
        }, json={"name": "reader", "scopes": ["read"]})
        assert reader.status_code == 201
        raw = reader.json()["raw_key"]

        denied = await request(app, "POST", "/v1/admin/policies", headers={
            "X-API-Key": raw
        }, json={"name": "refund", "rules": {"limit": 100}})
        assert denied.status_code == 403

        audit = await request(app, "GET", "/v1/admin/audit-log", headers={
            "X-API-Key": raw
        })
        assert audit.status_code == 200

    asyncio.run(run())
