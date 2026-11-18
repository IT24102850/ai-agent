import asyncio

import httpx
import pytest

from api.app.config import Settings
from api.app.main import create_app

HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(api_key="test-key", database_url=f"sqlite:///{tmp_path / 'test.db'}")
    )


async def request(app, method, path, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_health_ready_and_auth(app):
    async def run():
        health = await request(app, "GET", "/health")
        ready = await request(app, "GET", "/ready")
        version = await request(app, "GET", "/version")
        denied = await request(app, "GET", "/v1/sessions")
        assert health.status_code == 200
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        assert version.status_code == 200
        assert version.json()["name"] == "AgentBlackbox"
        assert version.json()["version"] == "0.1.0"
        assert denied.status_code == 401

    asyncio.run(run())


def test_scoped_api_keys_rotation_revocation_and_route_metadata(app):
    async def run():
        tenant = await request(
            app,
            "POST",
            "/v1/admin/tenants",
            headers=HEADERS,
            json={"name": "Customer A"},
        )
        assert tenant.status_code == 201

        read_key = await request(
            app,
            "POST",
            "/v1/admin/api-keys",
            headers=HEADERS,
            json={"name": "reader", "scopes": ["read"]},
        )
        assert read_key.status_code == 201
        raw_read = read_key.json()["raw_key"]
        assert "key_hash" not in read_key.json()

        denied = await request(
            app,
            "POST",
            "/v1/sessions",
            headers={"X-API-Key": raw_read},
            json={"name": "forbidden"},
        )
        assert denied.status_code == 403

        ingested = await request(
            app,
            "POST",
            "/v1/admin/api-keys",
            headers=HEADERS,
            json={"name": "ingester", "scopes": ["ingest"]},
        )
        assert ingested.status_code == 201
        raw_ingest = ingested.json()["raw_key"]
        key_id = ingested.json()["id"]

        created = await request(
            app,
            "POST",
            "/v1/sessions",
            headers={"X-API-Key": raw_ingest},
            json={"name": "ingest-only"},
        )
        assert created.status_code == 201

        listed = await request(
            app,
            "GET",
            "/v1/admin/api-keys",
            headers=HEADERS,
        )
        assert listed.status_code == 200
        assert all("raw_key" not in item for item in listed.json()["api_keys"])

        rotated = await request(
            app,
            "POST",
            f"/v1/admin/api-keys/{key_id}/rotate",
            headers=HEADERS,
        )
        assert rotated.status_code == 200
        assert rotated.json()["raw_key"]

        revoked = await request(
            app,
            "POST",
            f"/v1/admin/api-keys/{rotated.json()['id']}/revoke",
            headers=HEADERS,
        )
        assert revoked.status_code == 200
        invalid = await request(
            app,
            "GET",
            "/v1/sessions",
            headers={"X-API-Key": rotated.json()["raw_key"]},
        )
        assert invalid.status_code == 401

        schema = app.openapi()
        assert schema["paths"]["/v1/sessions/{session_id}/events"]["post"][
            "x-agentblackbox-permissions"
        ] == ["ingest"]

    asyncio.run(run())


def test_metrics_and_ready_headers(app):
    async def run():
        ready = await request(app, "GET", "/ready")
        metrics = await request(app, "GET", "/metrics")
        assert ready.status_code == 200
        assert ready.headers["x-agentblackbox-request-duration-ms"]
        assert metrics.status_code == 200
        assert "agentblackbox_database_up 1" in metrics.text
        assert "agentblackbox_requests_total" in metrics.text

    asyncio.run(run())


def test_production_rejects_default_secret(tmp_path):
    with pytest.raises(ValueError):
        Settings(
            environment="production",
            database_url=f"sqlite:///{tmp_path / 'prod.db'}",
        ).validate()


def test_session_events_idempotency_redaction_and_verify(app):
    async def run():
        created = await request(
            app,
            "POST",
            "/v1/sessions",
            headers=HEADERS,
            json={"name": "demo", "metadata": {"email": "a@b.com"}},
        )
        assert created.status_code == 201
        session_id = created.json()["id"]

        event = {
            "event_type": "llm.call",
            "payload": {"prompt": "email a@b.com phone 415-555-2671 card 4242-4242-4242-4242"},
        }
        first = await request(
            app,
            "POST",
            f"/v1/sessions/{session_id}/events",
            headers={**HEADERS, "Idempotency-Key": "same-event"},
            json=event,
        )
        duplicate = await request(
            app,
            "POST",
            f"/v1/sessions/{session_id}/events",
            headers={**HEADERS, "Idempotency-Key": "same-event"},
            json=event,
        )
        assert first.status_code == 200
        assert duplicate.status_code == 200
        assert first.json()["id"] == duplicate.json()["id"]
        assert "[REDACTED_EMAIL]" in duplicate.json()["payload"]["data"]["prompt"]
        assert "[REDACTED_CARD]" in duplicate.json()["payload"]["data"]["prompt"]

        listed = await request(app, "GET", f"/v1/sessions/{session_id}/events", headers=HEADERS)
        assert listed.json()["count"] == 1

        verified = await request(app, "GET", f"/v1/sessions/{session_id}/verify", headers=HEADERS)
        assert verified.status_code == 200
        assert verified.json()["valid"] is True

        ended = await request(app, "POST", f"/v1/sessions/{session_id}/end", headers=HEADERS)
        assert ended.status_code == 200
        assert ended.json()["status"] == "ended"

        got = await request(app, "GET", f"/v1/sessions/{session_id}", headers=HEADERS)
        assert got.json()["status"] == "ended"

    asyncio.run(run())


def test_test_cases_policy_evaluation_and_violation_ingestion(app):
    async def run():
        created = await request(
            app,
            "POST",
            "/v1/sessions",
            headers=HEADERS,
            json={"name": "refund-session"},
        )
        session_id = created.json()["id"]
        ingested = await request(
            app,
            "POST",
            f"/v1/sessions/{session_id}/events",
            headers=HEADERS,
            json={
                "event_type": "decision",
                "payload": {
                    "action": "refund",
                    "amount": 600,
                    "approved": False,
                },
            },
        )
        assert ingested.status_code == 200

        events = await request(app, "GET", f"/v1/sessions/{session_id}/events", headers=HEADERS)
        assert any(event["event_type"] == "policy.violation" for event in events.json()["events"])

        test_case = await request(
            app,
            "POST",
            "/v1/test-cases",
            headers=HEADERS,
            json={"session_id": session_id, "name": "refund baseline"},
        )
        assert test_case.status_code == 201
        test_case_id = test_case.json()["id"]

        run_response = await request(
            app,
            "POST",
            f"/v1/test-cases/{test_case_id}/runs",
            headers=HEADERS,
            json={
                "candidate_events": [
                    {
                        "event_type": "decision",
                        "payload": {
                            "action": "refund",
                            "amount": 600,
                            "approved": False,
                        },
                    },
                ]
            },
        )
        assert run_response.status_code == 201
        assert run_response.json()["status"] == "failed"
        assert run_response.json()["diff"]
        assert run_response.json()["violations"]

        policies = await request(app, "GET", "/v1/policies", headers=HEADERS)
        assert policies.status_code == 200
        assert policies.json()["count"] == 6

    asyncio.run(run())
