"""FastAPI routes and application factory."""

from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from xml.etree import ElementTree as ET

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from agentblackbox import (
    ChainEntry,
    ChainVerification,
    entry_hash,
    evaluate_policies,
    load_policy_yaml,
    structured_diff,
    verify_chain_result,
)
from agentblackbox.export import export_session_bundle
from agentblackbox.reports import (
    PdfUnavailableError,
    deterministic_audit_report,
    pdf_report_bytes,
)

from .audit import AdminAuditLogService
from .config import Settings
from .db import SQLiteRepository
from .encryption import EnvelopeEncryptor, LocalDevelopmentKeyProvider, ProductionKMSRequired
from .object_store import LocalFilesystemObjectStore
from .rbac import Role
from .redaction import redact_stable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionEnd(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=1, max_length=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str | None = None


class TestCaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TestRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_events: list[dict[str, Any]]


class PolicyEvaluateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: dict[str, Any] = Field(default_factory=dict)


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)


class APIKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=lambda: ["read"])
    expires_at: str | None = None


class RetentionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_days: int = Field(ge=0)


class PolicyEditCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    rules: dict[str, Any] = Field(default_factory=dict)


class TestSuiteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    test_case_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TestSuiteRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidates: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class BaselineUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseline_events: list[dict[str, Any]]


class RunApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved_by: str = "console"


def create_app(
    settings: Settings | None = None,
    *,
    key_provider: Any | None = None,
    object_store: Any | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    if key_provider is None:
        if settings.environment.lower() == "production":
            key_provider = ProductionKMSRequired()
        else:
            key_provider = LocalDevelopmentKeyProvider(settings.payload_key)
    payload_encryptor = EnvelopeEncryptor(key_provider)
    if object_store is None:
        object_store = LocalFilesystemObjectStore(settings.object_store_root)
    repository = SQLiteRepository(
        settings.database_url,
        key_provider=key_provider,
        payload_encryptor=payload_encryptor,
        object_store=object_store,
        large_payload_threshold=settings.large_payload_threshold,
    )
    admin_audit = AdminAuditLogService(repository)
    local_tenant_id = "local"
    if not repository.get_tenant(local_tenant_id):
        repository.create_tenant(local_tenant_id, "Local development", utc_now())
    app = FastAPI(title="AgentBlackbox", version="0.1.0")
    policy_pack_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "agentblackbox"
        / "policy_packs"
        / "customer_support_refunds.yaml"
    )
    policy_rules = load_policy_yaml(policy_pack_path)
    request_metrics = {"requests": 0, "ingested_events": 0, "policy_violations": 0}
    metrics_lock = threading.Lock()

    async def require_api_key(
        x_api_key: str = Header(default="", alias="X-API-Key"),
    ) -> dict[str, Any]:
        scoped = repository.authenticate_api_key(x_api_key, settings.api_key_pepper)
        if scoped:
            tenant = repository.get_tenant(scoped["tenant_id"])
            if not tenant or tenant["status"] != "active":
                raise HTTPException(status_code=401, detail="Invalid tenant")
            admin_audit.append(
                scoped["tenant_id"], scoped["id"], "login.success",
                "api_key", scoped["id"], {"method": "api_key"}, utc_now(),
            )
            return {
                "tenant_id": scoped["tenant_id"],
                "key_id": scoped["id"],
                "scopes": scoped["scopes"],
                "role": (
                    "owner"
                    if "admin" in scoped["scopes"]
                    else "analyst"
                    if "ingest" in scoped["scopes"]
                    else "auditor_readonly"
                    if "read" in scoped["scopes"]
                    else "service"
                ),
            }
        if secrets.compare_digest(x_api_key, settings.api_key):
            admin_audit.append(
                local_tenant_id, None, "login.success",
                "api_key", None, {"method": "local_api_key"}, utc_now(),
            )
            return {
                "tenant_id": local_tenant_id,
                "key_id": None,
                "scopes": ["ingest", "read", "admin"],
                "role": Role.OWNER.value,
            }
        if not x_api_key:
            admin_audit.append(
                local_tenant_id, None, "login.failure",
                "api_key", None, {"method": "api_key", "reason": "missing"}, utc_now(),
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        admin_audit.append(
            local_tenant_id, None, "login.failure",
            "api_key", None, {"method": "api_key", "reason": "invalid"}, utc_now(),
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    def authorize(scope: str):
        async def scoped(principal: dict[str, Any] = Depends(require_api_key)) -> dict[str, Any]:
            if scope not in principal["scopes"]:
                raise HTTPException(status_code=403, detail=f"Missing {scope} scope")
            return principal

        return Depends(scoped)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {
            "name": app.title,
            "version": app.version,
            "environment": settings.environment,
        }

    @app.get("/ready")
    async def ready() -> dict[str, Any]:
        db_ok = repository.ping()
        body = {"status": "ready" if db_ok else "not_ready", "database": "ok" if db_ok else "error"}
        return JSONResponse(body, status_code=200 if db_ok else 503)

    @app.post(
        "/v1/admin/tenants",
        status_code=201,
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def create_tenant(
        body: TenantCreate, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        tenant_id = str(uuid4())
        tenant = repository.create_tenant(tenant_id, body.name, utc_now())
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "tenant.create",
            "tenant",
            tenant_id,
            {"name": body.name},
            utc_now(),
        )
        return tenant

    @app.get(
        "/v1/admin/tenants",
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def list_tenants(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
        items = repository.list_tenants(limit)
        return {"tenants": items, "count": len(items)}

    @app.put(
        "/v1/admin/tenants/{tenant_id}/retention",
        dependencies=[authorize("admin")],
    )
    async def set_tenant_retention(
        tenant_id: str,
        body: RetentionUpdate,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        item = repository.set_tenant_retention(tenant_id, body.retention_days)
        if not item:
            raise HTTPException(status_code=404, detail="Tenant not found")
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "tenant.retention.update",
            "tenant",
            tenant_id,
            {"retention_days": body.retention_days},
            utc_now(),
        )
        return item

    @app.post(
        "/v1/admin/tenants/{tenant_id}/purge",
        dependencies=[authorize("admin")],
    )
    async def purge_tenant(
        tenant_id: str,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        if not repository.get_tenant(tenant_id):
            raise HTTPException(status_code=404, detail="Tenant not found")
        result = repository.purge_tenant_payloads(tenant_id)
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "tenant.payload.purge",
            "tenant",
            tenant_id,
            {"purged": result["purged"]},
            utc_now(),
        )
        return result

    @app.post(
        "/v1/admin/api-keys",
        status_code=201,
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def create_api_key(
        body: APIKeyCreate, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        allowed = {"ingest", "read", "admin"}
        if any(scope not in allowed for scope in body.scopes):
            raise HTTPException(status_code=400, detail="Invalid API key scope")
        raw_key = f"abb_{secrets.token_urlsafe(32)}"
        key_id = str(uuid4())
        item = repository.create_api_key(
            key_id,
            principal["tenant_id"],
            body.name,
            raw_key,
            settings.api_key_pepper,
            body.scopes,
            body.expires_at,
            utc_now(),
        )
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "api_key.create",
            "api_key",
            key_id,
            {"name": body.name, "scopes": body.scopes},
            utc_now(),
        )
        return {**item, "raw_key": raw_key}

    @app.post(
        "/v1/admin/api-keys/{key_id}/rotate",
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def rotate_api_key(
        key_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        raw_key = f"abb_{secrets.token_urlsafe(32)}"
        item, _ = repository.rotate_api_key(
            principal["tenant_id"],
            key_id,
            raw_key,
            settings.api_key_pepper,
            None,
            utc_now(),
            utc_now(),
        )
        if not item:
            raise HTTPException(status_code=404, detail="API key not found")
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "api_key.rotate",
            "api_key",
            item["id"],
            {},
            utc_now(),
        )
        return {**item, "raw_key": raw_key}

    @app.post(
        "/v1/admin/api-keys/{key_id}/revoke",
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def revoke_api_key(
        key_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        revoked = repository.revoke_api_key(principal["tenant_id"], key_id, utc_now())
        if not revoked:
            raise HTTPException(status_code=404, detail="Active API key not found")
        repository.add_audit(
            principal["tenant_id"],
            principal["key_id"],
            "api_key.revoke",
            "api_key",
            key_id,
            {},
            utc_now(),
        )
        return {"id": key_id, "revoked": True}

    @app.get(
        "/v1/admin/api-keys",
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def list_api_keys(
        limit: int = Query(default=100, ge=1, le=1000),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        items = repository.list_api_keys(principal["tenant_id"], limit)
        return {"api_keys": items, "count": len(items)}

    @app.get(
        "/v1/admin/audit-log",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_admin_audit_log(
        limit: int = Query(default=1000, ge=1, le=10000),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        items = repository.list_audit(principal["tenant_id"], limit)
        return {
            "audit_log": items,
            "count": len(items),
            "verification": admin_audit.verify(principal["tenant_id"]),
        }

    @app.get("/metrics")
    async def metrics() -> Response:
        with metrics_lock:
            requests = request_metrics["requests"]
            ingested = request_metrics["ingested_events"]
            violations = request_metrics["policy_violations"]
        db_ok = repository.ping()
        text = (
            "# HELP agentblackbox_requests_total Number of instrumented API operations.\n"
            "# TYPE agentblackbox_requests_total counter\n"
            f"agentblackbox_requests_total {requests}\n"
            "# HELP agentblackbox_events_ingested_total Number of ingested events.\n"
            "# TYPE agentblackbox_events_ingested_total counter\n"
            f"agentblackbox_events_ingested_total {ingested}\n"
            "# HELP agentblackbox_policy_violations_total Number of emitted policy violations.\n"
            "# TYPE agentblackbox_policy_violations_total counter\n"
            f"agentblackbox_policy_violations_total {violations}\n"
            "# HELP agentblackbox_database_up Whether the local database is reachable.\n"
            "# TYPE agentblackbox_database_up gauge\n"
            f"agentblackbox_database_up {1 if db_ok else 0}\n"
        )
        return Response(content=text, media_type="text/plain")

    @app.middleware("http")
    async def count_requests(request: Any, call_next: Any) -> Response:
        started = time.monotonic()
        response = await call_next(request)
        with metrics_lock:
            request_metrics["requests"] += 1
        response.headers["X-AgentBlackbox-Request-Duration-Ms"] = str(
            round((time.monotonic() - started) * 1000, 3)
        )
        return response

    @app.post(
        "/v1/sessions",
        status_code=201,
        dependencies=[authorize("ingest")],
        openapi_extra={"x-agentblackbox-permissions": ["ingest"]},
    )
    async def create_session(
        body: SessionCreate, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session_id = str(uuid4())
        return repository.create_session(
            session_id,
            body.name,
            redact_stable(body.metadata, settings.api_key_pepper),
            utc_now(),
            principal["tenant_id"],
        )

    @app.get(
        "/v1/sessions",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_sessions(
        limit: int = Query(default=100, ge=1, le=1000),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        items = repository.list_sessions(limit, principal["tenant_id"])
        return {"sessions": items, "count": len(items)}

    @app.get(
        "/v1/sessions/{session_id}",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def get_session(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session = repository.get_session(session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    @app.post(
        "/v1/sessions/{session_id}/events",
        dependencies=[authorize("ingest")],
        openapi_extra={"x-agentblackbox-permissions": ["ingest"]},
    )
    async def ingest_event(
        session_id: str,
        body: EventCreate,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        session = repository.get_session(session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        if session["status"] == "ended":
            raise HTTPException(status_code=409, detail="Session is ended")

        if idempotency_key:
            existing = repository.get_idempotent_event(session_id, idempotency_key)
            if existing:
                safe_payload = redact_stable(body.payload, settings.api_key_pepper)
                existing_payload = existing["payload"]
                existing_data = (
                    existing_payload.get("data")
                    if isinstance(existing_payload, dict) and "data" in existing_payload
                    else existing_payload
                )
                if existing["event_type"] != body.event_type or existing_data != safe_payload:
                    raise HTTPException(
                        status_code=409,
                        detail="Idempotency key reused with different event",
                    )
                return existing

        head_hash, sequence = repository.head(session_id)
        safe_payload = {
            "event_type": body.event_type,
            "data": redact_stable(body.payload, settings.api_key_pepper),
        }
        timestamp = body.timestamp or utc_now()
        hash_ = entry_hash(
            sequence,
            safe_payload,
            head_hash,
            tenant_id=principal["tenant_id"],
            session_id=session_id,
            event_type=body.event_type,
        )
        event_id = str(uuid4())
        try:
            ingested = repository.append_event(
                event_id,
                session_id,
                body.event_type,
                safe_payload,
                timestamp,
                sequence,
                head_hash,
                hash_,
                idempotency_key,
                principal["tenant_id"],
            )
            with metrics_lock:
                request_metrics["ingested_events"] += 1
        except Exception as exc:
            raise HTTPException(status_code=409, detail="Event ingestion conflict") from exc

        policy_context = dict(safe_payload["data"])
        policy_context["event_type"] = body.event_type
        violations = evaluate_policies(policy_rules, policy_context)
        if violations:
            violation_payload = {"violations": violations}
            with metrics_lock:
                request_metrics["policy_violations"] += len(violations)
            violation_head, violation_sequence = repository.head(session_id)
            violation_hash = entry_hash(
                violation_sequence,
                {"event_type": "policy.violation", "data": violation_payload},
                violation_head,
                tenant_id=principal["tenant_id"],
                session_id=session_id,
                event_type="policy.violation",
            )
            repository.append_event(
                str(uuid4()),
                session_id,
                "policy.violation",
                {"event_type": "policy.violation", "data": violation_payload},
                utc_now(),
                violation_sequence,
                violation_head,
                violation_hash,
                None,
                principal["tenant_id"],
            )
        return ingested

    @app.post(
        "/v1/sessions/{session_id}/end",
        dependencies=[authorize("ingest")],
        openapi_extra={"x-agentblackbox-permissions": ["ingest"]},
    )
    async def end_session(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session = repository.end_session(session_id, utc_now(), principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return session

    @app.get(
        "/v1/sessions/{session_id}/events",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_events(
        session_id: str,
        limit: int = Query(default=1000, ge=1, le=10000),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        if not repository.get_session(session_id, principal["tenant_id"]):
            raise HTTPException(status_code=404, detail="Session not found")
        events = repository.list_events(session_id, limit, principal["tenant_id"])
        return {"events": events, "count": len(events)}

    @app.post(
        "/v1/sessions/{session_id}/verify",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    @app.get(
        "/v1/sessions/{session_id}/verify",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def verify_session(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        if not repository.get_session(session_id, principal["tenant_id"]):
            raise HTTPException(status_code=404, detail="Session not found")
        events = repository.list_events(session_id, 10000, principal["tenant_id"])
        entries = []
        for event in events:
            payload = (
                {"event_type": event["event_type"], "data": event["payload"]["data"]}
                if isinstance(event["payload"], dict)
                and event["payload"].get("event_type") == event["event_type"]
                else event["payload"]
            )
            entries.append(
                ChainEntry(
                    sequence=event["sequence"],
                    payload=payload,
                    previous_hash=event["previous_hash"],
                    hash=event["hash"],
                    tenant_id=principal["tenant_id"],
                    session_id=session_id,
                    event_type=event["event_type"],
                )
            )
        if any(event["payload_purged"] for event in events):
            valid = True
            reason = None
            for expected_sequence, event in enumerate(events):
                if event["sequence"] != expected_sequence:
                    valid = False
                    reason = "sequence_mismatch"
                    break
                previous = "0" * 64
                if expected_sequence:
                    previous = events[expected_sequence - 1]["hash"]
                if event["previous_hash"] != previous:
                    valid = False
                    reason = "previous_hash_mismatch"
                    break
                if event["payload_purged"] and not event["payload_content_hash"]:
                    valid = False
                    reason = "purged_payload_hash_missing"
                    break
            result = ChainVerification(valid=valid, sequence=len(events), reason=reason)
        else:
            result = verify_chain_result(entries)
        head, count = repository.head(session_id)
        return {
            "valid": result.valid,
            "sequence": result.sequence,
            "reason": result.reason,
            "count": count,
            "head": head,
        }

    @app.get(
        "/v1/sessions/{session_id}/export",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def export_session(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session = repository.get_session(session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        events = repository.list_events(session_id, 10000, principal["tenant_id"])
        admin_audit.append(
            principal["tenant_id"],
            principal["key_id"],
            "export.create",
            "session",
            session_id,
            {"format": "json"},
            utc_now(),
        )
        return export_session_bundle(session, events)

    @app.get(
        "/v1/sessions/{session_id}/audit-report",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def audit_report(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session = repository.get_session(session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        bundle = export_session_bundle(
            session, repository.list_events(session_id, 10000, principal["tenant_id"])
        )
        return JSONResponse(deterministic_audit_report(bundle))

    @app.get(
        "/v1/sessions/{session_id}/report.pdf",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def pdf_report(
        session_id: str, principal: dict[str, Any] = Depends(require_api_key)
    ) -> Response:
        session = repository.get_session(session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        bundle = export_session_bundle(
            session, repository.list_events(session_id, 10000, principal["tenant_id"])
        )
        report = deterministic_audit_report(bundle)
        try:
            content = pdf_report_bytes(report)
        except PdfUnavailableError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        return Response(content=content, media_type="application/pdf")

    @app.post(
        "/v1/test-cases",
        status_code=201,
        dependencies=[authorize("ingest")],
        openapi_extra={"x-agentblackbox-permissions": ["ingest"]},
    )
    async def create_test_case(
        body: TestCaseCreate, principal: dict[str, Any] = Depends(require_api_key)
    ) -> dict[str, Any]:
        session = repository.get_session(body.session_id, principal["tenant_id"])
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        events = repository.list_events(body.session_id)
        baseline = [
            {
                "event_type": event["event_type"],
                "payload": event["payload"].get("data", event["payload"]),
            }
            for event in events
        ]
        name = body.name or f"Test case for {body.session_id}"
        return repository.create_test_case(
            str(uuid4()),
            name,
            body.session_id,
            redact_stable(body.metadata, settings.api_key_pepper),
            baseline,
            utc_now(),
        )

    @app.get(
        "/v1/test-cases",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_test_cases(
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        items = repository.list_test_cases(limit)
        return {"test_cases": items, "count": len(items)}

    @app.get(
        "/v1/test-cases/{test_case_id}",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def get_test_case(test_case_id: str) -> dict[str, Any]:
        item = repository.get_test_case(test_case_id)
        if not item:
            raise HTTPException(status_code=404, detail="Test case not found")
        return item

    @app.post(
        "/v1/test-cases/{test_case_id}/runs",
        status_code=201,
        dependencies=[authorize("ingest")],
        openapi_extra={"x-agentblackbox-permissions": ["ingest"]},
    )
    async def create_test_run(test_case_id: str, body: TestRunCreate) -> dict[str, Any]:
        test_case = repository.get_test_case(test_case_id)
        if not test_case:
            raise HTTPException(status_code=404, detail="Test case not found")
        safe_candidate_events = [
            {
                "event_type": event.get("event_type", ""),
                "payload": redact_stable(event.get("payload", {}), settings.api_key_pepper),
            }
            for event in body.candidate_events
        ]
        diff = structured_diff(
            {"events": test_case["baseline_events"]},
            {"events": safe_candidate_events},
        )
        violations: list[dict[str, Any]] = []
        for event in safe_candidate_events:
            context = dict(event.get("payload", {}))
            context["event_type"] = event.get("event_type", "")
            violations.extend(evaluate_policies(policy_rules, context))
        if violations:
            status = "failed"
        elif diff:
            status = "changed"
        else:
            status = "passed"
        run = repository.create_test_run(
            str(uuid4()),
            test_case_id,
            safe_candidate_events,
            diff,
            status,
            violations,
            utc_now(),
        )
        run["sandbox"] = {
            "network_allowed": False,
            "credentials_allowed": False,
            "process_allowed": False,
            "real_tools_executed": False,
        }
        return run

    @app.get(
        "/v1/test-cases/{test_case_id}/runs",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_test_runs(
        test_case_id: str,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        if not repository.get_test_case(test_case_id):
            raise HTTPException(status_code=404, detail="Test case not found")
        items = repository.list_test_runs(test_case_id, limit)
        return {"test_runs": items, "count": len(items)}

    @app.post(
        "/v1/test-cases/{test_case_id}/baseline",
        dependencies=[authorize("ingest")],
    )
    async def update_test_case_baseline(test_case_id: str, body: BaselineUpdate) -> dict[str, Any]:
        item = repository.update_test_case_baseline(test_case_id, body.baseline_events)
        if not item:
            raise HTTPException(status_code=404, detail="Test case not found")
        return item

    @app.post(
        "/v1/test-runs/{test_run_id}/approve",
        dependencies=[authorize("ingest")],
    )
    async def approve_test_run(
        test_run_id: str,
        body: RunApproval,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        item = repository.approve_test_run(test_run_id, body.approved_by, utc_now())
        if not item:
            raise HTTPException(status_code=404, detail="Test run not found")
        return item

    @app.get("/v1/test-runs/{test_run_id}",
             dependencies=[authorize("read")])
    async def get_test_run(test_run_id: str) -> dict[str, Any]:
        item = repository.get_test_run(test_run_id)
        if not item:
            raise HTTPException(status_code=404, detail="Test run not found")
        return item

    @app.post("/v1/test-suites", status_code=201, dependencies=[authorize("ingest")])
    async def create_test_suite(
        body: TestSuiteCreate,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        for test_case_id in body.test_case_ids:
            if not repository.get_test_case(test_case_id):
                raise HTTPException(status_code=404, detail=f"Test case not found: {test_case_id}")
        return repository.create_test_suite(
            str(uuid4()), body.name, body.test_case_ids,
            redact_stable(body.metadata, settings.api_key_pepper),
            principal["tenant_id"], utc_now(),
        )

    @app.get("/v1/test-suites", dependencies=[authorize("read")])
    async def list_test_suites(
        limit: int = Query(default=100, ge=1, le=1000),
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        items = repository.list_test_suites(principal["tenant_id"], limit)
        return {"test_suites": items, "count": len(items)}

    @app.get("/v1/test-suites/{suite_id}", dependencies=[authorize("read")])
    async def get_test_suite(suite_id: str) -> dict[str, Any]:
        item = repository.get_test_suite(suite_id)
        if not item:
            raise HTTPException(status_code=404, detail="Test suite not found")
        return item

    @app.post("/v1/test-suites/{suite_id}/runs", status_code=201,
              dependencies=[authorize("ingest")])
    async def create_test_suite_run(
        suite_id: str,
        body: TestSuiteRunCreate,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        suite = repository.get_test_suite(suite_id)
        if not suite:
            raise HTTPException(status_code=404, detail="Test suite not found")
        test_run_ids: list[str] = []
        counts = {"passed": 0, "changed": 0, "failed": 0, "errored": 0}
        for test_case_id in suite["test_case_ids"]:
            test_case = repository.get_test_case(test_case_id)
            if not test_case:
                counts["errored"] += 1
                continue
            candidate_events = body.candidates.get(test_case_id, test_case["baseline_events"])
            safe_candidate = [
                {
                    "event_type": event.get("event_type", ""),
                    "payload": redact_stable(event.get("payload", {}), settings.api_key_pepper),
                }
                for event in candidate_events
            ]
            diff = structured_diff(
                {"events": test_case["baseline_events"]},
                {"events": safe_candidate},
            )
            violations: list[dict[str, Any]] = []
            for event in safe_candidate:
                context = dict(event["payload"])
                context["event_type"] = event["event_type"]
                violations.extend(evaluate_policies(policy_rules, context))
            if violations:
                run_status = "failed"
            elif diff:
                run_status = "changed"
            else:
                run_status = "passed"
            counts[run_status] += 1
            run = repository.create_test_run(
                str(uuid4()), test_case_id, safe_candidate, diff,
                run_status, violations, utc_now(),
            )
            test_run_ids.append(run["id"])
        suite_status = "failed" if counts["failed"] or counts["errored"] else (
            "changed" if counts["changed"] else "passed"
        )
        return repository.create_test_suite_run(
            str(uuid4()), suite_id, test_run_ids, suite_status,
            counts, principal["tenant_id"], utc_now(),
        )

    @app.get("/v1/test-suites/{suite_id}/runs", dependencies=[authorize("read")])
    async def list_test_suite_runs(
        suite_id: str,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        if not repository.get_test_suite(suite_id):
            raise HTTPException(status_code=404, detail="Test suite not found")
        items = repository.list_test_suite_runs(suite_id, limit)
        return {"suite_runs": items, "count": len(items)}

    @app.get("/v1/test-suites/{suite_id}/runs/{suite_run_id}/junit",
             dependencies=[authorize("read")])
    async def suite_run_junit(suite_id: str, suite_run_id: str) -> Response:
        suite_run = repository.get_test_suite_run(suite_run_id)
        if not suite_run or suite_run["suite_id"] != suite_id:
            raise HTTPException(status_code=404, detail="Suite run not found")
        counts = suite_run["summary"]
        runs = [repository.get_test_run(run_id) for run_id in suite_run["test_run_ids"]]
        root = ET.Element(
            "testsuite",
            name=suite_id,
            tests=str(len(runs)),
            failures=str(counts.get("failed", 0)),
            errors=str(counts.get("errored", 0)),
        )
        for run in runs:
            if not run:
                continue
            case = ET.SubElement(root, "testcase", name=run["test_case_id"])
            if run["status"] == "failed":
                ET.SubElement(case, "failure").text = json.dumps(run["diff"], sort_keys=True)
            elif run["status"] == "changed":
                ET.SubElement(case, "skipped").text = json.dumps(run["diff"], sort_keys=True)
        xml = ET.tostring(root, encoding="unicode", xml_declaration=True)
        return Response(content=xml, media_type="application/xml")

    @app.get(
        "/v1/policies",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def list_policies() -> dict[str, Any]:
        return {"policies": policy_rules, "count": len(policy_rules)}

    @app.post(
        "/v1/admin/policies",
        dependencies=[authorize("admin")],
        openapi_extra={"x-agentblackbox-permissions": ["admin"]},
    )
    async def edit_policy(
        body: PolicyEditCreate,
        principal: dict[str, Any] = Depends(require_api_key),
    ) -> dict[str, Any]:
        admin_audit.append(
            principal["tenant_id"],
            principal["key_id"],
            "policy.edit",
            "policy",
            body.name,
            {"name": body.name, "rule_count": len(body.rules)},
            utc_now(),
        )
        return {"name": body.name, "updated": True, "rules": body.rules}

    @app.post(
        "/v1/policies/evaluate",
        dependencies=[authorize("read")],
        openapi_extra={"x-agentblackbox-permissions": ["read"]},
    )
    async def evaluate_policy(body: PolicyEvaluateCreate) -> dict[str, Any]:
        violations = evaluate_policies(policy_rules, body.context)
        return {"violations": violations, "count": len(violations)}

    app.state.repository = repository
    app.state.settings = settings
    return app


app = create_app()
