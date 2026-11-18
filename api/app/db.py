"""Small SQLite repository; the interface intentionally isolates persistence."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class SQLiteRepository:
    """SQLite implementation with PostgreSQL-compatible application models."""

    def __init__(
        self,
        database_url: str,
        *,
        key_provider: Any | None = None,
        payload_encryptor: Any | None = None,
        object_store: Any | None = None,
        large_payload_threshold: int = 1024 * 1024,
    ) -> None:
        self.key_provider = key_provider
        self.payload_encryptor = payload_encryptor
        self.object_store = object_store
        self.large_payload_threshold = large_payload_threshold
        if not database_url.startswith("sqlite:///"):
            raise ValueError("This bounded implementation supports sqlite:/// URLs")
        path = database_url.removeprefix("sqlite:///")
        if path == ":memory:":
            self.path = f"file:agentblackbox_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._uri = True
        else:
            self.path = str(Path(path).resolve())
            self._uri = False
        if not self._uri:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, check_same_thread=False, uri=self._uri)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self._lock, self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    retention_days INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    scopes TEXT NOT NULL DEFAULT '[]',
                    expires_at TEXT,
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(tenant_id) REFERENCES tenants(id)
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    actor_key_id TEXT,
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    hash TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(tenant_id) REFERENCES tenants(id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    name TEXT,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    ended_at TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_purged INTEGER NOT NULL DEFAULT 0,
                    payload_purged_at TEXT,
                    payload_content_hash TEXT,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    UNIQUE(session_id, sequence),
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    session_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    PRIMARY KEY(session_id, idempotency_key),
                    FOREIGN KEY(session_id) REFERENCES sessions(id),
                    FOREIGN KEY(event_id) REFERENCES events(id)
                );
                CREATE TABLE IF NOT EXISTS test_cases (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    name TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    baseline_events TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE TABLE IF NOT EXISTS test_runs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    test_case_id TEXT NOT NULL,
                    candidate_events TEXT NOT NULL,
                    diff TEXT NOT NULL,
                    status TEXT NOT NULL,
                    violations TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(test_case_id) REFERENCES test_cases(id)
                );
                CREATE TABLE IF NOT EXISTS test_suites (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    name TEXT NOT NULL,
                    test_case_ids TEXT NOT NULL DEFAULT '[]',
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS test_suite_runs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    suite_id TEXT NOT NULL,
                    test_run_ids TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(suite_id) REFERENCES test_suites(id)
                );
                CREATE INDEX IF NOT EXISTS events_session_idx ON events(session_id, sequence);
                """
            )
            for table in (
                "sessions", "events", "test_cases", "test_runs",
                "test_suites", "test_suite_runs",
            ):
                columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                if "tenant_id" not in columns:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT")
            tenant_columns = {row[1] for row in connection.execute("PRAGMA table_info(tenants)")}
            if "retention_days" not in tenant_columns:
                connection.execute(
                    "ALTER TABLE tenants ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 0"
                )
            event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
            for column, definition in (
                ("payload_purged", "INTEGER NOT NULL DEFAULT 0"),
                ("payload_purged_at", "TEXT"),
                ("payload_content_hash", "TEXT"),
            ):
                if column not in event_columns:
                    connection.execute(f"ALTER TABLE events ADD COLUMN {column} {definition}")
            test_case_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(test_cases)")
            }
            if "suite_id" not in test_case_columns:
                connection.execute("ALTER TABLE test_cases ADD COLUMN suite_id TEXT")
            test_run_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(test_runs)")
            }
            for column, definition in (
                ("approved_at", "TEXT"),
                ("approved_by", "TEXT"),
            ):
                if column not in test_run_columns:
                    connection.execute(f"ALTER TABLE test_runs ADD COLUMN {column} {definition}")
            audit_columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_log)")}
            if "previous_hash" not in audit_columns:
                connection.execute(
                    "ALTER TABLE audit_log ADD COLUMN previous_hash TEXT NOT NULL DEFAULT '0'"
                )
            if "hash" not in audit_columns:
                connection.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def hash_api_key(raw_key: str, pepper: str) -> str:
        return hmac.new(pepper.encode("utf-8"), raw_key.encode("utf-8"), hashlib.sha256).hexdigest()

    def create_tenant(self, tenant_id: str, name: str, created_at: str) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)",
                (tenant_id, name, created_at),
            )
            row = connection.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return dict(row)

    def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return dict(row) if row else None

    def list_tenants(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tenants ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def create_api_key(
        self,
        key_id: str,
        tenant_id: str,
        name: str,
        raw_key: str,
        pepper: str,
        scopes: list[str],
        expires_at: str | None,
        created_at: str,
    ) -> dict[str, Any]:
        prefix = raw_key[:12]
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO api_keys(
                    id,tenant_id,name,key_prefix,key_hash,scopes,expires_at,created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    key_id,
                    tenant_id,
                    name,
                    prefix,
                    self.hash_api_key(raw_key, pepper),
                    json.dumps(scopes),
                    expires_at,
                    created_at,
                ),
            )
            row = connection.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        return self._api_key(row)

    def authenticate_api_key(self, raw_key: str, pepper: str) -> dict[str, Any] | None:
        digest = self.hash_api_key(raw_key, pepper)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM api_keys WHERE key_hash=?",
                (digest,),
            ).fetchone()
        if not row:
            return None
        item = self._api_key(row)
        if item["revoked_at"] or (item["expires_at"] and item["expires_at"] <= now):
            return None
        return item

    def rotate_api_key(
        self,
        tenant_id: str,
        key_id: str,
        raw_key: str,
        pepper: str,
        expires_at: str | None,
        created_at: str,
        revoked_at: str,
    ) -> tuple[dict[str, Any] | None, str | None]:
        with self._lock, self.connect() as connection:
            old = connection.execute(
                "SELECT * FROM api_keys WHERE id=? AND tenant_id=?", (key_id, tenant_id)
            ).fetchone()
            if not old:
                return None, None
            connection.execute(
                "UPDATE api_keys SET revoked_at=? WHERE id=? AND tenant_id=?",
                (revoked_at, key_id, tenant_id),
            )
            new_id = str(uuid.uuid4())
            scopes = json.loads(old["scopes"])
            connection.execute(
                """
                INSERT INTO api_keys(
                    id,tenant_id,name,key_prefix,key_hash,scopes,expires_at,created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    new_id,
                    tenant_id,
                    old["name"],
                    raw_key[:12],
                    self.hash_api_key(raw_key, pepper),
                    json.dumps(scopes),
                    expires_at,
                    created_at,
                ),
            )
            row = connection.execute("SELECT * FROM api_keys WHERE id=?", (new_id,)).fetchone()
        return self._api_key(row), raw_key

    def revoke_api_key(self, tenant_id: str, key_id: str, revoked_at: str) -> bool:
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE api_keys
                SET revoked_at=?
                WHERE id=? AND tenant_id=? AND revoked_at IS NULL
                """,
                (revoked_at, key_id, tenant_id),
            )
            return cursor.rowcount == 1

    def list_api_keys(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [self._api_key(row) for row in rows]

    def add_audit(
        self,
        tenant_id: str,
        actor_key_id: str | None,
        action: str,
        target_type: str | None,
        target_id: str | None,
        metadata: dict[str, Any],
        created_at: str,
    ) -> dict[str, Any]:
        audit_id = str(uuid.uuid4())
        with self._lock, self.connect() as connection:
            if not connection.execute(
                "SELECT 1 FROM tenants WHERE id=?", (tenant_id,)
            ).fetchone():
                connection.execute(
                    "INSERT INTO tenants(id,name,created_at) VALUES(?,?,?)",
                    (tenant_id, "Audit-only tenant", created_at),
                )
            row = connection.execute(
                """
                SELECT hash FROM audit_log
                WHERE tenant_id=? ORDER BY created_at DESC, id DESC LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
            previous_hash = row["hash"] if row and row["hash"] else "0" * 64
            event = {
                "id": audit_id,
                "tenant_id": tenant_id,
                "actor_id": actor_key_id,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "metadata": metadata,
                "created_at": created_at,
            }
            from .audit import audit_event_hash
            event_hash = audit_event_hash(previous_hash, event)
            connection.execute(
                """
                INSERT INTO audit_log(
                    id,tenant_id,actor_key_id,action,target_type,target_id,metadata,
                    created_at,previous_hash,hash
                )
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    audit_id,
                    tenant_id,
                    actor_key_id,
                    action,
                    target_type,
                    target_id,
                    json.dumps(metadata),
                    created_at,
                    previous_hash,
                    event_hash,
                ),
            )
        return {
            "id": audit_id,
            "tenant_id": tenant_id,
            "action": action,
            "previous_hash": previous_hash,
            "hash": event_hash,
        }

    def list_audit(self, tenant_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_log
                WHERE tenant_id=? ORDER BY created_at ASC, id ASC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _api_key(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "key_prefix": row["key_prefix"],
            "scopes": json.loads(row["scopes"]),
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
            "created_at": row["created_at"],
        }

    def ping(self) -> bool:
        try:
            with self.connect() as connection:
                connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def set_tenant_retention(
        self, tenant_id: str, retention_days: int
    ) -> dict[str, Any] | None:
        if retention_days < 0:
            raise ValueError("retention_days must be non-negative")
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                "UPDATE tenants SET retention_days=? WHERE id=?",
                (retention_days, tenant_id),
            )
            row = connection.execute(
                "SELECT * FROM tenants WHERE id=?", (tenant_id,)
            ).fetchone()
        return dict(row) if cursor.rowcount and row else None

    set_tenant_retention_days = set_tenant_retention

    def purge_tenant_payloads(
        self, tenant_id: str, before: str | None = None
    ) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            if before:
                rows = connection.execute(
                    """
                    SELECT payload FROM events
                    WHERE tenant_id=? AND timestamp<=? AND payload_purged=0
                    """,
                    (tenant_id, before),
                ).fetchall()
                cursor = connection.execute(
                    """
                    UPDATE events
                    SET payload=?, payload_purged=1, payload_purged_at=?
                    WHERE tenant_id=? AND timestamp<=? AND payload_purged=0
                    """,
                    (
                        json.dumps({"purged": True}),
                        datetime.now(timezone.utc).isoformat(),
                        tenant_id,
                        before,
                    ),
                )
            else:
                rows = connection.execute(
                    """
                    SELECT payload FROM events
                    WHERE tenant_id=? AND payload_purged=0
                    """,
                    (tenant_id,),
                ).fetchall()
                cursor = connection.execute(
                    """
                    UPDATE events
                    SET payload=?, payload_purged=1, payload_purged_at=?
                    WHERE tenant_id=? AND payload_purged=0
                    """,
                    (
                        json.dumps({"purged": True}),
                        datetime.now(timezone.utc).isoformat(),
                        tenant_id,
                    ),
                )
        if self.object_store is not None:
            for row in rows:
                try:
                    stored = json.loads(row["payload"])
                    if (
                        isinstance(stored, dict)
                        and stored.get("_agentblackbox_envelope") == "v1"
                        and self.payload_encryptor is not None
                    ):
                        stored = self.payload_encryptor.decrypt(stored)
                    if isinstance(stored, dict) and stored.get("_agentblackbox_object") == "v1":
                        self.object_store.delete(stored["key"])
                except Exception:
                    continue
        return {"tenant_id": tenant_id, "purged": cursor.rowcount}

    purge_payloads = purge_tenant_payloads

    def purge_expired_payloads(self, now: str | None = None) -> dict[str, Any]:
        current = datetime.now(timezone.utc)
        if now:
            current = datetime.fromisoformat(now.replace("Z", "+00:00"))
        purged = 0
        with self._lock, self.connect() as connection:
            tenants = connection.execute(
                "SELECT id,retention_days FROM tenants WHERE retention_days>0"
            ).fetchall()
        for tenant in tenants:
            cutoff = (current - timedelta(days=tenant["retention_days"])).isoformat()
            purged += self.purge_tenant_payloads(tenant["id"], cutoff)["purged"]
        return {"purged": purged}

    def create_session(
        self,
        session_id: str,
        name: str | None,
        metadata: dict[str, Any],
        created_at: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                "INSERT INTO sessions(id,tenant_id,name,metadata,created_at) VALUES(?,?,?,?,?)",
                (session_id, tenant_id, name, json.dumps(metadata), created_at),
            )
        return self.get_session(session_id, tenant_id)

    def get_session(self, session_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            if tenant_id is None:
                row = connection.execute(
                    "SELECT * FROM sessions WHERE id=?", (session_id,)
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM sessions WHERE id=? AND (tenant_id=? OR tenant_id IS NULL)",
                    (session_id, tenant_id),
                ).fetchone()
        return self._session(row) if row else None

    def list_sessions(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            if tenant_id is None:
                rows = connection.execute(
                    "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM sessions
                    WHERE tenant_id=? OR tenant_id IS NULL
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (tenant_id, limit),
                ).fetchall()
        return [self._session(row) for row in rows]

    def end_session(
        self, session_id: str, ended_at: str, tenant_id: str | None = None
    ) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            if tenant_id is None:
                connection.execute(
                    "UPDATE sessions SET status='ended', ended_at=? WHERE id=?",
                    (ended_at, session_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE sessions SET status='ended', ended_at=?
                    WHERE id=? AND (tenant_id=? OR tenant_id IS NULL)
                    """,
                    (ended_at, session_id, tenant_id),
                )
        return self.get_session(session_id, tenant_id)

    def get_idempotent_event(self, session_id: str, key: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                """
                SELECT e.* FROM idempotency i JOIN events e
                ON e.id=i.event_id WHERE i.session_id=? AND i.idempotency_key=?
                """,
                (session_id, key),
            ).fetchone()
        return self._event(row) if row else None

    def append_event(
        self,
        event_id: str,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
        timestamp: str,
        sequence: int,
        previous_hash: str,
        hash_: str,
        idempotency_key: str | None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:

        serialized = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        content_hash = hashlib.sha256(serialized).hexdigest()
        stored_payload: dict[str, Any] = payload
        object_ref: dict[str, Any] | None = None
        if len(serialized) > self.large_payload_threshold and self.object_store is not None:
            object_ref = self.object_store.put(content_hash, serialized)
            stored_payload = {
                "_agentblackbox_object": "v1",
                "sha256": content_hash,
                "size": len(serialized),
                "adapter": object_ref.get("adapter", "unknown"),
                "key": object_ref["key"],
            }
        if self.payload_encryptor is not None:
            stored_payload = self.payload_encryptor.encrypt(stored_payload)
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO events(id,tenant_id,session_id,sequence,event_type,payload,
                                   payload_content_hash,previous_hash,hash,timestamp)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    tenant_id,
                    session_id,
                    sequence,
                    event_type,
                    json.dumps(stored_payload),
                    content_hash,
                    previous_hash,
                    hash_,
                    timestamp,
                ),
            )
            if idempotency_key:
                connection.execute(
                    "INSERT INTO idempotency(session_id,idempotency_key,event_id) VALUES(?,?,?)",
                    (session_id, idempotency_key, event_id),
                )
        return self.get_event(session_id, event_id)

    def list_events(
        self, session_id: str, limit: int = 1000, tenant_id: str | None = None
    ) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            if tenant_id is None:
                rows = connection.execute(
                    "SELECT * FROM events WHERE session_id=? ORDER BY sequence LIMIT ?",
                    (session_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM events
                    WHERE session_id=? AND (tenant_id=? OR tenant_id IS NULL)
                    ORDER BY sequence LIMIT ?
                    """,
                    (session_id, tenant_id, limit),
                ).fetchall()
        return [self._event(row) for row in rows]

    def get_event(self, session_id: str, event_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE session_id=? AND id=?", (session_id, event_id)
            ).fetchone()
        return self._event(row) if row else None

    def head(self, session_id: str) -> tuple[str, int]:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                """
                SELECT hash,sequence FROM events
                WHERE session_id=? ORDER BY sequence DESC LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        return (row["hash"], row["sequence"] + 1) if row else ("0" * 64, 0)

    def create_test_case(
        self,
        test_case_id: str,
        name: str,
        session_id: str,
        metadata: dict[str, Any],
        baseline_events: list[dict[str, Any]],
        created_at: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO test_cases(id,name,session_id,metadata,baseline_events,created_at)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    test_case_id,
                    name,
                    session_id,
                    json.dumps(metadata),
                    json.dumps(baseline_events),
                    created_at,
                ),
            )
        return self.get_test_case(test_case_id)

    def get_test_case(self, test_case_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM test_cases WHERE id=?", (test_case_id,)
            ).fetchone()
        return self._test_case(row) if row else None

    def list_test_cases(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_cases ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._test_case(row) for row in rows]

    def create_test_run(
        self,
        test_run_id: str,
        test_case_id: str,
        candidate_events: list[dict[str, Any]],
        diff: list[dict[str, Any]],
        status: str,
        violations: list[dict[str, Any]],
        created_at: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO test_runs(
                    id,test_case_id,candidate_events,diff,status,violations,created_at
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    test_run_id,
                    test_case_id,
                    json.dumps(candidate_events),
                    json.dumps(diff),
                    status,
                    json.dumps(violations),
                    created_at,
                ),
            )
        return self.get_test_run(test_run_id)

    def get_test_run(self, test_run_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM test_runs WHERE id=?", (test_run_id,)
            ).fetchone()
        return self._test_run(row) if row else None

    def list_test_runs(self, test_case_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM test_runs WHERE test_case_id=? ORDER BY created_at DESC LIMIT ?
                """,
                (test_case_id, limit),
            ).fetchall()
        return [self._test_run(row) for row in rows]

    def create_test_suite(
        self, suite_id: str, name: str, test_case_ids: list[str],
        metadata: dict[str, Any], tenant_id: str, created_at: str,
    ) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO test_suites(
                   id,tenant_id,name,test_case_ids,metadata,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    suite_id, tenant_id, name, json.dumps(test_case_ids),
                    json.dumps(metadata), created_at,
                ),
            )
        return self.get_test_suite(suite_id)

    def get_test_suite(self, suite_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute("SELECT * FROM test_suites WHERE id=?", (suite_id,)).fetchone()
        return self._test_suite(row) if row else None

    def list_test_suites(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_suites WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [self._test_suite(row) for row in rows]

    def create_test_suite_run(self, suite_run_id: str, suite_id: str, test_run_ids: list[str],
                              status: str, summary: dict[str, Any], tenant_id: str,
                              created_at: str) -> dict[str, Any]:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO test_suite_runs(
                   id,tenant_id,suite_id,test_run_ids,status,summary,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (suite_run_id, tenant_id, suite_id, json.dumps(test_run_ids),
                 status, json.dumps(summary), created_at),
            )
        return self.get_test_suite_run(suite_run_id)

    def get_test_suite_run(self, suite_run_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM test_suite_runs WHERE id=?", (suite_run_id,)
            ).fetchone()
        return self._test_suite_run(row) if row else None

    def list_test_suite_runs(self, suite_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_suite_runs WHERE suite_id=? ORDER BY created_at DESC LIMIT ?",
                (suite_id, limit),
            ).fetchall()
        return [self._test_suite_run(row) for row in rows]

    def update_test_case_baseline(self, test_case_id: str,
                                  baseline_events: list[dict[str, Any]]) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            connection.execute(
                "UPDATE test_cases SET baseline_events=? WHERE id=?",
                (json.dumps(baseline_events), test_case_id),
            )
        return self.get_test_case(test_case_id)

    def approve_test_run(self, test_run_id: str, approved_by: str,
                         approved_at: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            connection.execute(
                "UPDATE test_runs SET approved_at=?,approved_by=? WHERE id=?",
                (approved_at, approved_by, test_run_id),
            )
            row = connection.execute(
                "SELECT * FROM test_runs WHERE id=?", (test_run_id,)
            ).fetchone()
        run = self._test_run(row) if row else None
        if run:
            self.update_test_case_baseline(run["test_case_id"], run["candidate_events"])
        return run

    @staticmethod
    def _session(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "metadata": json.loads(row["metadata"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "ended_at": row["ended_at"],
        }

    def _event(self, row: sqlite3.Row) -> dict[str, Any]:
        payload_raw = json.loads(row["payload"])
        if row["payload_purged"]:
            payload = {"purged": True, "payload_hash": row["payload_content_hash"]}
        elif (
            isinstance(payload_raw, dict)
            and payload_raw.get("_agentblackbox_envelope") == "v1"
            and self.payload_encryptor is not None
        ):
            payload = self.payload_encryptor.decrypt(payload_raw)
        else:
            payload = payload_raw
        if isinstance(payload, dict) and payload.get("_agentblackbox_object") == "v1":
            if self.object_store is None:
                payload = {
                    "_agentblackbox_object": "v1",
                    "unavailable": True,
                    "sha256": payload["sha256"],
                }
            else:
                try:
                    content = self.object_store.get(payload["key"])
                    if hashlib.sha256(content).hexdigest() != payload["sha256"]:
                        raise ValueError("Object content hash mismatch")
                    payload = json.loads(content.decode("utf-8"))
                except Exception:
                    payload = {
                        "_agentblackbox_object": "v1",
                        "unavailable": True,
                        "sha256": payload["sha256"],
                    }
        return {
            "id": row["id"],
            "session_id": row["session_id"],
            "sequence": row["sequence"],
            "event_type": row["event_type"],
            "payload": payload,
            "payload_purged": bool(row["payload_purged"]),
            "payload_purged_at": row["payload_purged_at"],
            "payload_content_hash": row["payload_content_hash"],
            "previous_hash": row["previous_hash"],
            "hash": row["hash"],
            "timestamp": row["timestamp"],
        }

    @staticmethod
    def _test_case(row: sqlite3.Row) -> dict[str, Any]:
        try:
            suite_id = row["suite_id"]
        except (IndexError, KeyError):
            suite_id = None
        return {
            "id": row["id"],
            "name": row["name"],
            "session_id": row["session_id"],
            "metadata": json.loads(row["metadata"]),
            "baseline_events": json.loads(row["baseline_events"]),
            "created_at": row["created_at"],
            "suite_id": suite_id,
        }

    @staticmethod
    def _test_run(row: sqlite3.Row) -> dict[str, Any]:
        try:
            approved_at = row["approved_at"]
            approved_by = row["approved_by"]
        except (IndexError, KeyError):
            approved_at = None
            approved_by = None
        return {
            "id": row["id"],
            "test_case_id": row["test_case_id"],
            "candidate_events": json.loads(row["candidate_events"]),
            "diff": json.loads(row["diff"]),
            "status": row["status"],
            "violations": json.loads(row["violations"]),
            "created_at": row["created_at"],
            "approved_at": approved_at,
            "approved_by": approved_by,
        }

    @staticmethod
    def _test_suite(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "name": row["name"],
            "test_case_ids": json.loads(row["test_case_ids"]),
            "metadata": json.loads(row["metadata"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _test_suite_run(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "tenant_id": row["tenant_id"],
            "suite_id": row["suite_id"],
            "test_run_ids": json.loads(row["test_run_ids"]),
            "status": row["status"],
            "summary": json.loads(row["summary"]),
            "created_at": row["created_at"],
        }
