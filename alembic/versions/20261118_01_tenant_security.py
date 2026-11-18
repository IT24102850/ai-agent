"""Add tenant and API-key security foundation."""

from alembic import op

revision = "20261118_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE tenants (
      id VARCHAR(36) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      created_at VARCHAR(64) NOT NULL,
      retention_days INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE api_keys (
      id VARCHAR(36) PRIMARY KEY,
      tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id),
      name VARCHAR(255) NOT NULL,
      key_prefix VARCHAR(12) NOT NULL,
      key_hash VARCHAR(64) NOT NULL UNIQUE,
      scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
      expires_at VARCHAR(64),
      revoked_at VARCHAR(64),
      created_at VARCHAR(64) NOT NULL
    );
    CREATE TABLE sessions (
      id VARCHAR(36) PRIMARY KEY,
      tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id),
      name VARCHAR(255),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      created_at VARCHAR(64) NOT NULL,
      ended_at VARCHAR(64)
    );
    CREATE TABLE events (
      id VARCHAR(36) PRIMARY KEY,
      tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id),
      session_id VARCHAR(36) NOT NULL REFERENCES sessions(id),
      sequence INTEGER NOT NULL,
      event_type VARCHAR(100) NOT NULL,
      payload JSONB NOT NULL,
      payload_purged BOOLEAN NOT NULL DEFAULT FALSE,
      payload_purged_at VARCHAR(64),
      payload_content_hash VARCHAR(64),
      previous_hash VARCHAR(64) NOT NULL,
      hash VARCHAR(64) NOT NULL,
      timestamp VARCHAR(64) NOT NULL,
      UNIQUE (tenant_id, session_id, sequence)
    );
    CREATE TABLE audit_log (
      id VARCHAR(36) PRIMARY KEY,
      tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id),
      actor_key_id VARCHAR(36),
      action VARCHAR(100) NOT NULL,
      target_type VARCHAR(100),
      target_id VARCHAR(36),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at VARCHAR(64) NOT NULL
    );

    ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
    ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
    ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
    ALTER TABLE events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE events FORCE ROW LEVEL SECURITY;
    ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
    ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

    CREATE POLICY api_keys_tenant_isolation ON api_keys
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar);
    CREATE POLICY sessions_tenant_isolation ON sessions
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar);
    CREATE POLICY events_tenant_isolation ON events
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar);
    CREATE POLICY audit_tenant_isolation ON audit_log
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::varchar);

    CREATE FUNCTION agentblackbox_append_only_events() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'agentblackbox events are append-only';
    END;
    $$;
    CREATE TRIGGER events_no_update BEFORE UPDATE ON events
      FOR EACH ROW EXECUTE FUNCTION agentblackbox_append_only_events();
    CREATE TRIGGER events_no_delete BEFORE DELETE ON events
      FOR EACH ROW EXECUTE FUNCTION agentblackbox_append_only_events();

    CREATE FUNCTION agentblackbox_no_event_truncate() RETURNS event_trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'TRUNCATE events is forbidden';
    END;
    $$;
    CREATE EVENT TRIGGER agentblackbox_no_truncate
      ON ddl_command_start
      WHEN TAG IN ('TRUNCATE')
      EXECUTE FUNCTION agentblackbox_no_event_truncate();
    """)


def downgrade() -> None:
    op.execute("""
    DROP EVENT TRIGGER IF EXISTS agentblackbox_no_truncate;
    DROP TABLE IF EXISTS audit_log, events, sessions, api_keys, tenants CASCADE;
    DROP FUNCTION IF EXISTS agentblackbox_append_only_events();
    DROP FUNCTION IF EXISTS agentblackbox_no_event_truncate();
    """)
