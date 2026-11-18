# PostgreSQL least-privilege roles

Run migrations as a migration owner that is separate from runtime application
credentials.

```sql
CREATE ROLE agentblackbox_migrate LOGIN;
CREATE ROLE agentblackbox_app LOGIN;

GRANT CONNECT ON DATABASE agentblackbox TO agentblackbox_app;
GRANT USAGE ON SCHEMA public TO agentblackbox_app;
GRANT SELECT, INSERT, UPDATE ON tenants, api_keys, sessions, audit_log TO agentblackbox_app;
GRANT SELECT, INSERT ON events TO agentblackbox_app;

-- api_keys revocation uses UPDATE; sessions lifecycle uses UPDATE.
-- Events must never be updated or deleted at the application role boundary.
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM agentblackbox_app;

-- Set per request before issuing tenant-scoped queries.
-- Example: SELECT set_config('app.tenant_id', '<uuid>', true);
```

The runtime role is never the table owner. It must not own migration functions,
RLS policies, or the event event-trigger. Keep migration and DBA credentials
outside application deployments. A real secret manager/KMS is required for
the API-key pepper in production; this repository supplies configuration and
does not emulate a KMS.
