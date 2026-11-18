# Payload Encryption, Key Management, and Retention

## Application payload envelopes

AgentBlackbox encrypts event payload JSON before it is written to SQLite or
PostgreSQL-compatible persistence. The stored value is an application envelope:

```json
{
  "_agentblackbox_envelope": "v1",
  "kid": "key-id",
  "nonce": "base64",
  "ciphertext": "base64"
}
```

Encryption is AES-256-GCM. The payload hash and hash chain continue to use the
redacted plaintext payload semantics, so integrity verification is not weakened
by encryption.

The `KeyProvider` interface exposes `active_key`, `encrypt_data_key`, and
`decrypt_data_key`. `LocalDevelopmentKeyProvider` is available only for local
development and tests. Set `AGENTBLACKBOX_PAYLOAD_KEY` to a stable local key;
without it, the bounded service uses a fixed development-only key.

## Production key management

Production requires `ENV=production`, `AGENTBLACKBOX_API_KEY`,
`AGENTBLACKBOX_API_KEY_PEPPER`, and `AGENTBLACKBOX_KMS_KEY_ID`. The service
must be supplied a real `KeyProvider` implementation (not the local provider)
by the application factory. The built-in `ProductionKMSRequired` provider
fails closed: payload encryption and ingestion raise a key-provider error
unless a configured external KMS provider is injected.

No hosted KMS or cloud credential integration is silently approximated. KMS
key rotation, external secret escrow, and provider-specific permissions remain
deployment responsibilities. Never place production key material in SQLite,
event metadata, exports, or source control.

## Large payload object storage

Payloads above `AGENTBLACKBOX_LARGE_PAYLOAD_THRESHOLD` (1 MiB by default) are
stored through the object-storage interface. The object adapter receives the
serialized content, verifies the SHA-256 content hash on read, and the database
retains only an object reference and hash. `LocalFilesystemObjectStore` is the
safe local adapter.

The `MinioCompatibleObjectStore` name is currently a local-compatible interface
placeholder. It does not perform network requests or claim an S3/MinIO
container integration. Deployments requiring hosted object storage must supply
and verify an implementation that authenticates to their object store.

## Retention and purge

Tenants have a `retention_days` setting. Use:

```text
PUT /v1/admin/tenants/{tenant_id}/retention
{"retention_days":30}

POST /v1/admin/tenants/{tenant_id}/purge
```

Purge replaces payload content with `{"purged": true}` and sets
`payload_purged=true` and `payload_purged_at`. It does not alter the event
sequence, previous hash, or stored verification hash. The repository primitive
`purge_expired_payloads(now)` purges events older than each tenant's configured
retention period.

Purge is destructive. Backups, exports, object-store retention, and audit
archive lifecycle policies must be managed separately.
