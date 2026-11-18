# Security

## Supported guarantees

- Canonical JSON gives a repeatable byte representation for supported values,
  normalizes Unicode to NFC, rejects lone surrogates/non-finite floats, and
  stringifies integers outside the JavaScript safe range.
- Hash-chain verification detects changed payloads, sequences, previous links,
  context fields, or chain heads within the supplied entries. Version 1 uses
  domain-separated length-prefixed fields.
- Merkle proof verification detects changed leaves or roots for the documented
  proof format.
- Policy expressions execute without `eval` and do not allow calls, indexing,
  imports, or arbitrary attributes.
- The local API redacts common PII and refuses the known development API key
  when `ENV=production`.

## Not supported yet

The bounded MVP does not yet provide KMS/HSM signing, signed checkpoints,
independent external anchors, PostgreSQL FORCE RLS, scoped/hashed API keys,
MFA, TLS termination, envelope encryption, sandboxed candidate execution,
or production rate limiting. Optional Ed25519 bundle signing is not a
replacement for managed key custody. Hash chains cannot prove events omitted
before ingestion.

## Identity and webhook foundations

Argon2id password hashing is available only when the optional `argon2-cffi`
dependency is installed. If it is absent, password operations fail explicitly
rather than silently using an insecure alternative. Roles are deny-by-default:
`owner`, `admin`, `analyst`, `auditor_readonly`, and `service`.

Session-cookie and OIDC providers are interfaces only. TOTP and WebAuthn
enrollment/verification interfaces are extension points; no enrollment,
challenge, attestation, or recovery ceremony is implemented here and they must
not be treated as production MFA.

Administrative audit entries are chained with SHA-256 hashes and expose a
verification result. Webhook deliveries use HMAC-SHA256 with timestamp/replay
headers and reject HTTPS targets that resolve to private, loopback, link-local,
multicast, reserved, or metadata addresses. Redirect responses are rejected.

## Reporting

Report suspected security defects privately to the repository maintainers.
Do not include secrets or live customer data in reports.
