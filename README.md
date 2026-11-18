# AgentBlackbox

AgentBlackbox is a local-first foundation for tamper-evident AI agent audit
trails. This first slice provides deterministic canonical JSON, SHA-256 hash
chains, Merkle roots and proofs, structured diffs, and a restricted policy
expression evaluator. It is a library foundation, not a complete hosted SaaS.

## Install

```bash
python -m pip install -e ".[dev]"
```

## Run

```bash
python -m agentblackbox
python -m pytest
make check
```

## Core example

```python
from agentblackbox import create_chain, merkle_root, verify_chain

chain = create_chain([{"event": "started"}, {"event": "completed"}])
assert verify_chain(chain)
print(chain[-1].hash)
print(merkle_root([entry.to_dict() for entry in chain]))
```

## Repository scope

The core is now accompanied by a bounded FastAPI service and a pure-Python SDK.
Local SQLite persistence, API-key auth, idempotency, PII redaction, and hash-chain
verification are implemented. Enterprise signing, external identity, tenancy,
retention policy, and hosted durability are not; PostgreSQL and secret/KMS
integrations remain explicit extension points.

## HTTP service

```bash
python -m pip install -e ".[dev]"
python -m uvicorn api.app.main:app --reload
```

Set `AGENTBLACKBOX_API_KEY` and optionally
`AGENTBLACKBOX_DATABASE_URL=sqlite:///./agentblackbox.db`.

### Production persistence and tenant administration

PostgreSQL is supported through SQLAlchemy 2 async and Alembic:

```bash
AGENTBLACKBOX_DATABASE_URL=postgresql://app:password@localhost/agentblackbox
AGENTBLACKBOX_API_KEY_PEPPER=<secret-manager-value>
alembic upgrade head
```

The migration enables tenant RLS, append-only event protections, and unique
session sequences. SQLite remains supported for local tests and development.
PostgreSQL integration tests are skipped unless
`AGENTBLACKBOX_TEST_POSTGRES_URL` is configured.

Tenant and API-key routes derive tenant identity from the authenticated
principal, not request body fields:

```text
POST /v1/admin/tenants
POST /v1/admin/api-keys
POST /v1/admin/api-keys/{id}/rotate
POST /v1/admin/api-keys/{id}/revoke
GET  /v1/admin/api-keys
```

Creation and rotation return the raw key once. Listings and subsequent reads
return only a prefix and HMAC-derived record metadata. Scopes are `ingest`,
`read`, and `admin`, declared as OpenAPI `x-agentblackbox-permissions` metadata.

Payload envelopes, local key management, production fail-closed behavior,
large-payload object storage, and per-tenant purge behavior are documented in
[Payload Encryption, Key Management, and Retention](docs/ENCRYPTION_RETENTION.md).

## Replay and regression slice

```python
from agentblackbox_sdk import Recorder, ReplayDivergence, tool

replay = Recorder(replay=True, recorded_events=events)

@tool(recorder=replay, name="lookup")
def lookup(customer_id):
    raise AssertionError("real tool must not execute")

assert lookup("customer-123") is not None
```

Replay serves exact recorded tool results. It raises `ReplayDivergence` for an
missing result or mismatched arguments; set `collect_replay_divergences=True`
to collect divergences instead. Replay never executes a real tool.

Test cases snapshot a session's event sequence. Create and run them with the
API:

```text
POST /v1/test-cases
{"session_id":"<session-id>","name":"refund baseline"}

POST /v1/test-cases/<test-case-id>/runs
{"candidate_events":[{"event_type":"decision","payload":{"action":"refund","amount":600}}]}

GET /v1/test-cases
GET /v1/test-cases/<test-case-id>/runs
```

Policy packs are safe YAML mappings/lists validated with `yaml.safe_load`.
Expressions use an AST allow-list and never call `eval`, `exec`, Python
functions, or arbitrary attributes. The built-in customer-support refund pack
contains six policies.

```text
GET  /v1/policies
POST /v1/policies/evaluate
{"context":{"action":"refund","amount":600,"approved":false}}
```

Matching policies are attached as `policy.violation` events during session
ingestion, and test runs include policy violations alongside structured diffs.

CLI:

```bash
python -m agentblackbox --list-policies
python -m agentblackbox --list-policies --policy-pack ./policy.yaml
```

## Current boundaries

The bounded product slice includes portable JSON exports, chain/Merkle verification,
deterministic audit reports, an optional Ed25519 signer, an optional PDF renderer,
editable SDK/CLI suites, suite and run APIs, approval baselines, JUnit/JSON output,
and a functional Next.js console. Remaining enterprise integrations are explicitly:

- hosted SIEM/SOAR/webhook delivery at organization scale;
- SAML/OIDC/SCIM external identity and lifecycle management;
- managed global tenancy, policy federation, and cross-region replication;
- hosted immutable anchoring and external trust registries;
- production HSM/KMS, key escrow, and disaster recovery automation;
- distributed PostgreSQL worker fleets and horizontal replay orchestration;
- enterprise retention/legal-hold workflows and automated evidence archival.

## Export, verify, and reports

```bash
# Export and report endpoints
curl -H "X-API-Key: $AGENTBLACKBOX_API_KEY" \
  http://localhost:8000/v1/sessions/<session-id>/export
curl -H "X-API-Key: $AGENTBLACKBOX_API_KEY" \
  http://localhost:8000/v1/sessions/<session-id>/audit-report

# Standalone verification (no API or database required)
python -m agentblackbox verify exported-bundle.json
python -m agentblackbox verify exported-bundle.json \
  --public-key 0123... \
  --report audit-report.json

# Optional dependencies
python -m pip install -e ".[signing]"
python -m pip install -e ".[pdf]"
```

Ed25519 signatures are only available when `cryptography` is installed.
Verification reports unsigned bundles honestly and never treats signing as
automatic. PDF rendering explicitly fails with `PdfUnavailableError` unless
WeasyPrint is installed.

## Offline demo

```bash
python examples/refund_agent_demo.py --output examples/output
make refund-demo
make verify BUNDLE=examples/output/bundle.json
```

The demo uses local chain/Merkle primitives only; it does not call or emulate a
hosted model or external payment service.

## Web MVP

```bash
cd web
cp .env.example .env.local
npm install
npm run dev
```

Set `NEXT_PUBLIC_API_BASE_URL` to the API origin. The scaffold provides sessions,
timeline, policies, and reports placeholders and is not a production UI.

## Local DevOps Level 1

```bash
make doctor
make up
make migrate
make loadtest
make down
```

The Compose stack runs the API, web console, PostgreSQL image, and MinIO image.
Only the API and web console are currently integrated with application code; PostgreSQL
and MinIO remain local fixtures. Available operations targets include `up`, `down`,
`migrate`, `loadtest`, `docs`, `release-dry-run`, and `doctor`.

See [OPERATIONS_READINESS.md](OPERATIONS_READINESS.md) and [docs/ops/runbook-index.md](docs/ops/runbook-index.md).
Cloud hosting, managed PostgreSQL, KMS, Kubernetes, and real alerting are deferred.
