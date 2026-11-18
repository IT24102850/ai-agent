# Architecture Decisions

## Python first

Python 3.10+ is the initial implementation target because it is widely available
and supports clear data structures and tests.

## Pure core

The core has no runtime dependencies. Cryptography and serialization primitives
are implemented from the standard library to keep the initial foundation easy
to audit and run locally.

## Canonical JSON

Sorted keys and compact UTF-8 JSON provide deterministic representation. Integer
and floating-point semantics follow Python JSON where possible; non-finite
floats are rejected.

## SHA-256

SHA-256 is used for this prototype. Hash-chain and Merkle formats should be
versioned or signed before interoperability commitments are made.

## Safe policy evaluation

Policies use a parsed, allow-listed subset of Python expressions instead of
`eval`. Calls, subscriptions, imports, and arbitrary attributes are forbidden.
This is a primitive; production policy engines should also provide rule
versioning, signing, resource limits, and authorization.

## PostgreSQL and row-level isolation

PostgreSQL deployments use SQLAlchemy 2 async (`asyncpg`) with Alembic migrations.
SQLite remains the bounded local/unit-test repository and is not treated as a
PostgreSQL substitute. Tenant access uses `app.tenant_id` plus FORCE ROW LEVEL
SECURITY. Events are append-only and sessions have unique tenant/session/sequence
identity. API-key peers are scoped by tenant and permission.

## API-key storage

Raw API keys exist only in creation/rotation responses and are never persisted.
Only HMAC-SHA256 digest, prefix, expiry, scope, and revocation metadata are
stored. The HMAC pepper must come from environment/secret management in production.

## ECS/Fargate on AWS

AWS ECS on Fargate is the initial reference platform. It is proportionate for a small
containerized service: no control-plane administration, private task networking,
managed compute capacity, and direct integration with RDS, Secrets Manager, CloudWatch,
ECR, IAM, and KMS. EKS is deferred because cluster operations, add-ons, node or Fargate
profiles, and Kubernetes policy tooling add operational burden not justified at Level 2.
