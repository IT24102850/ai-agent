# Architecture

## Current scope

The `agentblackbox` package is a dependency-free Python core with six modules:

- `canonical`: strict JSON-compatible canonicalization and SHA-256 helpers
- `hashchain`: ordered, linked audit entries
- `merkle`: domain-separated leaf and node hashes plus inclusion proofs
- `diff`: deterministic recursive structured changes
- `policy`: allow-listed AST policy expression evaluation

## Hash formats

Canonical JSON uses sorted keys, UTF-8, no escaped Unicode, comma separation,
no insignificant whitespace, and rejection of NaN/infinity.

Hash-chain entries have a sequence number, canonical payload, previous hash,
and chain hash. The genesis hash is 64 ASCII zeroes by default. Payload and
metadata are canonicalized before hashing.

Merkle leaves are `SHA256(0x00 || canonical_json(value))`. Internal nodes are
`SHA256(0x01 || left_raw || right_raw)`. An unmatched right edge is duplicated.

## Extension boundaries

A future service should add storage, signatures, API validation, retention,
access control, and a workflow runtime around these primitives. It must not
silently replace canonicalization or hash formats.

## Phase 2/3 slice

`api/app` provides a local FastAPI slice backed by SQLite. Sessions and events
use the core `entry_hash` format. Idempotency is unique per session and key.
PII redaction is applied before persistence. The repository class is the
database boundary for a future PostgreSQL implementation.

`sdk-python/agentblackbox_sdk` provides recording and replay. Recording uses a
bounded background queue and remains fail-safe if the service is unavailable.
Replay mode only returns captured tool results and raises
`ReplayGuardError` for uncaptured calls. This is not a complete workflow
runtime or sandbox.
