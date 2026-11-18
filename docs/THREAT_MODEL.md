# AgentBlackbox Threat Model

## Scope

This repository is the foundation for a tamper-evident audit trail for agent
actions. The pure-logic package currently provides deterministic serialization,
SHA-256 hash chains, Merkle proofs, structured diffs, and a restricted policy
expression evaluator. A network service, durable storage, identity system, and
key management are intentionally out of scope for this slice.

## Assets

- **Audit payloads:** prompts, tool calls, tool results, approvals, and replay
  metadata may contain secrets or personal data.
- **Integrity metadata:** sequence numbers, hashes, Merkle roots, and inclusion
  proofs establish the relationship among events.
- **Policy decisions:** policy evaluation results and the rules that produced
  them must be reproducible.

## Trust boundaries

1. **Application boundary:** callers submit Python values that become audit
   records. The core validates JSON types and rejects non-finite floats.
2. **Process boundary:** payloads and policy expressions execute without a
   network or database. Policy expressions run through an allow-listed AST
   interpreter; they must never use Python `eval`.
3. **Storage boundary:** hash verification is local and does not authenticate
   the integrity of the storage system. External storage must provide its own
   access control and availability guarantees.
4. **External verification boundary:** a verifier needs the canonical payload
   bytes and trusted genesis parameters or a trusted signed checkpoint.

## Threats and mitigations

| Threat | Mitigation in this slice | Remaining work |
|---|---|---|
| Payload alteration | NFC canonical JSON, versioned length-prefixed SHA-256 chain and Merkle digests | Signed checkpoints and immutable storage |
| Chain reordering or deletion | Sequence and `previous_hash` verification | Anchoring and append-only storage |
| Ambiguous serialization | Stable key/value ordering, NFC, surrogate rejection, safe integer handling, and published vectors | Format-version interoperability tests |
| Hash algorithm ambiguity | Domain-separated Merkle leaves/nodes; documented chain format | Algorithm registry and signed manifests |
| Policy code execution | AST allow-list and no attribute calls | Sandboxed policy service and rule signing |
| Malicious large inputs | Callers impose process/resource limits | Streaming, size limits, quotas |
| Data leakage in logs | Core APIs avoid logging payload values | Redaction service and retention controls |
| Replay without provenance | Replay guarantees documented by deterministic normalization | Captured runtime context and dependencies |

## Assumptions

- SHA-256 and canonical JSON are sufficient for detecting accidental or
  non-adversarial modification, but are not a substitute for signatures.
- Python dictionaries and lists supplied by callers are treated as untrusted
  until canonicalized and hashed.
- Proof verification is about inclusion; it does not prove that an external
  observer trusts or recognizes the Merkle root.

## Residual risks

- A fully compromised application/database can rewrite a complete chain unless
  external signed checkpoints and independent anchors are enabled.
- Events omitted or altered before they reach the recorder are not provable.
- The local MVP has no KMS, PostgreSQL FORCE RLS, MFA, external anchoring, or
  network sandbox; it must not store production customer data.
- Redaction reduces exposure but cannot recognize every secret or infer context.

Every new control must have a regression test before it is treated as active.

## Out of scope

- KMS/HSM custody, external witnesses, production identity/MFA, encrypted
  storage, transport termination, and production availability controls.
