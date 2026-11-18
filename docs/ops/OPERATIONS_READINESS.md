# Operations readiness go/no-go checklist

Use this as an evidence gate. It is not a production certification. Helm rendering or a passing CI
job is not evidence of cluster availability, a cloud apply, or a successful restore.

## Reliability

- [ ] Approved availability/error-budget targets and measured SLO coverage.
- [ ] Capacity and failure tests for API, web, workers, database, storage, and migrations.
- [ ] Replica, anti-affinity, PDB, node-disruption, upgrade, and rollback behavior tested.
- [ ] `/health`, `/ready`, startup/liveness/readiness, hook failure, and recovery verified.
- [ ] Migration rollback and data compatibility procedures are reversible.

## Security

- [ ] Immutable image digests and image/signature/dependency scanning policy.
- [ ] Non-root, read-only root, dropped capabilities, seccomp, NetworkPolicy, and RBAC enforced.
- [ ] Production secrets externalized and rotated; default keys/peppers/API keys absent.
- [ ] TLS, ingress, identity/RBAC, KMS/HSM, audit, and vulnerability controls verified.
- [ ] Threat model, pentest scope, SBOM, and incident procedures are current.

## Backups and disaster recovery

- [ ] RPO/RTO approved for data, configuration, policies, keys, and audit evidence.
- [ ] Encrypted off-cluster, immutable backup retention and scheduling verified.
- [ ] Restore drills prove application/key/database compatibility and record RTO.
- [ ] Cross-region or alternate-cluster plans tested if required.
- [ ] Destructive runbooks preserve evidence and require named approvers.

## Observability

- [ ] Metrics, structured logs, traces, correlation IDs, retention, and dashboards configured.
- [ ] Alerts route to staffed primary/secondary on-call with escalation and test notifications.
- [ ] Pod restarts, PVC, database saturation, migration, API, and worker failures alert.
- [ ] Synthetic checks cover authentication, ingestion, replay, readiness, and upgrade.

## On-call

- [ ] Named primary and secondary responders for every covered schedule.
- [ ] Escalation contacts and incident authority published and reachable.
- [ ] Runbooks cover install, upgrade, rollback, restore, security, and dependency outage.
- [ ] Paging tested; incident communications and postmortem ownership documented.

## Cost

- [ ] Requests/limits and autoscaling boundaries match measured capacity.
- [ ] Cluster, storage, backup, logs/traces, database, KMS, and egress budgets/alerts exist.
- [ ] Test clusters, PVCs, images, and orphaned records have cleanup ownership.

## External dependencies

- [ ] Registry, DNS/TLS, ingress, storage classes, PostgreSQL, object store, and KMS have owners,
  credentials, outage plans, and support paths.
- [ ] OIDC, SIEM, webhook, signing, transparency, and customer integrations verified.
- [ ] Licenses, allow-lists, CA/trust, clock, network, and certificate rotation confirmed.

## Decision

**GO** only when all applicable evidence exists, exceptions have named approvers and expiry,
restore/rollback were exercised, and paging is proven. Otherwise: **NO-GO**.
Record approver, date, environment, evidence links, exceptions, and next review.
