# Operations readiness

## Level 1 status

This repository has a runnable local Docker stack, health/readiness/Prometheus-style metrics endpoints,
CI validation, local load tooling, and operations runbooks. It is **not** a production deployment
readiness claim.

## Implemented

- API, SQLite-backed local persistence, web console, PostgreSQL image, and MinIO image via Docker Compose
- API `/health`, `/ready`, and `/metrics`
- Least-privilege GitHub Actions and dependency scan commands
- Pinned Python 3.12, Node 20, and Docker Compose development toolchain
- Local SLO guidance and alert rule examples
- AWS ECS/Fargate reference Terraform scaffold for environment-separated VPC, private subnets,
  RDS PostgreSQL, S3 Object Lock/versioning, KMS, Secrets Manager, IAM, CloudWatch, and budgets
- `/version` endpoint, API probes, metrics, preflight and release-dry-run scripts

## Deferred

- External cloud hosting and DNS/TLS
- Managed PostgreSQL and backup automation
- KMS/HSM and external secret delivery
- Kubernetes manifests and autoscaling
- Real alerting, paging, and incident integration
- Multi-region disaster recovery
