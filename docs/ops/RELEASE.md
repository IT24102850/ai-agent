# Release guide

1. Ensure a clean git state and run `make check`.
2. Run `make web-build`.
3. Run `docker compose config` and `make release-dry-run`.
4. Verify `/health`, `/ready`, and `/metrics` from the local stack.
5. Record image digests and the git commit when publishing externally.

No registry, signing, promotion environment, or rollback platform is configured.

## Level 2 AWS dry-run

1. Run `python scripts/preflight.py`.
2. Fill one environment tfvars with an immutable ECR image digest and unique bucket name.
3. Configure an approved Terraform backend before `init`; never commit credentials.
4. Run `terraform -chdir=infra fmt -check -recursive`.
5. Run `terraform -chdir=infra init -backend=false` and `validate` for offline validation.
6. With authorized AWS credentials and an isolated backend, run a plan; do not apply.
7. Run `python scripts/release_dry_run.py` for local image/build validation.

A successful plan is not an apply. No cloud action is performed by repository scripts.
