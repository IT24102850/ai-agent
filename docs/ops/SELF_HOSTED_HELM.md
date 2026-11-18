# Self-hosted Helm install, upgrade, and backup

This chart requires Kubernetes 1.25+ and Helm 3. It is a deployment starting point; storage,
PostgreSQL/object/KMS integrations, DNS, TLS, ingress, secrets, and backup infrastructure remain
operator responsibilities. No repository script creates a cluster or deploys the chart.

## Preflight

```bash
python scripts/preflight.py
helm lint charts/agentblackbox
helm template agentblackbox charts/agentblackbox \
  -f charts/agentblackbox/values-standard.yaml
```

Missing `helm`, `kind`, or `kubectl` is reported honestly as skipped. CI and preflight scripts do
not install Helm charts, create kind clusters, run cloud applies, or modify a live cluster.

## Optional kind validation

With Docker, kind, kubectl, and Helm already installed and local authorization granted:

```bash
kind create cluster --name agentblackbox
kubectl cluster-info
helm upgrade --install agentblackbox ./charts/agentblackbox \
  --namespace agentblackbox --create-namespace \
  -f ./charts/agentblackbox/values-small.yaml
kubectl -n agentblackbox get pods,svc
kind delete cluster --name agentblackbox
```

These are explicit operator commands, not CI steps.

## Install and upgrade

Create the runtime secret outside source control:

```bash
kubectl -n agentblackbox create secret generic agentblackbox-runtime \
  --from-literal=AGENTBLACKBOX_API_KEY='replace-me' \
  --from-literal=AGENTBLACKBOX_API_KEY_PEPPER='replace-me'
```

Use a profile and pin reviewed image tags/digests for promotion:

```bash
helm upgrade --install agentblackbox ./charts/agentblackbox \
  --namespace agentblackbox --create-namespace \
  -f ./charts/agentblackbox/values-standard.yaml \
  --set api.secretRef=agentblackbox-runtime
```

Before upgrading, render the same values and inspect the migration hook and resource changes:

```bash
helm template agentblackbox ./charts/agentblackbox \
  -f ./charts/agentblackbox/values-standard.yaml \
  --set api.secretRef=agentblackbox-runtime
helm diff upgrade agentblackbox ./charts/agentblackbox \
  -n agentblackbox -f ./charts/agentblackbox/values-standard.yaml \
  --set api.secretRef=agentblackbox-runtime
helm history agentblackbox -n agentblackbox
```

The migration Job runs as a pre-install/pre-upgrade hook. Review and wait for it:

```bash
kubectl -n agentblackbox get jobs
kubectl -n agentblackbox wait --for=condition=complete job \
  -l app.kubernetes.io/instance=agentblackbox --timeout=10m
kubectl -n agentblackbox logs job/agentblackbox-migration-<release-revision>
```

Rollback only after database and application compatibility is confirmed:

```bash
helm rollback agentblackbox <revision> -n agentblackbox
```

## Backup and restore

The SQLite PVC is suitable only for bounded/local deployments. HA deployments must use external
PostgreSQL/object/KMS services. Store database backups encrypted outside the cluster.

For a SQLite deployment, checkpoint and copy the database explicitly:

```bash
kubectl -n agentblackbox exec deploy/agentblackbox-api -- \
  python -c "import sqlite3; c=sqlite3.connect('/data/agentblackbox.db'); c.execute('PRAGMA wal_checkpoint(FULL)'); c.close()"
kubectl -n agentblackbox cp deploy/agentblackbox-api:/data/agentblackbox.db \
  ./agentblackbox-backup.db
```

Stop writers before restore and verify application/chart/database compatibility. This guide does
not automate backups, restore drills, RPO/RTO, or off-cluster retention.
