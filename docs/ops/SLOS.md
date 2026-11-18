# Local SLO candidates

These are targets for an eventual deployed service, not measured production commitments.

| SLI | Suggested objective | Current measurement |
|---|---|---|
| API availability | 99.9% monthly for `/health` and `/ready` | Compose health check locally |
| API latency | 95% of `/health` requests under 250 ms | `scripts/loadtest.py` |
| Event ingestion success | 99.9% of authenticated ingestion requests | Application logs and future metrics |
| Database health | `/ready` reports SQLite connectivity | `/ready` |

No external monitoring or historical availability data exists in this repository.

The [example alert rules](alert-rules.yml) define local syntax examples only.
Production alert delivery is deferred until CloudWatch alarm actions and an on-call
notification destination are provisioned. Runbook index:

- [On-call](ON_CALL.md)
- [Incident response](../INCIDENT_RESPONSE.md)
- [Disaster recovery](DISASTER_RECOVERY.md)
