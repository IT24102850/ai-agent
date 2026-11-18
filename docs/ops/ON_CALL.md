# On-call guide

## Triage locally

1. Run `make doctor`.
2. Run `docker compose ps`.
3. Inspect `docker compose logs api web db minio`.
4. Check `curl http://localhost:8000/health` and `/ready`.
5. Check `/metrics` for database reachability and counters.

No real on-call rotation or paging integration is configured. Escalation ownership must be
established externally.
