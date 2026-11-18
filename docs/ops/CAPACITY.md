# Capacity guide

Start with one API replica and the SQLite data volume. Measure `/health` and ingest latency with:

```bash
make up
make loadtest
python scripts/loadtest.py --requests 500
```

SQLite is not a horizontally scalable backend. Before scaling beyond one API instance or one
host, migrate to PostgreSQL and define locking, backup, and migration roles.
