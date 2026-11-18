# Disaster recovery

The local SQLite database is persisted in the `api-data` Docker volume. Back it up explicitly
before destructive operations:

```bash
docker compose exec api python -c "import sqlite3; sqlite3.connect('/data/agentblackbox.db').execute('PRAGMA wal_checkpoint')"
docker run --rm -v ai_agent_api-data:/data -v "$PWD:/backup" alpine cp /data/agentblackbox.db /backup/agentblackbox.db
```

This is an operator copy procedure, not an automated backup or verified restore SLA.
PostgreSQL, object storage, off-site replication, and real restore drills remain deferred.
