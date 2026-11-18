# Service inventory

| Service | Runtime | Local role | Persistent data | Integrated now |
|---|---|---|---|---|
| API | FastAPI/Python 3.12 | HTTP application | SQLite `/data/agentblackbox.db` | Yes |
| db | PostgreSQL 16 image | Future relational backend | `postgres-data` volume | No; API uses SQLite |
| minio | MinIO | Future object storage | `minio-data` volume | No |
| web | Next.js/Node 20 | Local console | None | Yes |

The Compose `db` and `minio` services are Level 1 local fixtures only. No application code calls them.
