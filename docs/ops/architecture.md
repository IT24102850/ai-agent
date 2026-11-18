# Architecture and deployment diagrams

## Local architecture

```mermaid
flowchart LR
  Browser[Operator browser] --> Web[Next.js web :3000]
  Web -->|NEXT_PUBLIC_API_BASE_URL| API[FastAPI API :8000]
  API --> SQLite[(SQLite volume)]
  DB[PostgreSQL 16 :5432] -. future backend .-> API
  MinIO[MinIO :9000/:9001] -. future object storage .- API
```

## Local deployment

```mermaid
flowchart TB
  Docker[Docker Compose]
  Docker --> APIContainer[api container]
  Docker --> WebContainer[web container]
  Docker --> PGContainer[db container]
  Docker --> S3Container[minio container]
  APIContainer --> APIVolume[(api-data)]
  PGContainer --> PGVolume[(postgres-data)]
  S3Container --> MinIOVolume[(minio-data)]
```

This diagram describes only local containers. Cloud load balancers, managed PostgreSQL,
Kubernetes, KMS, DNS, and alerting are not implemented.
