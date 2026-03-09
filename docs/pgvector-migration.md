# PostgreSQL/pgvector Migration Guide

This documents the migration from the in-memory NumPy vector store (with S3/local file loading) to PostgreSQL with pgvector as the persistent vector store, using the CISA KEV (Known Exploited Vulnerabilities) dataset.

## Architecture

- **Local dev**: pgvector Docker image via compose, Langfuse postgres remapped to port 5433
- **Cloud**: TigerData (managed PostgreSQL with pgvector/pgai support)
- **ETL**: Standalone script fetches CISA KEV data, generates embeddings, upserts into PostgreSQL
- **App**: Read-only access to pgvector — no data loading on startup

## Prerequisites

- PostgreSQL 17 with pgvector extension
- OpenAI API key (for text-embedding-3-small)
- `uv` package manager

## Local Development Setup

### 1. Start pgvector

```bash
podman compose up -d pgvector
```

This starts pgvector on port 5432. Langfuse postgres is remapped to port 5433.

### 2. Run the ETL script

```bash
uv run python scripts/load_kev.py
```

This fetches ~1500 CISA KEV records, generates embeddings, and upserts them into the `kev_vulnerabilities` table.

### 3. Verify data

```bash
psql -h localhost -U postgresuser -d inventory -c "SELECT count(*) FROM kev_vulnerabilities;"
```

### 4. Start the app

```bash
uv run chainlit run app.py
```

The chatbot connects to PostgreSQL on startup and displays the record count.

## Database Schema

```sql
CREATE TABLE kev_vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    short_description TEXT,
    required_action TEXT,
    notes TEXT,
    date_added DATE,
    due_date DATE,
    known_ransomware_campaign_use VARCHAR(20),
    cwes TEXT[],
    content TEXT NOT NULL,
    embedding vector(1536)
);

CREATE INDEX kev_embedding_idx
    ON kev_vulnerabilities
    USING hnsw (embedding vector_cosine_ops);
```

The schema is auto-created by the app and ETL script on first run.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | Full connection string (takes precedence) |
| `PG_HOST` | `localhost` | PostgreSQL host |
| `PG_PORT` | `5432` | PostgreSQL port |
| `PG_USER` | `postgresuser` | PostgreSQL user |
| `PG_PASSWORD` | `postgrespw` | PostgreSQL password |
| `PG_DATABASE` | `inventory` | PostgreSQL database name |

### Cloud (TigerData)

Set `PG_HOST` to your TigerData endpoint in the K8s configmap. `PG_USER` and `PG_PASSWORD` are stored in AWS SSM Parameter Store and synced via External Secrets Operator.

Create SSM parameters:
```bash
aws ssm put-parameter --name /rag/PG_USER     --value <value> --type SecureString
aws ssm put-parameter --name /rag/PG_PASSWORD  --value <value> --type SecureString
```

## What Changed

| File | Change |
|------|--------|
| `pyproject.toml` | Replaced `numpy`, `aioboto3`, `boto3` with `asyncpg`, `pgvector`, `httpx` |
| `config.py` | Replaced S3/AWS settings with PostgreSQL settings |
| `rag/database.py` | New — connection pool and schema management |
| `rag/vector_store.py` | Rewritten — `PgVectorStore` using asyncpg + pgvector |
| `rag/agent.py` | Updated `Deps` and async search call |
| `app.py` | Removed data loading; wires PostgreSQL pool on startup |
| `rag/data_loader.py` | Deleted — replaced by ETL script |
| `scripts/load_kev.py` | New — CISA KEV ETL script |
| `docker-compose.yaml` | Added pgvector service, remapped Langfuse postgres to 5433 |
| `.env.example` | Replaced S3 vars with PostgreSQL vars |
| `k8s/configmap.yaml` | Added PG_HOST/PORT/DATABASE, removed S3 vars |
| `k8s/external-secret.yaml` | Added PG_USER/PG_PASSWORD from SSM |
| `k8s/deployment.yaml` | Reduced startup probe threshold (no slow data loading) |

## Refreshing KEV Data

Re-run the ETL script anytime to pull the latest CISA KEV feed. It uses `ON CONFLICT (cve_id) DO UPDATE` so existing records are updated in place.

```bash
uv run python scripts/load_kev.py
```
