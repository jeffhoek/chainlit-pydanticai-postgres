# Data Loading

This guide covers populating the PostgreSQL/pgvector database with CISA KEV, NIST NVD, and MITRE CWE vulnerability data. These steps apply regardless of where the database is hosted (local container, Timescale Cloud, RDS, etc.).

## Prerequisites

- PostgreSQL with pgvector extension enabled
- `.env` configured with `DATABASE_URL` (or `PG_*` vars) and `OPENAI_API_KEY`
- Dependencies installed (`uv sync`)

### Connecting securely (keep the password out of `argv`)

The `psql` commands below use `"$DATABASE_URL"`. **Never embed the database password
in that variable** — anything on a command line is visible to every user on the host
via `ps`, and it lands in your shell history. Instead, export a **password-less**
connection string and let `~/.pgpass` supply the secret:

```bash
# password-less — safe to appear in ps / history
export DATABASE_URL="postgresql://<user>@<host>:5432/<db>"
```

```
# ~/.pgpass  (chmod 600)  —  host:port:db:user:password
<host>:5432:<db>:<user>:<password>
```

With a matching `~/.pgpass` entry, `psql "$DATABASE_URL"` authenticates with no
password on the command line. (The Python app reads its own credentialed
`DATABASE_URL`/`PG_DATABASE_URL` from `.env`, which is never passed on a command
line — this guidance is only for interactive `psql`.)

Verify pgvector is available:

```bash
psql "$DATABASE_URL" -c "SELECT extname FROM pg_extension WHERE extname = 'vector';"
```

If not present:

```bash
psql "$DATABASE_URL" -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

## Schema

Schema creation runs automatically on app startup. To create it manually:

```bash
uv run python -c "from rag.database import init_db; import asyncio; asyncio.run(init_db())"
```

## ETL Scripts

There are four ETL scripts, each targeting a different scope:

| Script | Scope | Records | Use case |
|---|---|---|---|
| `scripts/load_kev.py` | CISA KEV catalog | ~1,500 | Always run first — KEV is the primary dataset |
| `scripts/load_nvd.py` | NVD data for KEV CVEs only | ~1,500 | Enriches KEV entries with CVSS scores, severity, affected products |
| `scripts/load_nvd_full.py` | Entire NVD database | ~280,000 | Full NVD corpus for broader vulnerability research |
| `scripts/load_cwe.py` | MITRE CWE definitions | ~900 | Resolves opaque CWE IDs to human-readable weakness names/descriptions |

### 1. Load CISA KEV data

Fetches the CISA KEV catalog and generates OpenAI embeddings:

```bash
uv run python scripts/load_kev.py
```

### 2. Load NVD enrichment (KEV-scoped)

Fetches NVD data only for CVE IDs already in the `kev_vulnerabilities` table:

```bash
uv run python scripts/load_nvd.py
```

**Rate limits:**
- Without API key: 5 requests/30s (~5 min for full load)
- With API key: 50 requests/30s (~30 sec for full load)

The script is incremental — it skips CVEs already loaded, so re-runs only fetch new entries.

### 3. Load full NVD database (optional)

Fetches the entire NVD (~280k CVEs) via paginated bulk API calls. This is a large dataset requiring ~3.5-5.5 GB of storage (see [plans/postgres-hosting-options.md](../plans/postgres-hosting-options.md) for sizing details).

```bash
# Full load — fetches all CVEs, generates embeddings
uv run python scripts/load_nvd_full.py

# Incremental sync — fetches only CVEs published or modified since last run
uv run python scripts/load_nvd_full.py --incremental

# Override start date — use after an interrupted incremental run
uv run python scripts/load_nvd_full.py --incremental --since 2026-04-14

# Data only, skip embedding generation (faster initial load)
uv run python scripts/load_nvd_full.py --skip-embeddings

# Backfill embeddings for records loaded without them
uv run python scripts/load_nvd_full.py --backfill-embeddings

# Test with a limited number of pages
uv run python scripts/load_nvd_full.py --limit 3
```

**Features:**
- Paginated bulk fetching (2,000 CVEs per page)
- Checkpoint/resume — interrupted full loads pick up where they left off
- Two-phase incremental sync: new CVEs (by publish date) first, then modified CVEs — ensures newly published vulnerabilities aren't buried behind routine metadata updates
- Staging table upserts (`INSERT ... ON CONFLICT`) for idempotent loads
- Retry logic for both NVD API and database connections

**Recovering from an interrupted incremental sync:**

If you kill an incremental run mid-way, the `MAX(last_modified)` high-water mark in the DB will have advanced, causing the next run to skip unprocessed records. Use `--since` to force the original start date:

```bash
uv run python scripts/load_nvd_full.py --incremental --since 2026-04-14
```

Already-processed records will upsert harmlessly.

**Recommended workflow for the full NVD load:**

1. Load data without embeddings (fast, ~30 min with API key):
   ```bash
   uv run python scripts/load_nvd_full.py --skip-embeddings
   ```

2. Backfill embeddings separately (can be interrupted and resumed):
   ```bash
   caffeinate -i uv run python scripts/load_nvd_full.py --backfill-embeddings
   ```

3. Keep up to date with incremental syncs (Phase 2 can take several hours — use `caffeinate -i`):
   ```bash
   caffeinate -i uv run python scripts/load_nvd_full.py --incremental
   ```

**HNSW index and large incremental syncs:**

NVD modifies thousands of CVEs per week for routine metadata refreshes (CVSS rescoring, CPE updates, etc.), so large incremental windows can involve 20k–80k upserts. Maintaining the HNSW vector index on every batch causes significant Disk IO — on constrained hosting (e.g. Supabase Micro) this can make each 2,000-row batch take several minutes.

For large syncs (roughly monthly or after a long gap), drop the index before running and rebuild it afterward. **Upgrade to Medium compute before the rebuild** — Micro cannot allocate enough shared memory for a usable `maintenance_work_mem` setting, making the build extremely slow. Downgrade back to Micro when done.

> **Running this in the cloud instead of a laptop?** These same catch-ups (and the HNSW drop/rebuild + schedule-disable steps) are driven from Azure DevOps via the manual [ETL pipeline](etl-pipeline.md), which starts a long-timeout Container Apps Job — no `caffeinate`, no laptop.

```sql
-- Before ETL (run in Supabase SQL editor or psql)
DROP INDEX IF EXISTS nvd_embedding_idx;
```

```bash
caffeinate -i uv run python scripts/load_nvd_full.py --incremental
```

```bash
# After ETL — rebuild with 1GB maintenance_work_mem (max usable on Medium)
caffeinate -i time psql "$DATABASE_URL" -c "SET statement_timeout = 0; SET maintenance_work_mem = '1GB'; CREATE INDEX nvd_embedding_idx ON nvd_vulnerabilities USING hnsw (embedding vector_cosine_ops);"
```

Monitor progress in the Supabase SQL editor:

```sql
SELECT phase, tuples_done, tuples_total,
       round(tuples_done::numeric / nullif(tuples_total, 0) * 100, 1) AS pct_done
FROM pg_stat_progress_create_index
WHERE relid = 'nvd_vulnerabilities'::regclass;
```

The row disappears when the build completes. On Medium with 1GB `maintenance_work_mem`, expect ~60 minutes for ~346k rows at 1536 dimensions. The chatbot's semantic search is unavailable during this window but the app remains up.

For smaller weekly syncs the index overhead is usually tolerable — skip the drop/rebuild unless upsert batches start taking several minutes.

### 4. Load CWE definitions (optional)

Resolves the CWE IDs stored in the `cwes` column of the KEV and NVD tables to human-readable weakness names and descriptions. Downloads MITRE's CWE list and upserts it into `cwe_definitions`:

```bash
uv run python scripts/load_cwe.py
```

No API key or authentication required. The script is idempotent — re-running pulls the latest CWE release (published 2–3 times per year) and upserts any changes. See [cwe-integration.md](cwe-integration.md) for schema and example join queries.

## NVD API Key

All NVD scripts benefit from an API key, which increases the rate limit from 5 to 50 requests per 30 seconds. Set `NVD_API_KEY` in `.env`. Request a free key at https://nvd.nist.gov/developers/request-an-api-key.

## Verification

```bash
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM kev_vulnerabilities;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM nvd_vulnerabilities;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM nvd_vulnerabilities WHERE embedding IS NULL;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM cwe_definitions;"
```

## Refreshing Data

**CISA KEV + NVD enrichment** (re-run to pick up new entries):

```bash
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py
```

**Full NVD** (incremental sync):

```bash
# Weekly — index overhead is usually fine
caffeinate -i uv run python scripts/load_nvd_full.py --incremental

# Monthly / large gap — upgrade to Medium compute, drop HNSW index first, rebuild after (see above)
```

No app restart is needed — data is queried live from the database.
