# ETL pipeline (cloud-native catch-ups)

How to run NVD/KEV ETL in the cloud — scheduled *and* ad-hoc — without running
`load_nvd_full.py` from a laptop under `caffeinate`.

## Two paths, one image

Both paths run the **same container image** (`vulncopilot:latest`) with the **same
managed identity and Key Vault secrets**. They differ only in trigger and timeout.

| Path | Resource | Trigger | Timeout | Runs |
|---|---|---|---|---|
| **Scheduled** | `job-vulncopilot-etl-dev` ([etl-job.bicep](../infra/modules/etl-job.bicep)) | Cron (`etlCronExpression`, UTC) | 2h | `run_etl.py` (NVD full incremental + KEV, emails a summary) |
| **Ad-hoc catch-up** | `job-vulncopilot-etl-catchup-dev` ([etl-catchup-job.bicep](../infra/modules/etl-catchup-job.bicep)) | Manual, via [azure-pipelines-etl.yml](../azure-pipelines-etl.yml) | ~10h | Any mode — the pipeline overrides the command/args per run |

The scheduled job owns the routine weekly refresh. The catch-up job exists for the
large one-off backlogs that overran the laptop — e.g. the June-2026 SSVC "storm"
backfill of ~344k records.

### Why a pipeline that *starts a job*, not a pipeline that *runs the ETL*

The pipeline only orchestrates (`az containerapp job start` + poll). The ETL itself
runs in Azure Container Apps because:

- **Secrets never touch the agent.** `PG_DATABASE_URL`, `NVD_API_KEY`, and
  `OPENAI_API_KEY` live in Key Vault, bound to the job's user-assigned identity.
  Nothing sensitive is added to ADO beyond the existing `azure-vulncopilot` service
  connection.
- **No 60-minute agent cap.** Microsoft-hosted agents terminate long jobs; a
  multi-hour catch-up would time out on the agent — the exact laptop-sleep problem,
  relocated. The container job runs async up to its `replicaTimeout` (~10h).
- **Network already allowlisted.** The job identity/egress is on the database
  allowlist; ephemeral hosted-agent IPs are not.

## Triggering a manual catch-up

In Azure DevOps: **Pipelines → `vulncopilot-etl` → Run pipeline**, then set the
parameters. The dialog renders directly from the `parameters:` block in
[azure-pipelines-etl.yml](../azure-pipelines-etl.yml).

| Parameter | Meaning |
|---|---|
| **mode** | Which loader to run (see table below). |
| **since** | `YYYY-MM-DD` start date — **`nvd-incremental` only**. Blank uses the DB high-water mark. Set this to recover from an interrupted run (the high-water mark advances mid-run and would skip records). |
| **skipEmbeddings** | `nvd-incremental` only. Load rows fast without embeddings; backfill them afterward with a `backfill-embeddings` run. |
| **waitForCompletion** | On: the pipeline polls the execution and fails if the run fails. Off: fire-and-forget (returns as soon as the job starts). |
| **pollTimeoutMinutes** | How long the pipeline waits before giving up (the *job* keeps running in Azure regardless). |

### Modes

| mode | Command run in the job | Use case |
|---|---|---|
| `nvd-incremental` | `load_nvd_full.py --incremental [--since …] [--skip-embeddings]` | The standard catch-up. Fill a backlog since a date. |
| `backfill-embeddings` | `load_nvd_full.py --backfill-embeddings` | Generate embeddings for rows loaded with `--skip-embeddings`. |
| `backfill-ssvc` | `load_nvd_full.py --backfill-ssvc` | Populate SSVC columns from `raw_json` (no API calls). |
| `full-refresh-kev-nvd` | `run_etl.py` | The scheduled job's payload, on demand (NVD incremental + KEV + email). |
| `kev-only` | `load_kev.py` | Refresh just the CISA KEV catalog. |

### Recommended large-catch-up workflow

Mirrors the fast laptop workflow, but in the cloud:

1. Run `nvd-incremental` with **`skipEmbeddings` on** and an explicit **`since`** —
   fast, data only.
2. Run `backfill-embeddings` to fill the vectors (the long part; the ~10h timeout
   covers it).

For a truly large embedding backfill, first apply the **HNSW index runbook** below.

## Operational runbook (learnings from the manual runs)

### Drop the HNSW index before a large bulk load, rebuild after — ~5–10x faster

Maintaining the `nvd_embedding_idx` HNSW index on every 2,000-row batch is heavy
Disk IO; on constrained compute it can make each batch take minutes. For a large
load (roughly monthly or after a long gap), drop the index first and rebuild once at
the end.

```sql
-- Before: Supabase SQL editor (or psql). Cheap; the app stays up, semantic search
-- degrades to non-vector paths until the rebuild finishes.
DROP INDEX IF EXISTS nvd_embedding_idx;
```

Run the catch-up (pipeline), then rebuild. **Bump Supabase compute Micro→Medium for
the rebuild** — Micro cannot allocate enough `maintenance_work_mem` and the build
crawls. Downgrade back to Micro afterward.

```bash
# After: ~60 min for ~346k rows at 1536 dims on Medium with 1GB maintenance_work_mem.
psql "$DATABASE_URL" -c "SET statement_timeout = 0; SET maintenance_work_mem = '1GB'; CREATE INDEX nvd_embedding_idx ON nvd_vulnerabilities USING hnsw (embedding vector_cosine_ops);"
```

```sql
-- Watch progress; the row disappears when the build completes.
SELECT phase, tuples_done, tuples_total,
       round(tuples_done::numeric / nullif(tuples_total, 0) * 100, 1) AS pct_done
FROM pg_stat_progress_create_index
WHERE relid = 'nvd_vulnerabilities'::regclass;
```

For small weekly syncs the index overhead is fine — skip the drop/rebuild.

### Disable the scheduled job during a large catch-up

Two incremental writers running at once race the `MAX(last_modified)` high-water
mark and contend on the same rows. Before a large catch-up, pause the schedule so
the Monday cron can't collide:

```bash
# Pause the cron trigger (keeps the job; just stops it firing).
az containerapp job update -n job-vulncopilot-etl-dev -g rg-vulncopilot-dev \
  --set properties.configuration.scheduleTriggerConfig.cronExpression="0 0 31 2 *"  # Feb 31 = never

# Re-enable after the catch-up (restore the real schedule, or redeploy the bicep).
az containerapp job update -n job-vulncopilot-etl-dev -g rg-vulncopilot-dev \
  --set properties.configuration.scheduleTriggerConfig.cronExpression="0 6 * * 1"
```

The catch-up pipeline also **hard-fails if a catch-up execution is already Running**
and **warns if the scheduled job is mid-run**, but disabling the schedule up front
is the clean way to avoid the overlap during a multi-hour run.

## Secret wiring

No ETL secrets live in the repo or in ADO. The catch-up job (like the scheduled
job) reads them from Key Vault via the user-assigned managed identity:

| Env var (in the job) | Key Vault secret | Source |
|---|---|---|
| `PG_DATABASE_URL` | `database-url` | Supabase connection string |
| `NVD_API_KEY` | `nvd-api-key` | NVD API key (raises the rate limit 5→50 req/30s) |
| `OPENAI_API_KEY` | `openai-api-key` | OpenAI key for embeddings |

The identity holds **Key Vault Secrets User** and **AcrPull** at resource-group
scope (see [rbac.bicep](../infra/modules/rbac.bicep)). The pipeline authenticates to
Azure only through the existing `azure-vulncopilot` service connection to call
`az containerapp job start`; it never handles the ETL secrets.

To rotate a secret, update the Key Vault secret — the next job run picks it up. No
pipeline or bicep change is needed.

## Logs

Container Apps job logs flow to the `log-vulncopilot-dev` Log Analytics workspace
(ingestion lags ~1–2 min, which is why the pipeline polls execution *status* rather
than tailing logs). To read a run's logs:

```bash
# Live-ish stream while a run is in progress
az containerapp job logs show -n job-vulncopilot-etl-catchup-dev -g rg-vulncopilot-dev \
  --container etl-catchup --follow

# Or query Log Analytics for a finished execution
az monitor log-analytics query \
  --workspace "$(az monitor log-analytics workspace show -n log-vulncopilot-dev -g rg-vulncopilot-dev --query customerId -o tsv)" \
  --analytics-query "ContainerAppConsoleLogs_CL | where ContainerAppName_s == 'job-vulncopilot-etl-catchup-dev' | order by _timestamp_d desc | take 200"
```

The `full-refresh-kev-nvd` mode also emails a results summary via ACS (same as the
scheduled job); the `load_nvd_full.py` modes do not email.
