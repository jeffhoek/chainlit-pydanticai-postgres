# EPSS Integration

## Overview

[EPSS](https://www.first.org/epss/) (Exploit Prediction Scoring System) is a FIRST.org model
that scores each CVE with the **probability of exploitation in the wild within the next 30
days** (0.0–1.0), plus a **percentile** rank against all scored CVEs. It is refreshed daily.

EPSS is the fourth prioritization signal in the database, and each answers a different
question:

| Signal | Question | Nature |
| --- | --- | --- |
| `nvd_vulnerabilities.cvss_v31_score` | How bad is it if exploited? | Severity, static |
| `epss_scores.probability` | How likely is exploitation soon? | Likelihood, daily |
| `kev_vulnerabilities` membership | Is it confirmed exploited now? | Ground truth, lagging |
| `nvd_vulnerabilities.ssvc_*` | How urgently should I act? | Coordinator decision |

Because EPSS leads and KEV lags, **high EPSS + absent from KEV is an early-warning signal**,
not a contradiction. That is the query the dataset exists to answer.

## Data Source

FIRST.org publishes the full scored set as a gzipped CSV, refreshed daily around 12:00 UTC:

**URL:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (~2.4 MB gzipped,
~10 MB uncompressed, **353,212 rows** as of 2026-07-28)

No API key or authentication required. Re-running `load_epss.py` at any time pulls the latest
publication and upserts it.

Two things about this URL routinely cause trouble:

- **Cyentia's EPSS hosting moved to Empirical Security.** The widely-documented
  `https://epss.cyentia.com/...` host still works, but only by redirecting here.
- **`-current` is itself a redirect** to a dated file (`epss_scores-2026-07-28.csv.gz`).

So the fetch must follow redirects. `httpx` does **not** do that by default (unlike
`requests`), and a plain `client.get()` returns a 302 with an empty body that surfaces as a
confusing "no rows parsed" failure. The loader constructs its client with
`follow_redirects=True`.

### File format

```
#model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z
cve,epss,percentile
CVE-1999-0001,0.03351,0.87435
CVE-1999-0002,0.27858,0.97896
```

**Line 1 is a `#` metadata comment, not the header.** Handing the stream straight to
`csv.DictReader` makes `#model_version:v2026.06.15` the field name and silently yields zero
usable rows. The loader consumes it explicitly and parses `model_version` / `score_date` out
of it for provenance.

### Per-CVE API

`https://api.first.org/data/v1/epss?cve=CVE-2021-44228` returns a single score as JSON. Handy
for spot-checks; unusable for bulk load (353k requests). The loader uses the CSV.

## Database Schema

```sql
TABLE: epss_scores (
  cve_id               VARCHAR(20) PRIMARY KEY,  -- natural PK; no SERIAL
  probability          NUMERIC(6,5) NOT NULL,    -- 0–1, exploitation within 30 days
  percentile           NUMERIC(6,5) NOT NULL,    -- rank vs all scored CVEs
  scored_at            DATE NOT NULL,            -- the feed's score_date
  model_version        VARCHAR(16),              -- e.g. 'v2026.06.15'
  previous_probability NUMERIC(6,5),             -- prior publication's score
  previous_scored_at   DATE
)
```

No `embedding` / `content` column — like `cwe_definitions`, this is a join/lookup table.

### Why a separate table rather than columns on `nvd_vulnerabilities`

EPSS republishes **every** score daily. Under Postgres MVCC an UPDATE writes a whole new heap
tuple, so two extra columns on `nvd_vulnerabilities` would mean rewriting each row's
`raw_json` **and** its 1536-dimension `embedding` — plus HNSW index maintenance — for ~353k
rows, every day. That is exactly the cost the NVD bulk-load runbook drops the HNSW index to
avoid ([data-loading.md](data-loading.md)).

A narrow standalone table rewrites in seconds and touches no vector index. Measured locally:
**353,212 rows upserted in ~2.3s**.

### Why `NUMERIC` and not `REAL`

Threshold filters are the primary use (`WHERE probability >= 0.9`). `REAL` is binary floating
point, so a stored `0.9` can compare as `0.89999998` and silently drop rows at the boundary.
`NUMERIC` compares exactly on the 5 decimals the feed publishes. asyncpg maps it to `Decimal`,
which the loader parses directly from the CSV text — `Decimal(str)`, never `float()`, since
asyncpg's numeric codec rejects floats on COPY.

### Why no foreign key to `nvd_vulnerabilities`

The two row sets overlap only partially, in both directions:

- EPSS scores only *published* CVEs, so it lacks the REJECTED/RESERVED records NVD carries.
- EPSS can score a CVE before our NVD sync has picked it up.

A FK would make the loader fail on exactly the newest CVEs. **Consequence for every query:
always `LEFT JOIN epss_scores`, and treat a missing row as _unscored_, never as _zero risk_.**
An INNER JOIN silently drops those CVEs from rankings.

### Movement tracking without a history table

A true `epss_scores_history` table would cost ~353k rows/day ≈ **129M rows/year**. The
`previous_probability` / `previous_scored_at` columns capture the highest-value slice of that
— what moved since the last publication — at zero extra storage, because the prior value is
already in the row at upsert time.

The shift is guarded on `scored_at` actually advancing. The scheduled ETL runs roughly every
12h while EPSS publishes once daily, so an unguarded shift would, on the day's second run,
overwrite yesterday's baseline with today's own value and flatten every delta to zero. The
guard also makes a same-day re-run idempotent, so the loader is safe to retry.

## Loading EPSS Scores

```bash
uv run python scripts/load_epss.py
```

Parse-only mode, for when the upstream format changes:

```bash
uv run python scripts/load_epss.py --dry-run
```

The loader downloads the gzipped CSV, parses it, and bulk-upserts through a temp staging table
(`COPY` + a single `INSERT ... SELECT ... ON CONFLICT`) rather than a per-row loop — at 353k
rows, one statement per row would be that many round trips. Expected output:

```
Starting FIRST.org EPSS ETL...
Downloading EPSS scores from https://epss.empiricalsecurity.com/epss_scores-current.csv.gz...
Parsed 353212 EPSS scores (model v2026.06.15, scored 2026-07-28)
Connecting to PostgreSQL...
Upserting scores...
Done! Loaded 353212 EPSS scores (353212 new, 0 updated).
```

It also runs as part of the scheduled refresh — `scripts/run_etl.py` lists it alongside the
NVD and KEV loaders, and all three run independently of each other's success.

## Example Queries

### The leading-indicator query: likely to be exploited, not yet on KEV

```sql
SELECT n.cve_id, n.cvss_v31_score, e.probability, e.percentile
FROM nvd_vulnerabilities n
JOIN epss_scores e ON e.cve_id = n.cve_id
LEFT JOIN kev_vulnerabilities k ON k.cve_id = n.cve_id
WHERE e.probability >= 0.5 AND k.cve_id IS NULL
ORDER BY e.probability DESC;
```

### Severity/likelihood mismatch: scary-looking but unlikely

```sql
SELECT n.cve_id, n.cvss_v31_score, e.probability
FROM nvd_vulnerabilities n
LEFT JOIN epss_scores e ON e.cve_id = n.cve_id
WHERE n.cvss_v31_score >= 9.0 AND (e.probability < 0.01 OR e.probability IS NULL);
```

### Biggest movers since the last publication

```sql
SELECT cve_id, previous_probability, probability,
       probability - previous_probability AS delta
FROM epss_scores
WHERE previous_probability IS NOT NULL
ORDER BY delta DESC
LIMIT 20;
```

### EPSS and SSVC agreeing — the strongest "patch now" signal

```sql
SELECT n.cve_id, n.cvss_v31_score, e.probability, n.ssvc_exploitation
FROM nvd_vulnerabilities n
JOIN epss_scores e ON e.cve_id = n.cve_id
WHERE e.probability >= 0.5 AND n.ssvc_exploitation = 'active'
ORDER BY e.probability DESC;
```

## Interpreting Scores

EPSS is **heavily skewed** — most CVEs sit below 0.01. Useful bands:

| Band | Reading |
| --- | --- |
| `probability >= 0.5` | High — act on this |
| `probability >= 0.1` | Elevated |
| `percentile >= 0.95` | Top 5% of all scored CVEs |
| `probability < 0.01` | The large majority; low absolute likelihood |

Report the percentile alongside a raw probability rather than describing e.g. 0.05 as "low" —
in percentile terms it is well above the median. Scores change daily, so cite `scored_at`.

## Verification

```sql
-- Row count and freshness
SELECT COUNT(*), MIN(scored_at), MAX(scored_at), MAX(model_version) FROM epss_scores;

-- Known-high CVE: Log4Shell sits at the ceiling
SELECT * FROM epss_scores WHERE cve_id = 'CVE-2021-44228';

-- Join coverage — expect a nonzero unscored remainder
SELECT COUNT(*) FILTER (WHERE e.cve_id IS NULL) AS unscored, COUNT(*) AS total
FROM nvd_vulnerabilities n LEFT JOIN epss_scores e ON e.cve_id = n.cve_id;
```

After the *second* publication is loaded, `previous_probability` should populate:

```sql
SELECT COUNT(*) FROM epss_scores WHERE previous_probability IS NOT NULL;
```

## Database Grants

`epss_scores` is a new table, and the project grants per-table with **no wildcard**
(see [supabase-readonly-role.md](supabase-readonly-role.md)). Without these the ETL fails on
write and the app returns permission errors on every EPSS query:

```sql
GRANT SELECT ON epss_scores TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON epss_scores TO app_etl;
```

No sequence grant is needed — `cve_id` is the primary key and there is no `SERIAL`.

Production runs `DB_INIT_SCHEMA=false`, and the loaders connect with a plain `asyncpg.connect`
that never applies `SCHEMA_SQL`, so the table must be created with the admin role before the
first run. Use the **pooled** Supabase host with `psql` (the direct host is IPv6-only, and
asyncpg's prepared statements break on the transaction pooler) — the DDL is in
[plans/epss-score-integration.md](../plans/epss-score-integration.md#10-production-rollout).

## See Also

- [plans/epss-score-integration.md](../plans/epss-score-integration.md) — design rationale,
  rollout runbook, and deferred work
- [data-loading.md](data-loading.md) — all ETL scripts and refresh cadence
- [nvd-integration.md](nvd-integration.md) — the NVD dataset EPSS joins against
