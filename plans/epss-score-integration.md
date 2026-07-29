# EPSS Score Integration

Load the FIRST.org **Exploit Prediction Scoring System** daily feed into a new `epss_scores`
table keyed by CVE ID, and teach the agent to use it.

Supersedes the sketch in [future-enhancements.md](future-enhancements.md#epss-score-ingestion)
(whose source URL and row count are both stale — see §1).

## Why EPSS

EPSS gives every scored CVE a **probability (0.0–1.0) of exploitation in the wild within the
next 30 days**, plus a **percentile** rank against all scored CVEs. It fills the gap between
the signals we already carry:

| Signal | Question it answers | Nature |
| --- | --- | --- |
| `cvss_v31_score` | *How bad is it if exploited?* | Severity, static |
| `epss.probability` | *How likely is it to be exploited soon?* | Likelihood, **daily-refreshed** |
| KEV listing | *Is it confirmed exploited right now?* | Ground truth, lagging |
| `ssvc_exploitation` | *How urgently should I act?* | Coordinator decision |

A CVSS 9.8 with EPSS 0.001 is likely noise; a CVSS 6.5 with EPSS 0.95 deserves attention this
week. EPSS is the **leading** indicator to KEV's lagging one, which unlocks the flagship query:
*"high-EPSS CVEs that aren't on KEV yet."*

It is also the load-bearing dependency for the Composite Risk Score tool in
[future-enhancements.md](future-enhancements.md#composite-risk-score-tool).

---

## 1. Data source (verified live 2026-07-28)

The URL in `future-enhancements.md` (`epss.cyentia.com`) is **stale**. Cyentia's EPSS hosting
moved to Empirical Security; the old host still works but only via redirect:

```
https://epss.cyentia.com/epss_scores-current.csv.gz
  → 302 → https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  → 302 → https://epss.empiricalsecurity.com/epss_scores-2026-07-28.csv.gz
```

Use the **canonical host directly** — `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
— and note that `-current` *itself* redirects to a dated file, so redirect-following is required
either way.

> **httpx gotcha:** unlike `requests`, **httpx does not follow redirects by default.** Both
> existing feed loaders (`load_kev.py`, `load_cwe.py`) call `client.get(...)` with no
> `follow_redirects`, because their URLs are direct. Copying that shape here yields a 302 with
> an empty body and a confusing "no rows parsed" failure. The client must be constructed with
> `httpx.AsyncClient(timeout=60, follow_redirects=True)`.

### Verified file shape

```
#model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z
cve,epss,percentile
CVE-1999-0001,0.03351,0.87435
CVE-1999-0002,0.27858,0.97896
```

| Property | Verified value |
| --- | --- |
| Download size (gzip) | ~2.4 MB |
| Uncompressed | ~10.2 MB |
| Data rows | **353,212** (`future-enhancements.md` says ~250K — stale) |
| Refresh cadence | Daily, ~12:00 UTC |
| Model version | `v2026.06.15` (EPSS v4 series) |
| Auth | None |

**Line 1 is a `#`-prefixed metadata comment, not a header.** Handing the stream straight to
`csv.DictReader` makes `#model_version:v2026.06.15` the field name and silently produces zero
usable rows. Consume line 1 explicitly, parse `model_version` and `score_date` out of it for
provenance, then let `DictReader` read line 2 as the header.

Also validate the header is exactly `cve,epss,percentile` and fail loudly otherwise — the same
`expected - set(reader.fieldnames)` guard `load_cwe.py:55` already uses.

### Per-CVE API (not used by the loader)

`https://api.first.org/data/v1/epss?cve=CVE-2021-44228` returns a single score as JSON. Fine for
spot-checking during verification; wrong for bulk load (353k requests). The loader uses the CSV.

---

## 2. Data model

### Separate table, **not** columns on `nvd_vulnerabilities`

This is the load-bearing design decision, and the reason is cost, not taste.

EPSS republishes **all ~353k scores every day**. Adding `epss_probability`/`epss_percentile`
columns to `nvd_vulnerabilities` would mean a daily UPDATE touching essentially every row of
that table. Under Postgres MVCC an UPDATE writes a **whole new heap tuple**, so changing two
numeric columns would rewrite each row's `raw_json` JSONB *and* its 1536-dimension `embedding`
— and force **HNSW index maintenance on all 353k rows**. That is precisely the cost the SSVC
runbook goes to great lengths to avoid by dropping the HNSW index for bulk loads
([ssvc-affected-integration.md](ssvc-affected-integration.md), step 3, ~5–10× lever).

A narrow standalone table is ~353k rows × ~40 bytes, rewrites in seconds, touches no vector
index, and joins on an indexed `cve_id`. Daily refresh becomes routine instead of an event.

### Schema

Add to `SCHEMA_SQL` in [rag/database.py](rag/database.py), following the existing
`CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` migration pattern:

```sql
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id               VARCHAR(20) PRIMARY KEY,
    probability          NUMERIC(6,5) NOT NULL,  -- 0.00000–1.00000, exploitation in next 30d
    percentile           NUMERIC(6,5) NOT NULL,  -- rank against all scored CVEs
    scored_at            DATE NOT NULL,          -- feed's score_date
    model_version        VARCHAR(16),            -- e.g. 'v2026.06.15'
    previous_probability NUMERIC(6,5),           -- prior day's score, for movement queries
    previous_scored_at   DATE
);

CREATE INDEX IF NOT EXISTS epss_probability_idx ON epss_scores (probability DESC);
```

Notes on the choices:

- **`cve_id` as the natural primary key — no `SERIAL id`.** Every other table here carries a
  synthetic `id SERIAL`, but nothing needs one, and omitting it avoids the sequence-grant
  footgun the ETL-stats work hit (`GRANT USAGE, SELECT ON SEQUENCE ...`, see
  [etl-stats-dashboard.md:66](etl-stats-dashboard.md)). The PK also serves the join.
- **`NUMERIC(6,5)`, not `REAL`** (a deliberate deviation from the `future-enhancements.md`
  sketch). Threshold filters are the primary use — `WHERE probability >= 0.9`, bucket
  boundaries, `>= 0.5` — and `REAL` is binary floating point, so a stored `0.9` can compare
  as `0.89999998` and silently drop rows at the boundary. `NUMERIC` compares exactly on the
  5 decimals the feed actually publishes. At 353k rows the extra bytes are irrelevant, and
  it matches the existing `cvss_v31_score NUMERIC(3,1)` convention. asyncpg returns
  `Decimal`, which `_cell_str` in [rag/sql_utils.py:30](rag/sql_utils.py:30) already
  stringifies correctly.
- **Only one index beyond the PK.** `percentile` is a monotone transform of `probability`, so
  a second index would earn nothing; `ORDER BY probability DESC` covers the ranking queries.
- **No `embedding` / `content` column.** This is a join/lookup table, exactly like
  `cwe_definitions`. See §5 for why EPSS must stay out of embedded content.

### No foreign key to `nvd_vulnerabilities`

Deliberate. The two sets do not nest in either direction:

- EPSS scores only *published* CVEs, so it lacks rows NVD has (REJECTED/RESERVED records).
- EPSS can carry a CVE ID before our NVD sync has picked it up.

Live counts make the mismatch concrete: **353,212 EPSS rows** vs ~366,846 NVD rows. A FK would
make the loader fail on exactly the newest and most interesting CVEs. Consequence for every
consumer: **always `LEFT JOIN`**, and treat a missing row as *unscored*, never as *zero risk*.
This must be stated in the system prompt (§4) or the agent will quietly use `INNER JOIN` and
under-report.

### Movement tracking without a history table

Trend queries ("biggest EPSS movers this week") are genuinely valuable, but a true
`epss_scores_history` table costs **353k rows/day ≈ 129M rows/year** — a large ongoing burden
on a Supabase instance already sized around the HNSW index.

The `previous_probability` / `previous_scored_at` columns give the highest-value slice of that
— *what moved since the last publication* — at **zero extra storage**, because the prior value
is already in the row at upsert time. Full history stays deferred (§8, Open question 2).

> **The delta guard is the subtle part.** The scheduled ETL runs roughly **every 12h** while
> EPSS publishes **once daily**. A naive `previous_probability = epss_scores.probability` shift
> would, on the day's *second* run, overwrite yesterday's baseline with today's own value and
> flatten every delta to zero. Guard the shift on the feed's `scored_at` actually advancing:

```sql
ON CONFLICT (cve_id) DO UPDATE SET
    probability   = EXCLUDED.probability,
    percentile    = EXCLUDED.percentile,
    scored_at     = EXCLUDED.scored_at,
    model_version = EXCLUDED.model_version,
    previous_probability = CASE
        WHEN EXCLUDED.scored_at > epss_scores.scored_at
        THEN epss_scores.probability
        ELSE epss_scores.previous_probability END,
    previous_scored_at = CASE
        WHEN EXCLUDED.scored_at > epss_scores.scored_at
        THEN epss_scores.scored_at
        ELSE epss_scores.previous_scored_at END
```

This makes a same-day re-run idempotent, which also means the loader is safe to retry.

---

## 3. The loader — `scripts/load_epss.py`

Shape it on **`load_nvd_full.py`'s bulk-staging pattern**, *not* on `load_cwe.py`.

`load_cwe.py` loops `await conn.execute(...)` once per row, which is fine for its ~900 rows but
would be **353,212 round trips** here — tens of minutes of pure latency against Supabase. Use
the temp-table + `copy_records_to_table` + `INSERT ... SELECT ... ON CONFLICT` approach from
[scripts/load_nvd_full.py:270](scripts/load_nvd_full.py:270), which loads the whole file in one
COPY and one upsert.

```python
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

CREATE_STAGING_SQL = """
    CREATE TEMP TABLE _epss_staging (
        cve_id VARCHAR(20),
        probability NUMERIC(6,5),
        percentile NUMERIC(6,5),
        scored_at DATE,
        model_version VARCHAR(16)
    ) ON COMMIT DROP
"""
```

Functions to implement:

| Function | Responsibility |
| --- | --- |
| `fetch_epss_csv() -> bytes` | GET with `follow_redirects=True`, `raise_for_status()`, return `resp.content` |
| `parse_epss_csv(raw: bytes) -> tuple[list[dict], dict]` | `gzip.decompress`, split off the `#` metadata line, validate header, coerce floats; returns `(rows, meta)` |
| `parse_metadata_line(line: str) -> dict` | `#model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z` → `{"model_version": ..., "scored_at": date(...)}` |
| `upsert_scores(conn, rows, meta) -> dict[str, int]` | staging COPY + upsert; returns `{"new": n, "modified": n}` |
| `run() -> LoaderReport` | orchestrator entrypoint (§6) |

Parsing rules to bake in:

- Skip blank lines and any further `#` lines defensively.
- Skip rows whose `cve` is empty or whose `epss`/`percentile` don't parse as float — count them
  and report as `skipped` rather than aborting the run over one malformed line.
- **Deduplicate on `cve_id`, last-wins.** `ON CONFLICT` raises
  `cardinality_violation` ("ON CONFLICT DO UPDATE command cannot affect row a second time") if
  a single staged batch contains the same key twice. The feed shouldn't duplicate, but a
  one-line dedupe converts a hard ETL failure into a non-event.
- `scored_at` and `model_version` come from the metadata line and are **the same for every
  row** — attach them at upsert time rather than per row.

New/modified counts: the KEV loader gets these from `RETURNING (xmax = 0)`
([scripts/load_kev.py:101](scripts/load_kev.py:101)), which works because it upserts row by
row. With a bulk `INSERT ... SELECT`, use `RETURNING (xmax = 0) AS inserted` on the set-level
statement and aggregate the returned rows, or — simpler and cheaper — capture
`SELECT COUNT(*) FROM epss_scores` before and after and derive `new`, with `modified` as the
remainder. Either is fine; the count-delta version avoids materializing 353k RETURNING rows.

CLI: `uv run python scripts/load_epss.py`, plus `--dry-run` to fetch and parse without writing
(useful when the feed format changes upstream).

---

## 4. Agent surface — system prompt and MCP docstring

These two **must be edited together**; the MCP docstring says so explicitly
([mcp_server/server.py:80](mcp_server/server.py:80): "mirrors config.py's system prompt — keep
the two in sync").

**a. Add the table** to both schema blocks — `system_prompt` in
[config.py:62](config.py:62) and the `query` docstring in
[mcp_server/server.py:71](mcp_server/server.py:71):

```
TABLE: epss_scores (
  cve_id VARCHAR(20),
  probability NUMERIC(6,5),           -- 0–1, chance of exploitation in next 30 days
  percentile NUMERIC(6,5),            -- rank vs all scored CVEs
  scored_at DATE,                     -- date of this EPSS publication
  model_version VARCHAR(16),
  previous_probability NUMERIC(6,5),  -- prior publication's score (movement queries)
  previous_scored_at DATE
)
```

**b. Add an EPSS primer**, mirroring the existing SSVC primer at
[config.py:112](config.py:112). It needs to carry four things the model will otherwise get
wrong:

- EPSS = **likelihood**, CVSS = **severity**, KEV = **confirmed exploitation**, SSVC =
  **urgency decision**. Four different questions; rank with the right one.
- **Always `LEFT JOIN epss_scores`** — a missing row means *unscored*, not *zero risk*
  (~13k NVD CVEs have no EPSS row).
- EPSS is **highly skewed**: most CVEs sit below 0.01. Useful bands: `>= 0.5` high,
  `>= 0.1` elevated, `percentile >= 0.95` top-5%. Don't describe 0.05 as "low risk" without
  the percentile context.
- Scores are **daily**; cite `scored_at` when reporting a probability.

**c. Add example queries** — the ones that show off the join:

```sql
-- Leading indicator: likely-to-be-exploited but not yet KEV-listed
SELECT n.cve_id, n.cvss_v31_score, e.probability, e.percentile
FROM nvd_vulnerabilities n
JOIN epss_scores e ON e.cve_id = n.cve_id
LEFT JOIN kev_vulnerabilities k ON k.cve_id = n.cve_id
WHERE e.probability >= 0.5 AND k.cve_id IS NULL
ORDER BY e.probability DESC;

-- Severity/likelihood mismatch: scary-looking but unlikely
SELECT n.cve_id, n.cvss_v31_score, e.probability
FROM nvd_vulnerabilities n
LEFT JOIN epss_scores e ON e.cve_id = n.cve_id
WHERE n.cvss_v31_score >= 9.0 AND (e.probability < 0.01 OR e.probability IS NULL);

-- Biggest movers since the last EPSS publication
SELECT cve_id, previous_probability, probability,
       probability - previous_probability AS delta
FROM epss_scores
WHERE previous_probability IS NOT NULL
ORDER BY delta DESC LIMIT 20;
```

**d. Cross-signal guidance.** Worth one line: EPSS `>= 0.5` combined with
`ssvc_exploitation = 'active'` is the strongest available "patch now" signal, and disagreement
between them is itself informative.

---

## 5. What *not* to do: EPSS in embedded content

`build_content()` ([scripts/nvd_utils.py:191](scripts/nvd_utils.py:191)) feeds the embedding.
SSVC was added there because SSVC factors are **static**. EPSS must **not** go in, and the
reason should be recorded so it isn't "fixed" later: EPSS changes **daily for every CVE**, so
including it would invalidate all 353k embeddings every single day — a full re-embed and full
HNSW rebuild, daily, forever.

The `retrieve` path can still surface EPSS **at query time**, which is a Tier 2 enhancement:
[rag/vector_store.py:11](rag/vector_store.py:11) currently selects only `content`, so it would
need `cve_id` added to both arms of the `UNION ALL`, a `LEFT JOIN epss_scores` on the outer
query, and an appended `EPSS: 0.94 (98th percentile, as of 2026-07-28)` line per result. Cheap
(top-k is 5 rows) and it keeps the embedding untouched. Deferred — see §8.

---

## 6. ETL orchestration

Register the loader in `STEPS` at [scripts/run_etl.py:41](scripts/run_etl.py:41):

```python
STEPS: list[tuple[str, str]] = [
    ("NVD full incremental", "scripts.load_nvd_full:run_incremental"),
    ("KEV catalog", "scripts.load_kev:run"),
    ("EPSS scores", "scripts.load_epss:run"),
]
```

`run()` returns a `LoaderReport` ([scripts/etl_report.py](scripts/etl_report.py)) so the results
email and the `/etl-stats` page render real metrics:

```python
return LoaderReport(
    summary=f"Loaded {total} EPSS scores ({new} new, {modified} updated, scored {scored_at})",
    metrics={"fetched": total, "new": new, "modified": modified,
             "skipped": skipped, "loaded": total},
)
```

The orchestrator already runs every step regardless of another's failure and needs no changes
beyond the list entry. EPSS writes only `epss_scores`, so it is independent of the other two
and order doesn't matter — though putting it last keeps the NVD sync (the long pole) first.

The Container Apps job entrypoint is already `scripts/run_etl.py`
([infra/modules/etl-job.bicep:123](infra/modules/etl-job.bicep:123)), so **no infra change is
needed** — the new step ships with the image. Runtime cost is small: one ~2.4 MB download and
one bulk upsert, well under a minute.

> Daily-feed vs 12h-ETL note: at a ~12h cron the loader runs twice per publication. The §2
> delta guard makes the second run a no-op for movement tracking, and the upsert is otherwise
> idempotent, so this is harmless — just not useful. No scheduling change required.

---

## 7. Ordered implementation steps

1. **Schema.** Add `epss_scores` + index to `SCHEMA_SQL` in
   [rag/database.py](rag/database.py).
2. **Loader.** Write `scripts/load_epss.py` (§3) with `run() -> LoaderReport`.
3. **Unit tests.** `tests/unit/test_load_epss.py` (§9).
4. **Orchestrator.** Add the `STEPS` entry in [scripts/run_etl.py](scripts/run_etl.py).
5. **Agent surface.** System prompt + MCP docstring together (§4).
6. **Quick-query buttons.** Add 2–3 EPSS prompts to `ACTION_BUTTONS` in **all three** places
   they're defined — [.env.example:38](.env.example), [k8s/configmap.yaml:32](k8s/configmap.yaml),
   and [infra/modules/app-service.bicep:181](infra/modules/app-service.bicep). Suggested:
   *"High-EPSS CVEs not yet on KEV"*, *"CVSS 9+ but low exploitation likelihood"*,
   *"Biggest EPSS movers"*.

   > **Found during implementation:** the bicep also set `SYSTEM_PROMPT` to a hand-copied
   > duplicate of `config.py`'s prompt, and it had already gone stale — the SSVC columns and
   > primer never made it in, so the deployed Azure app could not answer its own SSVC buttons,
   > and EPSS would have landed the same way. **Resolved by deleting the override** (51 lines)
   > so Azure falls back to `config.py`, which is what `k8s/configmap.yaml` already does
   > deliberately. Azure App Service replaces the whole `appSettings` collection on deploy, so
   > the stale setting is removed on the next deploy with no manual step.
7. **Docs.** New `docs/epss-integration.md` modeled on
   [docs/cwe-integration.md](docs/cwe-integration.md); add rows to the loader table in
   [docs/data-loading.md:59](docs/data-loading.md) and the docs index
   [docs/README.md](docs/README.md); add the doc link to [CLAUDE.md](CLAUDE.md); update the
   grants table in [docs/supabase-readonly-role.md:8](docs/supabase-readonly-role.md).
8. **Production rollout.** §10.
9. **Cleanup.** Update the stale URL/row-count in
   [future-enhancements.md](future-enhancements.md#epss-score-ingestion) and mark the item
   done, pointing at this plan (same convention the SSVC entry uses).

Steps 1–7 are a single reviewable PR; step 8 is operational and follows the merge.

---

## 8. Deferred (explicitly out of scope)

| Item | Why deferred |
| --- | --- |
| `epss_scores_history` table | 129M rows/year; `previous_probability` covers the common "what moved" question at zero cost |
| EPSS in `retrieve` result cards | Needs the `vector_store.search` signature change in §5; independent follow-up, no schema impact |
| `risk_score()` composite tool | Its own project ([future-enhancements.md](future-enhancements.md#composite-risk-score-tool)); this plan is its prerequisite |
| EPSS-weighted retrieval ranking | Blending EPSS into vector distance needs evaluation against [eval-framework.md](eval-framework.md) first |

---

## 9. Testing

New `tests/unit/test_load_epss.py`, modeled on
[tests/unit/test_load_kev.py](tests/unit/test_load_kev.py) and
[tests/unit/test_extract_ssvc.py](tests/unit/test_extract_ssvc.py). No live-network tests — use
a small gzipped fixture built in-test from the verified sample in §1.

Parsing:
- Metadata line parsed → correct `model_version` and `scored_at`.
- **The `#` line is not mistaken for the header** — the highest-value regression test here.
- Header validation raises when columns are missing/renamed.
- Malformed rows (blank `cve`, non-numeric `epss`) are skipped and counted, not fatal.
- Duplicate `cve_id` in one file collapses last-wins.
- Values land as `Decimal`/float with 5-decimal fidelity (`0.03351` stays `0.03351`).

Upsert semantics (fake-conn style, as `test_load_kev.py` does):
- `new` vs `modified` counts.
- **Delta guard:** re-running with the *same* `scored_at` leaves `previous_probability`
  untouched; a *later* `scored_at` shifts it. This is the logic most likely to regress.

`run()` threads counts into both `summary` and `metrics` — mirroring
`test_run_reports_new_and_modified`.

Integration (optional, `tests/integration/`): load a handful of rows into a real Postgres and
assert the `LEFT JOIN` against `nvd_vulnerabilities` returns unscored CVEs with `NULL`
probability rather than dropping them.

---

## 10. Production rollout

Same constraints the SSVC rollout documented the hard way
([ssvc-affected-integration.md](ssvc-affected-integration.md) §4) — reuse them, don't rediscover.

**a. Apply DDL manually.** Production runs `DB_INIT_SCHEMA=false` (read-only app role, no DDL),
and the loaders connect with a plain `asyncpg.connect` that never applies `SCHEMA_SQL` — only
`init_db()` does. So `epss_scores` will **not** exist just because it's in `SCHEMA_SQL`; the
first ETL run would fail on a missing relation. Apply it once with the **admin** role over the
**pooled** host (the direct `db.<ref>.supabase.co` host is IPv6-only), using plain `psql` rather
than `init_db()` (asyncpg prepared statements break on the transaction pooler), and plain
`CREATE INDEX` rather than `CONCURRENTLY` (which can't run in a pooled transaction):

```bash
psql "<admin-pooled-supabase-dsn>" <<'SQL'
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id               VARCHAR(20) PRIMARY KEY,
    probability          NUMERIC(6,5) NOT NULL,
    percentile           NUMERIC(6,5) NOT NULL,
    scored_at            DATE NOT NULL,
    model_version        VARCHAR(16),
    previous_probability NUMERIC(6,5),
    previous_scored_at   DATE
);
CREATE INDEX IF NOT EXISTS epss_probability_idx ON epss_scores (probability DESC);
SQL
```

**b. Grant access — this is the step that will bite.** The project splits roles and
[docs/supabase-readonly-role.md:52](docs/supabase-readonly-role.md) is explicit that grants are
per-table with **no wildcard**: *"Any new table added later requires an explicit grant."* Without
these, the ETL fails on write and the app returns permission errors on every EPSS query:

```sql
GRANT SELECT ON epss_scores TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON epss_scores TO app_etl;
```

No sequence grant is needed — `cve_id` is the PK and there's no `SERIAL` (§2). If RLS is ever
enabled, `epss_scores` also needs an `app_readonly_select` policy like the other tables
([docs/supabase-readonly-role.md:65](docs/supabase-readonly-role.md)).

The loader's temp staging table needs `TEMP` on the database, which Postgres grants to `PUBLIC`
by default — no action expected, but it's the thing to check first if the COPY fails.

**c. First load.** Run manually before letting the schedule pick it up:

```bash
uv run python scripts/load_epss.py
```

Expect ~353k rows in well under a minute. No HNSW involvement, no compute bump, and **no need
to suspend the scheduled ETL job** — unlike the SSVC storm sync, this touches a new table that
nothing else writes.

**d. Verify.**

```sql
-- Row count and freshness
SELECT COUNT(*), MIN(scored_at), MAX(scored_at), MAX(model_version) FROM epss_scores;

-- Known-high CVE: Log4Shell should be ~0.99999 at ~1.0 percentile
SELECT * FROM epss_scores WHERE cve_id = 'CVE-2021-44228';

-- Join coverage — how many NVD CVEs are unscored (expect a nonzero remainder)
SELECT COUNT(*) FILTER (WHERE e.cve_id IS NULL) AS unscored, COUNT(*) AS total
FROM nvd_vulnerabilities n LEFT JOIN epss_scores e ON e.cve_id = n.cve_id;

-- The flagship query returns sensible rows
SELECT n.cve_id, n.cvss_v31_score, e.probability
FROM nvd_vulnerabilities n
JOIN epss_scores e ON e.cve_id = n.cve_id
LEFT JOIN kev_vulnerabilities k ON k.cve_id = n.cve_id
WHERE e.probability >= 0.5 AND k.cve_id IS NULL
ORDER BY e.probability DESC LIMIT 10;
```

**e. Confirm the second run** (next scheduled ETL) leaves `previous_probability` NULL until the
feed's `scored_at` advances, then populates it the following day.

---

## Open questions

1. **Column naming — `probability` or `epss_score`?** *Recommend `probability`.* Qualified as
   `epss_scores.probability` it reads correctly in SQL, and `epss_scores.epss_score` stutters.
   The CSV's `epss` column maps to it in the loader. Low cost to change before the first load,
   high cost after (it lands in the system prompt, MCP docstring, and docs).
2. **Full history table.** Deferred (§8). Revisit only if trend questions turn out to be common
   in real usage; if so, prefer a **weekly** snapshot or a changed-rows-only table over a daily
   full copy.
3. **Should low-EPSS CVEs be filtered at load?** *Recommend no.* Storing all 353k is cheap and
   the "CVSS 9.8 / EPSS 0.001" mismatch query is one of the most useful — it needs the low
   scores present.
4. **`retrieve` surfacing (§5).** Worth doing, but as a separate PR so the vector-store change
   can be evaluated on its own.
