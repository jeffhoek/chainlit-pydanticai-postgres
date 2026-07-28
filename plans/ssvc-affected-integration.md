# SSVC + CVE Affected Data Integration

Plan to account for the NVD changes announced **2026-05-28** and deployed **2026-06-17**.

## What changed at NVD

Two announcements on the [NVD home page](https://www.nist.gov/itl/nvd):

- **May 28, 2026 — "NVD Will Now Include SSVC and Affected Data Within the CVE Feed and CVE API Results."** Pre-announced that NVD would add CISA-ADP **SSVC** (Stakeholder-Specific Vulnerability Categorization) data and CVE-Record-Format **affected** data to feeds and the API. Deployment window: June 16, 2026 20:00–24:00 EDT.
- **June 17, 2026 — "SSVC and CVE Affected Data Now Available."** Deployment done. SSVC via schema **v2.0.3**, affected via **CVE Affected v1.0**. **~95% of all existing CVE records were modified**, each gaining a new changelog entry and an updated `lastModified` timestamp. The CVE-Modified feed file size is elevated **for 8 days**, and **increased API latency** is expected during the refresh (matches the latency we've been hitting for 2 days).

### Verified JSON shape (live `CVE-2021-44228`)

SSVC is nested **under `metrics`**, not a top-level field (the published docs summary is misleading on this):

```jsonc
cve.metrics.ssvcV203 = [
  {
    "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",   // CISA-ADP UUID
    "ssvcData": {
      "timestamp": "2025-02-04T14:25:34.416117Z",
      "id": "CVE-2021-44228",
      "options": [
        { "exploitation": "active" },      // none | poc | active
        { "automatable": "yes" },          // yes | no
        { "technicalImpact": "total" }     // partial | total
      ],
      "role": "CISA Coordinator",
      "version": "2.0.3"
    }
  }
]
```

`affected` is a **top-level** field on the `cve` object (richer than the CPE-based `configurations`):

```jsonc
cve.affected = [
  {
    "source": "security@apache.org",
    "affectedData": [
      {
        "vendor": "Apache Software Foundation",
        "product": "Apache Log4j2",
        "versions": [
          { "version": "2.0-beta9", "lessThan": "log4j-core*", "versionType": "custom",
            "status": "affected",
            "changes": [ { "at": "2.3.1", "status": "unaffected" }, ... ] }
        ]
      }
    ]
  }
]
```

> Note: the sample `options` array carries only the three decision **factors** — no rolled-up CISA decision outcome (`Act` / `Attend` / `Track` / `Track*`). We either derive it from the CISA SSVC tree or leave it NULL. See Open Questions.

### Why both blocks, and why we treat them differently

The two blocks shipped in the same deployment but answer **different questions**, and neither replaces the other:

| | `metrics.ssvcV203` (SSVC) | `cve.affected` (Affected) |
| --- | --- | --- |
| Question it answers | *How urgently should I act?* | *Does this apply to me, and what do I patch?* |
| Nature | Prioritization / triage signal | Scope / inventory data |
| Content | 3 CISA decision factors (exploitation, automatable, technicalImpact) | Per-vendor/product/version ranges, affected vs. fixed |
| Source | CISA-ADP (coordinator enrichment) | The CNA (e.g. `security@apache.org`) |
| Cardinality | Tiny fixed enums → good as typed columns | Rich/nested/variable → stays in `raw_json` for now |
| Vs. existing data | Complements CVSS (severity ≠ priority) | Richer than CPE-based `configurations` / `affected_products` |

In short: **SSVC tells you whether to drop everything; Affected tells you which systems are actually in scope.** A CVE can be CVSS 10.0 with `exploitation=none` (don't panic yet) or moderate CVSS with `exploitation=active, automatable=yes` (patch now); and SSVC is moot if Affected says you don't run the impacted version. That difference in shape and purpose is why SSVC factors are promoted to typed columns (Tier 1) while `affected` stays in `raw_json` + searchable `content` (Tier 2 deferred).

## Key insight: storage already works

`nvd_vulnerabilities.raw_json` (JSONB) stores the **entire** `cve` object ([rag/database.py:46](rag/database.py:46), upserts in [scripts/load_nvd.py:164](scripts/load_nvd.py:164) and [scripts/load_nvd_full.py:252](scripts/load_nvd_full.py:252)). So **the next incremental sync automatically captures SSVC + affected into `raw_json`** with zero schema changes — the agent can already reach it via `raw_json->'metrics'->'ssvcV203'` / `raw_json->'affected'`.

That makes this a layered effort:

- **Tier 0 (no code):** re-sync, then teach the system prompt the JSONB paths. Minimum viable SSVC support.
- **Tier 1 (recommended):** promote the low-cardinality SSVC factors to typed columns for clean filtering/aggregation, and surface SSVC + affected vendor/product in the embedded `content`.
- **Tier 2 (later):** promote `affected` vendor/product/version ranges to structured columns.

---

## 1. Data model changes

Add SSVC factor columns to `nvd_vulnerabilities` (low cardinality → cheap to index and aggregate). Keep `affected` in `raw_json` for now.

```sql
-- in SCHEMA_SQL (rag/database.py), follow the existing
-- "ADD COLUMN IF NOT EXISTS" migration pattern used for raw_json
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_exploitation     VARCHAR(8);   -- none|poc|active
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_automatable      VARCHAR(4);   -- yes|no
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_technical_impact VARCHAR(8);   -- partial|total
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision         VARCHAR(8);   -- Act|Attend|Track|Track* (nullable)
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_version          VARCHAR(8);   -- "2.0.3"

CREATE INDEX IF NOT EXISTS nvd_ssvc_exploitation_idx ON nvd_vulnerabilities (ssvc_exploitation);
CREATE INDEX IF NOT EXISTS nvd_ssvc_decision_idx     ON nvd_vulnerabilities (ssvc_decision);
```

Also mirror these columns in the `_nvd_staging` temp table and `STAGING_COLUMNS`/upsert lists in [scripts/load_nvd_full.py:75](scripts/load_nvd_full.py:75).

**Backfill without re-fetching:** for records already synced post-June-17, `raw_json` already holds SSVC, so columns can be filled with a pure-SQL UPDATE (no NVD API calls):

```sql
UPDATE nvd_vulnerabilities SET
  ssvc_exploitation     = raw_json#>>'{metrics,ssvcV203,0,ssvcData,options}' ... -- see note
WHERE raw_json->'metrics' ? 'ssvcV203';
```

The `options` array-of-singletons shape makes the jsonb path awkward in SQL; simplest is to backfill in Python via the same `extract_ssvc()` helper reading `raw_json`. Provide a small `--backfill-ssvc` mode (analogous to `--backfill-embeddings`) that selects rows where `raw_json ? ...` and updates the five columns.

## 2. ETL changes

**`scripts/nvd_utils.py`** — add an extractor (with a unit-test fixture from the verified sample above):

```python
def extract_ssvc(metrics: dict) -> dict:
    """Flatten cisa-adp SSVC v2.0.3 options into a dict of factor->value."""
    for entry in metrics.get("ssvcV203", []):
        data = entry.get("ssvcData", {})
        opts = {}
        for o in data.get("options", []):
            opts.update(o)            # each option is a single-key dict
        return {
            "exploitation": opts.get("exploitation"),
            "automatable": opts.get("automatable"),
            "technical_impact": opts.get("technicalImpact"),
            "decision": opts.get("decision"),   # usually absent today
            "version": data.get("version"),
        }
    return {}
```

- Wire `extract_ssvc()` into `build_upsert_params()` ([scripts/load_nvd.py:145](scripts/load_nvd.py:145)) and `_prepare_row()` ([scripts/load_nvd_full.py:214](scripts/load_nvd_full.py:214)); extend both UPSERT statements and `STAGING_COLUMNS`.
- **`build_content()`** ([scripts/nvd_utils.py:147](scripts/nvd_utils.py:147)): append SSVC factors and `affected` vendor/product names so semantic search surfaces them, e.g. `SSVC: exploitation=active, automatable=yes, technicalImpact=total` and `Affected: Apache Software Foundation Apache Log4j2`. This changes embedding inputs — see operational note on re-embedding.

> **Wiring `load_nvd_full.py` is six coordinated edits, not one.** The column lists are order-sensitive across six spots that must all stay aligned, or a bulk insert will silently shift values between columns:
> 1. `STAGING_COLUMNS` list ([scripts/load_nvd_full.py:80](scripts/load_nvd_full.py:80))
> 2. `CREATE_STAGING_SQL` temp-table DDL ([scripts/load_nvd_full.py:98](scripts/load_nvd_full.py:98))
> 3. `UPSERT_FROM_STAGING_SQL` — the `INSERT (…)` column list ([scripts/load_nvd_full.py:118](scripts/load_nvd_full.py:118))
> 4. same statement — the `SELECT …` column list
> 5. same statement — the `ON CONFLICT DO UPDATE SET` assignments
> 6. `_prepare_row()` return tuple ([scripts/load_nvd_full.py:214](scripts/load_nvd_full.py:214))
>
> Append the five SSVC columns in the **same order** in all six. `load_nvd.py` is the smaller sibling: `build_upsert_params()` tuple + the single `UPSERT_SQL` string. Do both loaders in one pass, or column sets drift between them depending on which one ran.

Optionally add an `extract_affected_named(cve.affected)` helper now (vendor/product strings) just for `build_content`, deferring dedicated columns to Tier 2.

## 3. System prompt changes

In `config.py` `system_prompt` ([config.py:56](config.py:56)):

- Add the new columns to the `nvd_vulnerabilities` schema block.
- Add an **SSVC primer** so the model interprets it correctly:
  - SSVC is CISA's decision framework that complements CVSS for *prioritization*.
  - `ssvc_exploitation` none|poc|active; `ssvc_automatable` yes|no; `ssvc_technical_impact` partial|total; `ssvc_decision` (when present) Act > Attend > Track in urgency.
  - KEV-listed CVEs are typically `ssvc_exploitation = 'active'`.
- Note that richer per-version affected data lives in `raw_json->'affected'` (vendor/product/version ranges), distinct from the CPE list in `affected_products`.
- Add 1–2 example queries (e.g. "count CVEs by ssvc_exploitation", "active + automatable + total technical impact = top remediation priority").

Update [docs/nvd-integration.md](docs/nvd-integration.md) to document the new columns and JSONB paths.

## 4. Operational plan for the re-sync (the latency / ETL-completion problem)

The June-17 storm modified ~95% of records, so a normal incremental run's **Phase 2** ([scripts/load_nvd_full.py:533](scripts/load_nvd_full.py:533)) will try to re-pull ~all CVEs while the API is degraded and the modified feed is oversized (through ~June 25).

**Prerequisite — the five SSVC columns must exist in the target database before the ETL runs.** The upserts now reference `ssvc_exploitation … ssvc_version`, so a sync against a database that lacks them will error. The columns ship in `SCHEMA_SQL` ([rag/database.py](rag/database.py)), but the loaders connect with a plain `asyncpg.connect` and do **not** apply `SCHEMA_SQL` (only `init_db()` does), and the production app runs `DB_INIT_SCHEMA=false` (read-only role, no DDL — see [docs/supabase-readonly-role.md](docs/supabase-readonly-role.md)). So apply the migration once with the **admin** connection before starting, and confirm:

```bash
psql "$ADMIN_DATABASE_URL" -c "\d nvd_vulnerabilities" | grep ssvc_   # expect 5 rows
```

**Applying the schema to Supabase (prod) — use the *pooled* connection, and `psql`, not `init_db()`.** Hard-won specifics:

- **Direct connection (`db.<ref>.supabase.co:5432`) is IPv6-only** unless you buy the IPv4 add-on. On an IPv4-only network it simply won't connect — this is expected, not a misconfig. Use the **pooler** hostname (`aws-0-<region>.pooler.supabase.com`), which is what worked in practice.
- **Prefer raw `psql` DDL over `init_db()`.** `init_db()` uses asyncpg, whose prepared statements break over the pgBouncer **transaction** pooler (`:6543`) with "prepared statement already exists". Plain idempotent `ALTER`/`CREATE INDEX` statements via `psql` are pooler-safe in either mode. (`init_db()` only works cleanly over the **session** pooler, `:5432` on the pooler host, or a direct connection.)
- Use plain `CREATE INDEX IF NOT EXISTS` (as below), **not** `CREATE INDEX CONCURRENTLY` — the latter can't run in a transaction and chokes on the transaction pooler. These columns are tiny/low-cardinality, so a non-concurrent build is a quick lock.
- Run with the **admin/DDL role** (independent of direct-vs-pooled). Applied 2026-07-27.

```bash
psql "<admin-pooled-supabase-dsn>" <<'SQL'
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_exploitation     VARCHAR(8);
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_automatable      VARCHAR(4);
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_technical_impact VARCHAR(8);
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision         VARCHAR(8);
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_version          VARCHAR(8);
CREATE INDEX IF NOT EXISTS nvd_ssvc_exploitation_idx ON nvd_vulnerabilities (ssvc_exploitation);
CREATE INDEX IF NOT EXISTS nvd_ssvc_decision_idx     ON nvd_vulnerabilities (ssvc_decision);
SQL
```

Recommended sequence:

1. ~~**Deploy the exponential-backoff PR first.**~~ **Done — merged in [PR #93](https://github.com/jeffhoek/vulncopilot/pull/93).** This replaced the old fixed 10–30s retry sleeps ([scripts/load_nvd_full.py:199](scripts/load_nvd_full.py:199)) that stalled under sustained latency. Prerequisite for finishing the storm sync — satisfied.
2. **Disable the scheduled Azure ETL job for the duration of the storm sync**, then run the manual catch-up from the laptop with `caffeinate -i`. The storm sync doesn't need to be *fast* — it needs to not **collide** with the automated run. The scheduled Container Apps Job ([infra/modules/etl-job.bicep:82](infra/modules/etl-job.bicep:82), `Schedule` trigger) fires on `etlCronExpression`; the bicep default is weekly (`0 6 * * 1`) but the **deployed** value is currently ~every 12h (overridden via deploy var). Suspend/disable that job before starting and re-enable when done — so a manual run that overruns the 12h window won't overlap a scheduled one.
   - This makes a **second API key unnecessary** — throughput stops mattering once nothing is racing the sync. (For the record: NVD ties a key to one email and re-requesting with the same email invalidates the first, and NVD doesn't document whether the 50-req/30s limit is per-key or per-IP — so a second key from the same laptop might give zero gain anyway. Not worth pursuing.)
   - **Disable / re-enable commands** (Container Apps Jobs have no "pause schedule" flag — point the cron at a date that never occurs, then restore it):

     ```bash
     # Identify the job + its resource group
     az containerapp job list -o table          # note the ETL job name + RG
     RG=<resource-group>
     JOB=<etl-job-name>

     # 1. RECORD the current cron first — the live value is overridden (~12h),
     #    NOT the bicep weekly default, so capture it to restore exactly.
     az containerapp job show -g "$RG" -n "$JOB" \
       --query "properties.configuration.scheduleTriggerConfig.cronExpression" -o tsv

     # 2. DISABLE — "Feb 31" never exists, so the trigger never fires.
     az containerapp job update -g "$RG" -n "$JOB" --cron-expression "0 0 31 2 *"

     # 3. RE-ENABLE — restore the value recorded in step 1 (example: every 12h).
     az containerapp job update -g "$RG" -n "$JOB" --cron-expression "0 */12 * * *"
     ```

     Updating the cron does not interrupt a run already in flight, and leaves the job (image, identity, env) otherwise untouched.
3. Run the storm sync **`--skip-embeddings`** first: `--incremental --since 2026-06-15 --skip-embeddings`. Gets SSVC/affected into `raw_json` fast and cheaply; ~275k embeddings during a degraded window is the wrong time to pay that cost.
4. **`--backfill-ssvc`** (new mode) to populate the five SSVC columns from `raw_json` — pure SQL/Python, no API.
5. **Verify, then re-enable the scheduled job.** Confirm the columns populated, then restore the cron from step 2's RE-ENABLE command (do not leave the job disabled):

   ```sql
   -- distribution across the decision factor (expect none/poc/active buckets)
   SELECT ssvc_exploitation, COUNT(*) FROM nvd_vulnerabilities GROUP BY 1 ORDER BY 2 DESC;
   -- a known KEV CVE should read 'active'
   SELECT cve_id, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact
   FROM nvd_vulnerabilities WHERE cve_id = 'CVE-2021-44228';
   ```

6. Optional **targeted re-embed** later: the `content` change is additive, so stale embeddings remain usable. If desired, a `--reembed-since` mode can refresh only storm-touched rows (the existing `--backfill-embeddings` only fills NULLs, so it won't refresh changed content — a new mode is needed).

> Embedding-refresh nuance: the upsert sets `embedding = COALESCE(EXCLUDED.embedding, existing)` ([scripts/load_nvd_full.py:140](scripts/load_nvd_full.py:140)), so running incremental *with* embeddings would overwrite them — correct but expensive at storm scale. Hence the skip-then-backfill split above.

## 5. Sequencing & testing

1. Schema migration + `extract_ssvc` + unit test against the verified fixture.
2. Wire ETL upserts (both loaders) + `build_content` update. **See the six-edit note in §2 — `load_nvd_full.py` alone is six column-order-aligned spots; do both loaders in one pass to avoid column drift.**
3. `--backfill-ssvc` mode.
4. System prompt + docs.
5. Operational re-sync per section 4.

Tests: extend [tests/unit](tests/unit) with `extract_ssvc` cases (active record, record with no SSVC, malformed options). No live-API tests.

## Open questions (resolved)

1. **SSVC decision outcome** — **Decided: leave `ssvc_decision` NULL for now.** Don't derive `Act/Attend/Track` from the CISA tree yet; populate it if/when NVD publishes the rolled-up decision. Deriving from the tree is a separate, well-scoped follow-up.
2. **Promote `affected` to columns (Tier 2)** — **Decided: defer.** Keep `affected` in `raw_json` and surface vendor/product in `content`; revisit dedicated columns later.
3. **Refresh embeddings for storm-touched records** — **Decided: defer.** Accept slightly stale embeddings; the `content` change is additive so existing vectors stay usable. Optional `--reembed-since` pass later if needed.
