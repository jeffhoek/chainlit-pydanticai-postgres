# Composite Risk Score

## Overview

Four prioritization signals live in the database, and each answers a different question. The
composite risk score blends them into one 0–100 number so *"what do I patch first?"* is a single
`ORDER BY` rather than a bespoke four-way JOIN with a ranking invented per question.

| Signal | Question | Weight |
| --- | --- | --- |
| CVSS base score | How bad is it if exploited? | 0.25 |
| EPSS probability | How likely is exploitation soon? | 0.30 |
| KEV listing | Confirmed exploited right now? | 0.20 |
| KEV ransomware flag | Used in ransomware campaigns? | 0.10 |
| SSVC factors | How urgently should a coordinator act? | up to 0.10 |
| CWE weakness class | What kind of weakness is it? | 0.05 |

CWE is an input but not a fifth *signal*: it says what kind of weakness this is, not how urgent it
is. It carries the smallest weight and acts as a tiebreaker between CVEs the four signals rate
equally.

The weights sum to exactly 1.00 at maximum, asserted at import time in
[rag/risk.py](../rag/risk.py) — a weight edit that breaks the invariant crashes the app rather than
silently emitting scores above 100.

Two surfaces:

- **`v_cve_risk`** — a SQL view, one row per CVE in NVD or KEV, for ranking, filtering, counting.
- **`risk_score`** — an agent tool (and MCP tool) taking up to 25 CVE IDs, returning the score,
  band, per-signal breakdown, and a prose rationale.

## Why a view, not prompt guidance

`validate_sql` ([rag/sql_utils.py](../rag/sql_utils.py)) rejects anything not starting with
`SELECT`, so the agent **cannot write a `WITH ... SELECT` CTE at all**. Any multi-signal ranking it
composes has to be a single flat SELECT with repeated inline arithmetic — inconsistent between
turns and unauditable. `v_cve_risk` turns that into:

```sql
SELECT cve_id, risk_score FROM v_cve_risk ORDER BY risk_score DESC;
```

## One source of truth

The obvious implementation — a SQL view plus a Python function that blends the same inputs — is
two independent implementations of the same arithmetic, and they drift. A weight tweak in Python
leaves the view returning a different number for the same CVE, and CI never notices because the
Python function still passes its own unit tests.

Instead:

- **[rag/risk.py](../rag/risk.py) owns the constants** — weights, the CWE class map, band
  cut-points, the missing-CVSS prior.
- **It generates the SQL** from those constants: `score_expression()` and `view_ddl()`.
- **The arithmetic runs exactly once, in Postgres.** The `risk_score` tool selects from
  `v_cve_risk` and reads back the component columns; it does no blending of its own.
- **Python owns the prose** — band naming and the `rationale` string, which has no SQL counterpart
  to drift from.

`rag/risk.py` imports nothing from `rag/database.py`; the dependency runs the other way so
`init_db()` can apply the generated DDL. The CWE class map is emitted as an inline `VALUES` list
inside the view, which avoids a new table, a new loader, and two new grants.

## The `v_cve_risk` view

### Columns

| Column | Notes |
| --- | --- |
| `cve_id` | |
| `risk_score` | `NUMERIC(4,1)`, 0–100 |
| `c_cvss`, `c_epss`, `c_kev`, `c_ransomware`, `c_ssvc`, `c_cwe` | Weighted contributions, 0–1. Sum × 100 = `risk_score` |
| `cvss_score` | `COALESCE(cvss_v31_score, cvss_v2_score)` |
| `cvss_imputed` | `TRUE` when neither CVSS version exists and the neutral prior was used |
| `epss_probability`, `epss_percentile`, `epss_scored_at` | NULL when the CVE has no EPSS row |
| `epss_previous_probability`, `epss_previous_scored_at` | For movement queries |
| `kev_listed`, `kev_date_added`, `known_ransomware_campaign_use` | |
| `ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact` | |
| `cwe_top` | Highest-severity rated CWE for this CVE; NULL when none are rated |

The component columns are what make the score defensible: `risk_score` alone is a black box,
`risk_score` beside its six contributions is an argument. They also let the `query` tool answer
"why is this ranked here?" without calling `risk_score` at all.

### The CVE universe is a union

The view is based on the **union of NVD and KEV CVE IDs**, and every join off it is a `LEFT JOIN`.

In production today all KEV CVEs are present in NVD, so the union costs a `UNION` and buys nothing.
It is a cheap guard against a case that would be maximally damaging if it ever occurred — a KEV
entry invisible to the ranking is the worst possible omission for a tool whose job is deciding what
to patch first — and the loaders are independent, so nothing structurally guarantees containment
holds.

### CWEs are concatenated, not coalesced

`kev_vulnerabilities` carries its own `cwes TEXT[]` independent of NVD's, and the two disagree in a
way that matters: roughly **93 KEV CVEs have NVD `cwes` consisting only of `NVD-CWE-*` placeholders
while KEV holds real weakness IDs**. Reading only `n.cwes` sends all of them to the neutral
default despite the data being right there — and these are KEV rows, the highest-value records in
the corpus.

`COALESCE(n.cwes, k.cwes)` does **not** fix this: no KEV row has an *empty* NVD array, so the
coalesce never fires. It just contains nothing useful. The view concatenates instead:

```sql
unnest(COALESCE(n.cwes, '{}'::text[]) || COALESCE(k.cwes, '{}'::text[]))
```

Concatenating is safe precisely because highest-severity-member-wins is already the rule — merging
can only raise the component when one source knows something the other doesn't, never lower it.

## Missing-signal policy

Absent signals are where a scoring model quietly goes wrong, and the three cases are *not* the same:

| Missing | Contributes | Why |
| --- | --- | --- |
| EPSS row (~4.8% of the corpus) | **0** | `LEFT JOIN` always. A missing row means unscored, and the score must never come back NULL because one signal is absent. |
| SSVC factors (~54.5%) | **0** | Additive-when-present. Over half the corpus lacks SSVC entirely, so a multiplier or penalty would distort the majority of rows. |
| CVSS, both versions NULL (~6.9%) | **neutral prior 5.0/10 → 0.125** | *Not* zero. See below. |
| CWE (empty, or only `NVD-CWE-*`) | **neutral 0.5 → 0.025** | Placeholders carry no severity information; the midpoint neither rewards nor punishes. |

CVSS is the one deviation from "missing = 0", and production data makes the argument concrete:
**40% of the rows with no CVSS were published in 2025 or later.** NULL CVSS means *not yet
assessed*, and unassessed CVEs skew heavily toward the newest records — exactly the ones an analyst
most wants surfaced. Scoring them at zero would rank a brand-new CVE carrying EPSS ≥ 0.1 below a
fully-assessed CVSS 4.0 with EPSS 0.0001.

So the view imputes the corpus-neutral 5.0 and **makes the imputation visible**: `cvss_imputed` is
a view column, and the tool's rationale says *"CVSS unassessed — scored at the neutral 5.0 prior"*.
A number that silently invents an input is worse than no number; a number that says which input it
invented is fine. Bulk queries that need precision can filter with `WHERE NOT cvss_imputed`.

## CWE class severity

A static map from CWE ID to a 0–1 class severity, weighted 0.05, deliberately small — the CWEs that
actually appear at volume, everything else neutral:

| Class | Severity | CWEs |
| --- | --- | --- |
| Memory corruption | 1.0 | CWE-787, CWE-119, CWE-125, CWE-416, CWE-120, CWE-121, CWE-122, CWE-190 |
| Injection / code execution | 1.0 | CWE-89, CWE-78, CWE-94, CWE-74, CWE-434, CWE-77, CWE-502 |
| Access control / traversal | 0.8 | CWE-22, CWE-862, CWE-284, CWE-863, CWE-269, CWE-59 |
| Authentication bypass | 0.8 | CWE-287, CWE-306, CWE-288 |
| Request forgery / XSS | 0.6 | CWE-352, CWE-918, CWE-79 |
| Information disclosure | 0.4 | CWE-200, CWE-203 |
| DoS / resource exhaustion | 0.3 | CWE-400, CWE-476 |
| Everything else, incl. `NVD-CWE-noinfo`, `NVD-CWE-Other`, CWE-20, CWE-264 | 0.5 | — |

Three notes:

- **CWE-79 (XSS) is the single most common CWE in the corpus**, roughly 14% of NVD rows. Placing it
  at 0.6 rather than 1.0 is a high-leverage choice, not a footnote: it is what stops the most common
  weakness class from inflating a seventh of the corpus.
- **CWE-20 and CWE-264 stay neutral.** Both are Class-level catch-alls (Improper Input Validation;
  Permissions/Privileges/Access Controls) spanning everything from XSS to RCE. A severity tier for
  either would be noise dressed as signal.
- The map keys off the `cwes TEXT[]` columns directly rather than joining `cwe_definitions`, so it
  behaves identically in production and in a dev database where `load_cwe.py` was never run.
  **Highest-severity member wins** when a CVE lists several CWEs — Log4Shell (`CWE-20`, `CWE-400`,
  `CWE-502`, `CWE-917`) resolves to 1.0 via CWE-502.

## Bands

| Band | Range | Meaning |
| --- | --- | --- |
| low | 0–24 | Background noise |
| moderate | 25–44 | Worth tracking |
| high | 45–64 | Reachable without KEV: high CVSS **and** genuine exploitation likelihood, or KEV with a modest CVSS |
| critical | 65–100 | Effectively requires confirmed exploitation |

These are calibrated against the production corpus, not chosen for roundness. The obvious
70/85 cut-points are **unreachable off KEV**: `c_kev` and `c_ransomware` are both gated on a KEV
row existing, and `ssvc_exploitation='active'` is functionally an alias for KEV listing (the two
sets differ by ~6 rows out of 371k), so that bonus is effectively KEV-gated too. A non-KEV CVE is
therefore capped at **64** — CVSS 10.0 with EPSS 0.99999, automatable, total impact, and a
top-tier CWE still only reaches 64, and the measured maximum is 63.5. Under 70/85 bands the
flagship query this work exists for, *"high-EPSS CVEs that aren't on KEV yet"*, would return CVEs
labelled "moderate", which is precisely the wrong signal.

The handful of CVEs carrying `active` *without* a KEV listing are the one exception — they can add
0.06 the rest cannot, reaching 70. See
[Re-verify the band calibration](#re-verify-the-band-calibration) for why that population is the
thing worth monitoring rather than the maximum itself.

Measured against the deployed view on 2026-08-01, 372,463 rows:

| Band | Rows | Share | KEV | non-KEV |
| --- | --- | --- | --- | --- |
| low 0–24 | 282,227 | 75.77% | 0 | 282,227 |
| moderate 25–44 | 86,732 | 23.29% | 41 | 86,691 |
| high 45–64 | 2,533 | 0.68% | 644 | **1,889** |
| critical 65+ | 971 | 0.26% | 971 | 0 |

A clean pyramid; "critical" is 0.26% of the corpus and means confirmed exploitation; and 1,889
non-KEV CVEs reach "high" — the early-warning population the naive bands rendered invisible. No KEV
CVE falls into "low", and only 41 sit in "moderate".

Mean weighted contribution per component over the same run, useful as a wiring check — each of
these is independently derivable from the source distributions:

| `c_cvss` | `c_epss` | `c_kev` | `c_ransomware` | `c_ssvc` | `c_cwe` |
| --- | --- | --- | --- | --- | --- |
| 0.1623 | 0.0082 | 0.0009 | 0.0001 | 0.0055 | 0.0335 |

`c_cvss` implies a mean input of 6.49, which is exactly `0.931 × 6.60 + 0.069 × 5.0` — the measured
mean CVSS blended with the imputed prior at its measured frequency. `c_ssvc` reconstructs as
`(1,655 × 0.06 + 38,769 × 0.02 + 57,553 × 0.02) / 371,323 = 0.00546` from the three factor
populations. `c_cwe` implies a mean class severity of 0.67 — not flat at the 0.5 neutral default,
so the map is matching; not near 1.0, so it isn't over-rating.

> **These figures supersede the pre-ship estimates** in
> [plans/composite-risk-score.md](../plans/composite-risk-score.md) §3.4, which were simulated with
> an inline query rather than the shipped view. That simulation scored an unrated CWE at 0 instead
> of the neutral 0.025 the model specifies, which put roughly half the corpus about 1.3 points low
> and is why the plan reports a maximum of 97.5 where the view returns 100.0. The band *shares* are
> unaffected — the offset was near-uniform and the bands are wide relative to it — so the
> cut-points did not need re-cutting.

### KEV's effective weight is 0.36, deliberately

Because `ssvc_exploitation='active'` is a KEV alias, KEV's real weight is `0.20` (nominal) + `0.06`
(SSVC exploitation, KEV-implied) + `0.10` (ransomware, a KEV-only column) = **0.36** — more than
CVSS and more than EPSS.

That is the right doctrine: confirmed in-the-wild exploitation *should* dominate a remediation
ranking, which is why "critical" is a KEV-only band and why that isn't a defect. It is recorded
here because a future reader comparing the weight table to the correlation will see double-counting
and be tempted to drop the SSVC exploitation term. Dropping it lowers every KEV row by 6 and
changes nothing about ordering *within* KEV — nearly a no-op, which is itself the argument for
leaving it alone rather than churning the bands.

The other two SSVC factors *are* independent (13,338 non-active CVEs carry `automatable=yes` AND
`technical_impact=total`) and are what let a non-KEV CVE climb into the high band.

## The `risk_score` tool

```
risk_score(cve_ids: list[str]) -> list[RiskScore] | str
```

A list rather than a single ID: the dominant real question is *"rank these"*, and a singular tool
forces the agent into 20 serial round trips for a 20-CVE list — 20× the latency and 20× the
tool-call tokens, against a query that costs the same as one. A single-element list covers the
singular case at no cost. Capped at 25, results ranked highest-risk first.

Each entry carries `score` (0–100 int), `band`, `components` (the six weighted contributions), and
`rationale` — clauses ranked by contribution, e.g.:

> Critical (100). Listed in KEV since 2021-12-10 with known ransomware campaign use (+30). EPSS
> 0.99999 (100th percentile, as of 2026-07-29) (+30). CVSS 10.0 (+25). SSVC exploitation=active,
> automatable=yes, technical impact=total (+10). Injection / code execution class, CWE-502 (+5).

Returning a pydantic model rather than a formatted string means the components land in Langfuse and
Logfire traces structurally, with no extra instrumentation — which is what the weight-tuning loop
needs before it can start.

Safety: IDs are validated against `^CVE-\d{4}-\d{4,}$` and passed as a bound parameter
(`WHERE cve_id = ANY($1::text[])`), never interpolated. The tool builds its own SQL and so does
**not** pass through `validate_sql`, which makes parameterization the only thing standing between a
tool argument and the database. Unknown IDs come back as an explicit
*"Not found in KEV or NVD — unscored, not low risk"* entry rather than being silently dropped, since
a missing row in a ranking reads as "low risk".

### Tool vs. view

Use the **tool** for a handful of named CVEs. Use the **view** for ranking, filtering, and counting.
Both the system prompt and the MCP docstring say so explicitly, because without it the model calls
the tool 25 times where one `ORDER BY` would do.

## Example queries

```sql
-- What should I patch first?
SELECT cve_id, risk_score, cvss_score, epss_probability, kev_listed
FROM v_cve_risk ORDER BY risk_score DESC LIMIT 20;
```

```sql
-- Early warning: high composite risk without confirmed exploitation
SELECT cve_id, risk_score, epss_probability, epss_percentile
FROM v_cve_risk
WHERE NOT kev_listed AND risk_score >= 45
ORDER BY risk_score DESC;
```

```sql
-- Band distribution across the corpus
SELECT CASE WHEN risk_score >= 65 THEN 'critical'
            WHEN risk_score >= 45 THEN 'high'
            WHEN risk_score >= 25 THEN 'moderate'
            ELSE 'low' END AS band,
       COUNT(*)
FROM v_cve_risk GROUP BY 1 ORDER BY 1;
```

```sql
-- Why is this CVE ranked here? (no tool call needed)
SELECT cve_id, risk_score, c_cvss, c_epss, c_kev, c_ransomware, c_ssvc, c_cwe, cwe_top
FROM v_cve_risk WHERE cve_id = 'CVE-2021-44228';
```

## Deployment

### Local / dev

`init_db()` applies `view_ddl()` after `SCHEMA_SQL`, under the same `db_init_schema` gate. Nothing
to do.

`view_ddl()` drops whatever `v_cve_risk` currently is and rebuilds it, so re-running it is always
safe. It branches on `pg_class.relkind` rather than issuing both `DROP VIEW IF EXISTS` and
`DROP MATERIALIZED VIEW IF EXISTS`, because `IF EXISTS` only suppresses *"does not exist"* — a
relation of the wrong kind still raises. That branch is also the migration path for any database
still holding the original plain view.

Because it drops and repopulates, `view_ddl()` is schema-setup DDL, not something to run casually
against a full corpus. Day to day, `refresh_sql()` is what you want.

### Production

Production runs `DB_INIT_SCHEMA=false` (read-only app role, no DDL), so **`v_cve_risk` will not
exist, or update, just because it is in the code path.** Print it and apply it with the admin role
over the pooled host:

```bash
uv run python -c "from rag.risk import view_ddl; print(view_ddl())" > /tmp/v_cve_risk.sql
```

```bash
psql "<admin-pooled-supabase-dsn>" -f /tmp/v_cve_risk.sql
```

Expect this to take at least as long as the 12.8s query it replaces — it runs the full computation
once to populate.

Then three grants, and **all three are easy to miss**:

```sql
-- The app reads it.
GRANT SELECT ON v_cve_risk TO app_readonly;

-- The ETL refreshes it, through the SECURITY DEFINER wrapper rather than directly.
-- Without this the refresh step fails with "permission denied for materialized view".
GRANT EXECUTE ON FUNCTION refresh_v_cve_risk() TO app_etl;

-- The ETL also reads the view: refresh_risk_view.py logs the row count back after
-- refreshing. Without this the refresh succeeds and the script then fails with
-- "permission denied for materialized view v_cve_risk".
GRANT SELECT ON v_cve_risk TO app_etl;
```

**Both SELECT grants are required on every re-apply**, not only the first: the DDL drops and
recreates the view, which discards every grant on it. The `EXECUTE` grant survives, since the
wrapper function is `CREATE OR REPLACE`d rather than dropped.

**Do not try to make `app_etl` the owner instead.** `REFRESH MATERIALIZED VIEW` is owner-only and
no `GRANT` confers it, so ownership looks like the obvious fix — but it needs two escalations in
sequence, and the second is disqualifying:

| Attempt | Result |
| --- | --- |
| `ALTER MATERIALIZED VIEW v_cve_risk OWNER TO app_etl` | `ERROR: must be able to SET ROLE "app_etl"` |
| `GRANT app_etl TO postgres`, then retry | `ERROR: permission denied for schema public` |
| `GRANT CREATE ON SCHEMA public TO app_etl` | Works — and lets the ETL role create objects in `public`, which is exactly what the role exists to prevent |

`SECURITY DEFINER` inverts the problem: the function executes with the privileges of the admin role
that created it, so `app_etl` gains one callable statement and no DDL rights at all. `REVOKE ALL
... FROM PUBLIC` in the DDL keeps it from being world-executable, which a definer-privileged
function otherwise would be.

### Verify

```sql
-- No NULL scores anywhere (the invariant)                     expect: 0
SELECT COUNT(*) FROM v_cve_risk WHERE risk_score IS NULL;

-- Universe coverage: view rows = DISTINCT union of NVD + KEV
SELECT (SELECT COUNT(*) FROM v_cve_risk) AS view_rows,
       (SELECT COUNT(*) FROM (SELECT cve_id FROM nvd_vulnerabilities
                              UNION SELECT cve_id FROM kev_vulnerabilities) u) AS universe;

-- Known-value check: Log4Shell maxes every component          expect: risk_score = 100.0
SELECT * FROM v_cve_risk WHERE cve_id = 'CVE-2021-44228';

-- Rows leaning on the imputed CVSS prior                       expect: ~6.9%
SELECT COUNT(*) FILTER (WHERE cvss_imputed) AS imputed, COUNT(*) AS total FROM v_cve_risk;

-- EPSS join gap                                                expect: ~4.8%
SELECT COUNT(*) FILTER (WHERE epss_probability IS NULL) FROM v_cve_risk;
```

### Re-verify the band calibration

The corpus grows daily and EPSS re-scores everything, so confirm the shape still holds after each
significant load:

```sql
SELECT percentile_disc(ARRAY[0.5, 0.9, 0.99, 0.999])
         WITHIN GROUP (ORDER BY risk_score) AS p50_p90_p99_p999,
       MIN(risk_score), MAX(risk_score),
       MAX(risk_score) FILTER (WHERE NOT kev_listed) AS max_nonkev
FROM v_cve_risk;
```

Measured 2026-08-01: p50 20.2, p90 29.3, p99 44.1, p99.9 85.7, min 1.7, max 100.0,
**max_nonkev 63.5**.

A `min` comfortably above zero is its own check: the floor is `0.05 × 0.3 = 0.015` from the lowest
CWE tier, so a min near 0 would mean the `COALESCE(cw.severity, 0.5)` has stopped firing and
unrated CWEs are being zeroed rather than neutralized.

The load-bearing assertion is `max_nonkev`, which must land **inside** the high band (45–64). If it
drops below 45 the early-warning population goes invisible again and the bands need re-cutting.

Drifting the *other* way is close to structurally impossible, and it is worth knowing why rather
than watching a number that cannot move. A non-KEV row scores at most:

| Non-KEV ceiling | Value |
| --- | --- |
| CVSS 10 (0.25) + EPSS ~1.0 (0.30) + automatable & total (0.04) + top CWE class (0.05) | **64** |
| …plus `ssvc_exploitation='active'` (0.06) | **70** |

`c_kev` and `c_ransomware` are both gated on a KEV row existing, so a non-KEV CVE can never reach
that 0.30. At 63.5 the observed maximum is already at 99% of the practical ceiling — it stopped
climbing because it ran out of room, not by coincidence.

The second line is the only path by which a non-KEV CVE can be labelled "critical", and it applies
to the handful of CVEs that are `ssvc_exploitation='active'` without being KEV-listed (3 rows at
calibration). That population is small enough to inspect directly, and is the thing actually worth
monitoring here:

```sql
-- The only rows that can breach 65 without confirmed exploitation
SELECT cve_id, risk_score, cvss_score, epss_probability, ssvc_exploitation
FROM v_cve_risk
WHERE NOT kev_listed AND ssvc_exploitation = 'active'
ORDER BY risk_score DESC;
```

Expect a single-digit row count, all scoring well under 65. A row here at 65+ is a genuine
mislabel — either KEV is lagging a CVE that CISA's own SSVC data already calls actively exploited
(in which case the score is arguably right and KEV is wrong), or the SSVC value is stale.

### Performance — why it is materialized

`v_cve_risk` shipped as a plain view and was promoted after measurement. As a plain view it
re-computed on every access — three LEFT JOINs plus a lateral unnest over the whole CVE universe,
then a sort — and `EXPLAIN ANALYZE` on the production corpus measured:

```
Execution Time: 12769.175 ms
```

**12.8 seconds against a ~2s budget.** No index could fix it: `risk_score` is computed, so every
one of the ~372k rows has to be built before the sort can begin. Materializing is the only lever
that changes the shape of that work.

After materializing, the same query against the same corpus measured:

```
Execution Time: 0.843 ms
```

The rows are precomputed and `v_cve_risk_score_idx` covers the descending order this query asks
for, so nothing has to be built before the sort. Four orders of magnitude — the shape of the work
changed, not just its constant factor.

To re-measure after a schema or corpus change:

```sql
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT cve_id, risk_score, cvss_score, epss_probability, kev_listed
FROM v_cve_risk ORDER BY risk_score DESC LIMIT 100;
```

Run it two or three times — the first is cold and overstates. Note this reports server-side
execution only; the latency an analyst experiences also includes the round trip to Supabase.

The cost of materializing is **staleness bounded by the ETL cadence (~12h)** plus one extra ETL
step, [scripts/refresh_risk_view.py](../scripts/refresh_risk_view.py), which must stay last in
`STEPS` because the view reads all three loader tables.

`refresh_sql()` uses `REFRESH MATERIALIZED VIEW CONCURRENTLY`. That is not optional: a plain
`REFRESH` takes an `ACCESS EXCLUSIVE` lock, so every risk query would hang for the duration of the
rebuild rather than just reading slightly stale scores. `CONCURRENTLY` in turn requires a unique
index, which is why `view_ddl()` always emits `v_cve_risk_cve_id_idx`.

## What this is not

- **Not asset-aware.** It ranks CVEs, not *your* CVEs. Reachability, exposure, and compensating
  controls aren't in the data.
- **Not a calibrated probability.** It's an ordering heuristic with fixed weights, not a fitted
  model. The bands are corpus-relative labels.
- **Not stable over time.** EPSS refreshes daily and KEV grows, so a CVE's score moves without the
  CVE changing. Any consumer that stores a score must store `epss_scored_at` alongside it.

## Testing

| Tier | File | Covers |
| --- | --- | --- |
| Unit | [tests/unit/test_risk.py](../tests/unit/test_risk.py) | Weight invariant, band cut-points, generated DDL matching the constants, rationale prose, ID validation |
| Unit | [tests/unit/test_risk_tool.py](../tests/unit/test_risk_tool.py) | Tool error paths, parameterization, the two tool surfaces staying in sync |
| Integration | [tests/integration/test_risk_view_db.py](../tests/integration/test_risk_view_db.py) | The model itself — known values, universe CTE, CWE sourcing, missing-signal policy |

The integration tier is the one that matters: the arithmetic deliberately lives in SQL, so unit
tests can only check that the generated DDL matches the constants it was generated from.

Known-value fixtures pin the top of the scale:

| CVE | Inputs | Score |
| --- | --- | --- |
| CVE-2021-44228 (Log4Shell) | CVSS 10.0, EPSS 0.99999, KEV+ransomware, active/yes/total, CWE-502 | **100.0** |
| CVE-2017-0144 (EternalBlue) | CVSS 8.8, EPSS 0.99230, KEV+ransomware, active/no/total, `NVD-CWE-noinfo` | **92.3** |
| CVE-2014-0160 (Heartbleed) | CVSS 7.5, EPSS 0.99999, KEV (ransomware Unknown), active/yes/partial, CWE-125 | **81.8** |

Log4Shell maxing every component is the useful one: that single fixture pins the whole arithmetic,
and its CWE array doubles as the highest-member-wins test since only CWE-502 is in the 1.0 tier.

Integration tests need `TEST_DATABASE_URL` pointed at a pgvector database:

```bash
TEST_DATABASE_URL=postgresql://postgresuser:postgrespw@localhost:5432/vulncopilot_test uv run pytest tests/integration
```

## Related

- [epss-integration.md](epss-integration.md) — the likelihood signal
- [nvd-integration.md](nvd-integration.md) — CVSS and SSVC
- [cwe-integration.md](cwe-integration.md) — the weakness taxonomy
- [supabase-readonly-role.md](supabase-readonly-role.md) — the grant this view needs
- [plans/composite-risk-score.md](../plans/composite-risk-score.md) — the design and its measurements
