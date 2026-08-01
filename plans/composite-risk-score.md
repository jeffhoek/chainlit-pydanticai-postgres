# Composite Risk Score

Blend the four prioritization signals already in Postgres — CVSS severity, EPSS likelihood, KEV
confirmed exploitation, SSVC urgency — plus CWE weakness class as a minor modifier, into one 0–100
number with a structured breakdown, exposed both as an agent tool (`risk_score`) and as a SQL view
(`v_cve_risk`).

Expands the sketch in
[future-enhancements.md](future-enhancements.md#composite-risk-score-tool). Prerequisite work is
complete: SSVC shipped in PR [#130](https://github.com/jeffhoek/vulncopilot/pull/130), EPSS in PR
[#133](https://github.com/jeffhoek/vulncopilot/pull/133) (plan:
[epss-score-integration.md](epss-score-integration.md)).

## Why

Each existing signal answers a different question, and the agent currently makes the analyst do
the blending in their head:

| Signal | Question | Column |
| --- | --- | --- |
| CVSS | How bad if exploited? | `nvd_vulnerabilities.cvss_v31_score` / `cvss_v2_score` |
| EPSS | How likely to be exploited soon? | `epss_scores.probability` |
| KEV | Confirmed exploited right now? | presence in `kev_vulnerabilities` |
| SSVC | How urgently should a coordinator act? | `nvd_vulnerabilities.ssvc_*` |

CWE is a fifth input but not a fifth *signal*: it says what kind of weakness this is, not how
urgent it is. It carries the smallest weight (0.05) and acts as a tiebreaker between CVEs the four
signals rate equally — which is why it's kept out of the four-signal framing the system prompt
already teaches ([config.py:141](config.py:141)).

*"What do I patch first?"* requires all four at once. Today that means the model writes a bespoke
four-way JOIN per question and invents an ad-hoc ranking each time — inconsistent between turns
and unauditable. One view plus one tool makes the ranking deterministic, explainable, and
reusable by Software Inventory Matching, Alerting, and Retrieval Scoring.

There is also a hard technical reason a **view** is required rather than prompt guidance:
`validate_sql` ([rag/sql_utils.py:8](rag/sql_utils.py:8)) rejects anything not starting with
`SELECT`, so the agent **cannot write a `WITH ... SELECT` CTE at all**. Any multi-signal ranking
it composes today has to be a single flat SELECT with repeated inline arithmetic. `v_cve_risk`
turns that into `SELECT cve_id, risk_score FROM v_cve_risk ORDER BY risk_score DESC`.

---

## 1. What the signals actually look like (measured)

Measured against the **production corpus** via the deployed MCP server on 2026-07-29:
371,323 NVD rows, 1,655 KEV, 353,521 EPSS scores (`scored_at` 2026-07-29), 944 CWE definitions.

**CVSS coverage — the coalesce is not optional, and 7% have nothing to coalesce.**

| | Rows | Share |
| --- | --- | --- |
| `cvss_v31_score` present | 231,811 | 62.4% |
| `cvss_v2_score` only | 113,785 | 30.6% |
| **neither version** | **25,727** | **6.9%** |

Mean CVSS (coalesced) is 6.60. Scoring against `cvss_v31_score` alone would zero the largest
weight for 37.6% of the corpus, and the 25,727 rows with no CVSS at all are large enough that the
missing-value policy is a real decision, not an edge case (§3.2).

**SSVC coverage is substantial — 169,135 rows (45.5%)**, far broader than the 2026-06-17 start
date suggests, because CISA-ADP backfilled. Distribution of the three factors:

| Factor | Population |
| --- | --- |
| `exploitation = active` | 1,655 |
| `exploitation = poc` | 39,344 |
| `automatable = yes` | 38,769 |
| `technical_impact = total` | 57,553 |
| `automatable=yes` AND `impact=total` AND not active | 13,338 |

**`ssvc_exploitation='active'` is functionally an alias for KEV listing.** Cross-tabulated:
1,652 CVEs are both, 3 are active but not KEV, 3 are KEV but not active, and **0 KEV rows lack SSVC
data entirely**. This is the finding with the largest effect on the model (§3.5) — the +0.06 SSVC
exploitation term is not an independent signal, it is a KEV bonus.

The other two factors *are* independent: 13,338 non-active CVEs carry `automatable=yes` AND
`technical_impact=total`, so a non-KEV CVE can earn +0.04 but never the +0.06.

**EPSS is extremely skewed.** Across all 353,521 scored CVEs:

| Statistic | Value |
| --- | --- |
| median probability | 0.00714 |
| p90 | 0.04234 |
| p99 | 0.58229 |
| p99.9 | 0.97842 |
| min / max | 0.00047 / 0.99999 |
| ≥ 0.5 | 4,300 (1.2%) |
| ≥ 0.1 | 17,259 (4.9%) |

At weight 0.30, the **median CVE's EPSS term contributes 0.2 points out of 100**, and the p90 CVE
contributes 1.3. EPSS only moves the score for the top ~1%. That is *correct* — those CVEs really
are unlikely to be exploited — but it means the score's dynamic range is much narrower than the
sketch's bands assume (§3.4).

**17,802 NVD rows (4.8%) have no EPSS row at all** — the concrete size of the `LEFT JOIN` gap the
EPSS plan warned about. An `INNER JOIN` in the view would silently drop 1 CVE in 21.

**`cwes[]` is dominated by XSS and NVD placeholders.** Top of the distribution:

| CWE | Occurrences |
| --- | --- |
| CWE-79 (XSS) | 52,270 |
| `NVD-CWE-noinfo` | 36,059 |
| `NVD-CWE-Other` | 29,982 |
| CWE-89 (SQLi) | 23,636 |
| CWE-787 (OOB write) | 16,840 |
| CWE-119 | 14,443 |
| CWE-20 | 13,864 |

The two placeholders together account for 66,041 occurrences (17.8%), and a further 21,320 rows
(5.7%) have no CWE at all. Neither joins to `cwe_definitions`; both must map to the neutral
default rather than falling through to zero (§3.3).

`cwe_definitions` is populated in production (944 rows) but **empty in the local dev database**
(`load_cwe.py` was never run there). The CWE term keys off the `cwes TEXT[]` column directly rather
than joining that table, so the view behaves identically in both — which also keeps the integration
tests independent of a loader run.

---

## 2. Where the formula lives — one source of truth

The sketch describes "a SQL query ... plus a pure Python function that blends." Implemented
literally that is **two independent implementations of the same arithmetic**, and they will drift:
a weight tweak in Python leaves `v_cve_risk` returning a different number for the same CVE, and
nothing in CI catches it because the Python function passes its own unit tests.

Instead:

- **`rag/risk.py` owns the constants** — weights, the CWE class map, band cut-points, the missing
  CVSS prior.
- **`rag/risk.py` generates the SQL**, exposing `score_expression() -> str` and
  `view_ddl() -> str` built from those constants.
- **The arithmetic runs exactly once, in Postgres.** `risk_score()` selects from `v_cve_risk` and
  reads back the per-component columns; it does no blending of its own.
- **Python owns the prose** — band naming and the `rationale` string, which is genuinely Python's
  job and has no SQL counterpart to drift from.

`rag/risk.py` imports nothing from `rag/database.py` (the dependency runs the other way, so
`init_db` can apply the generated DDL). No new table is introduced: the CWE class map is emitted
as an inline `VALUES` list inside the view definition, which keeps it in the Python constants and
avoids a new table, a new loader, and two new grants.

```python
# rag/risk.py  (shape, not final text)
WEIGHT_CVSS = Decimal("0.25")
WEIGHT_EPSS = Decimal("0.30")
WEIGHT_KEV = Decimal("0.20")
WEIGHT_RANSOMWARE = Decimal("0.10")
WEIGHT_SSVC_EXPLOITATION = Decimal("0.06")
WEIGHT_SSVC_AUTOMATABLE = Decimal("0.02")
WEIGHT_SSVC_IMPACT = Decimal("0.02")
WEIGHT_CWE = Decimal("0.05")
# Sums to 1.00 at maximum. Assert this at import time — a weight edit that breaks
# the invariant should fail fast, not silently produce scores above 100.

CVSS_MISSING_PRIOR = Decimal("5.0")   # §3.2
CWE_DEFAULT_SEVERITY = Decimal("0.5") # §3.3
```

---

## 3. The scoring model

### 3.1 Weights (unchanged from the sketch)

| Signal | Expression | Weight |
| --- | --- | --- |
| CVSS base, normalized | `COALESCE(cvss_v31_score, cvss_v2_score, 5.0) / 10` | 0.25 |
| EPSS probability | `COALESCE(epss.probability, 0)` | 0.30 |
| KEV listed | row present in `kev_vulnerabilities` | +0.20 flat |
| KEV ransomware use | `known_ransomware_campaign_use = 'Known'` | +0.10 flat |
| SSVC urgency | `exploitation='active'` +0.06, `automatable='yes'` +0.02, `technical_impact='total'` +0.02 | up to +0.10 |
| CWE class severity | static map over `cwes[]`, max member wins | 0.05 |

Maximum 1.00, ×100 for the reported score.

The weights are deliberately kept as specified. They encode a defensible triage doctrine —
confirmed exploitation dominates, likelihood outranks severity — and the sketch's own guidance is
to ship fixed weights and revisit against real usage. The changes below are about **missing data
and band calibration**, not about re-litigating the weights.

### 3.2 Missing-signal policy

Absent signals are where a scoring model quietly goes wrong, and the three cases are *not* the
same:

| Missing | Rows affected | Contributes | Why |
| --- | --- | --- | --- |
| EPSS row | 17,802 (4.8%) | **0** | Carried over from the EPSS plan. `LEFT JOIN` always; a missing row means unscored, and the score must never come back NULL because one signal is absent. |
| SSVC factors | 202,188 (54.5%) | **0** | Additive-when-present. Over half the corpus lacks SSVC entirely, so anything other than zero — a multiplier, a penalty — would distort the majority of rows. |
| CVSS (both versions NULL) | 25,727 (6.9%) | **neutral prior 5.0/10 → 0.125** | *Not* zero. See below. |
| CWE (empty, or only `NVD-CWE-*`) | ~87,000 occurrences | **neutral 0.5 → 0.025** | Placeholders carry no severity information; the neutral midpoint neither rewards nor punishes. |

The CVSS case is the one deviation from "missing = 0", and production data makes the argument
concrete rather than theoretical. Of the 25,727 rows with no CVSS score:

- **10,296 (40%) were published in 2025 or later**, 4,401 of them in 2026. NULL CVSS means
  *not yet assessed*, and unassessed CVEs skew heavily toward the newest records — exactly the ones
  an analyst most wants surfaced.
- **85 of them already carry EPSS ≥ 0.1.** Under a zero-CVSS policy those would score below a
  fully-assessed CVSS 4.0 with EPSS 0.0001. That is the failure mode in one line.

So: impute the corpus-neutral 5.0, and make the imputation visible — `cvss_imputed` as a view
column and an explicit clause in the `rationale` (`"CVSS unassessed — scored at the neutral 5.0
prior"`). A number that silently invents an input is worse than no number; a number that says which
input it invented is fine.

### 3.3 CWE class severity

A static map from CWE ID to a 0–1 class severity, weighted 0.05. Deliberately small — the CWEs
that actually appear at volume in the production corpus, everything else neutral:

| Class | Severity | CWEs (production occurrence counts) |
| --- | --- | --- |
| Memory corruption | 1.0 | CWE-787 (16,840), CWE-119 (14,443), CWE-125 (10,689), CWE-416 (9,627), CWE-120 (5,295), CWE-121 (3,550), CWE-122, CWE-190 (3,855) |
| Injection / code execution | 1.0 | CWE-89 (23,636), CWE-78 (7,382), CWE-94 (7,140), CWE-74 (5,103), CWE-434 (5,070), CWE-77 (4,236), CWE-502 (3,530) |
| Access control / traversal | 0.8 | CWE-22 (10,899), CWE-862 (9,736), CWE-284 (6,226), CWE-863 (3,735), CWE-269 (3,331), CWE-59 |
| AuthN / AuthZ bypass | 0.8 | CWE-287 (5,084), CWE-306, CWE-288 |
| Request forgery / XSS | 0.6 | CWE-352 (10,684), CWE-918 (3,401), CWE-79 (52,270) |
| Information disclosure | 0.4 | CWE-200 (10,804), CWE-203 |
| DoS / resource exhaustion | 0.3 | CWE-400 (3,759), CWE-476 (6,456) |
| Everything else, incl. `NVD-CWE-noinfo` (36,059), `NVD-CWE-Other` (29,982), `CWE-20` (13,864), `CWE-264` (5,491) | 0.5 | — |

Three notes:

- **`CWE-79` is the single most common CWE in the corpus** at 52,270 occurrences — 14% of all NVD
  rows. Placing XSS at 0.6 rather than 1.0 is therefore a high-leverage choice, not a footnote: it
  is what stops the most common weakness class from inflating a seventh of the corpus.
- **`CWE-20` and `CWE-264` stay neutral.** Both are Class-level catch-alls (Improper Input
  Validation; Permissions/Privileges/Access Controls) spanning everything from XSS to RCE. A
  severity tier for either would be noise dressed as signal.
- The map keys off the `cwes TEXT[]` column directly rather than joining `cwe_definitions`, so it
  behaves identically in production and in the CWE-less dev database (§1). **Max member wins** when
  a CVE lists several CWEs — Log4Shell (`CWE-20`, `CWE-400`, `CWE-502`, `CWE-917`) resolves to 1.0
  via CWE-502, which is exactly the intended behavior and a good regression fixture.

**Source CWEs from both tables, concatenated.** `kev_vulnerabilities` carries its own `cwes TEXT[]`
independent of NVD's, and the two disagree in a way that matters: **93 KEV CVEs have NVD `cwes`
consisting only of `NVD-CWE-*` placeholders while KEV holds real weakness IDs**. Reading only
`n.cwes` sends all 93 to the neutral default despite the data being right there — and these are KEV
rows, the highest-value records in the corpus.

Note that `COALESCE(n.cwes, k.cwes)` does *not* fix this: zero KEV rows have an empty NVD array, so
the coalesce never fires. The array concatenation in §4 is what's required. Concatenating is safe
precisely because max-member-wins is already the rule — merging can only raise the component when
one source knows something the other doesn't, never lower it. 1,484 of 1,655 KEV rows carry CWE
data worth merging.

### 3.4 Bands must be recalibrated — the sketch's cut-points are unreachable

The sketch proposes 0–39 low / 40–69 moderate / 70–84 high / 85–100 critical. Because
`ssvc_exploitation='active'` is a KEV alias (§1), the +0.06 is unreachable off KEV, and the
achievable ceilings are:

| CVE profile | Theoretical max | Observed max (production) |
| --- | --- | --- |
| Not on KEV (best case: CVSS 10, EPSS ~1.0, automatable+total, top CWE class) | 0.25+0.30+0.04+0.05 = **64** | **61.0** |
| On KEV, no ransomware flag | **90** | — |
| On KEV + ransomware | **100** | **97.5** |

So under the sketch's bands, **no CVE that isn't on KEV can ever be rated "high"** (70+) — not even
CVSS 10.0 with EPSS 0.99999. That directly defeats the flagship query this whole line of work was
built for: *"high-EPSS CVEs that aren't on KEV yet."* Those CVEs come back labeled "moderate,"
which is precisely the wrong signal.

Simulating the full formula across all 371,323 production rows:

| Statistic | Score |
| --- | --- |
| p50 | 19.1 |
| p90 | 27.6 |
| p99 | 42.8 |
| p99.9 | 84.3 |
| max | 97.5 |
| max, excluding KEV | **61.0** |
| KEV median | 68.8 |
| KEV minimum | 33.4 |

**Recalibrated bands:**

| Band | Range | Meaning |
| --- | --- | --- |
| low | 0–24 | Background noise |
| moderate | 25–44 | Worth tracking |
| high | 45–64 | Reachable without KEV: high CVSS **and** genuine exploitation likelihood, or KEV with a modest CVSS |
| critical | 65–100 | Effectively requires confirmed exploitation |

Validated against the production corpus — this is the resulting distribution:

| Band | Rows | Share | KEV | non-KEV |
| --- | --- | --- | --- | --- |
| low 0–24 | 282,591 | 76.10% | 0 | 282,591 |
| moderate 25–44 | 85,244 | 22.96% | 41 | 85,203 |
| high 45–64 | 2,523 | 0.68% | 649 | **1,874** |
| critical 65+ | 965 | 0.26% | 965 | 0 |

That is the shape the score needs. A clean pyramid; "critical" is 0.26% of the corpus and means
confirmed exploitation; and **1,874 non-KEV CVEs reach "high"** — the early-warning population the
sketch's bands rendered invisible. The non-KEV maximum (61.0) sits inside the high band with
headroom, which is the specific property that was broken before.

Spot-checks against known CVEs confirm the top of the scale behaves:

| CVE | Inputs | Score |
| --- | --- | --- |
| CVE-2021-44228 (Log4Shell) | CVSS 10.0, EPSS 0.99999, KEV+ransomware, active/yes/total, CWE-502 | **100** |
| CVE-2017-0144 (EternalBlue) | CVSS 8.8, EPSS 0.99230, KEV+ransomware, active/no/total, `NVD-CWE-noinfo` | **92** |
| CVE-2014-0160 (Heartbleed) | CVSS 7.5, EPSS 0.99999, KEV (ransomware Unknown), active/yes/partial, CWE-125 | **82** |

Log4Shell scoring exactly 100 is a useful property to pin as a test: it is the one CVE in the
corpus that maxes every component.

These cut-points should still be re-checked after the first production run (§10d) — the corpus
grows daily and EPSS re-scores everything — but they are calibrated, not guessed.

### 3.5 The SSVC exploitation term is a KEV alias — priced in deliberately

Not merely correlated: `ssvc_exploitation='active'` and KEV listing are the **same set** to within
6 rows out of 371,323 (§1). The +0.06 is therefore not an independent urgency signal, it is an
automatic KEV bonus, and KEV's real weight in the model is:

| | Weight |
| --- | --- |
| Nominal `kev` term | 0.20 |
| `ssvc_exploitation='active'` (KEV-implied) | 0.06 |
| Ransomware flag (KEV-only column) | 0.10 |
| **Effective KEV-gated total** | **0.36** |

That is more than the CVSS weight and more than EPSS. Two things follow, and both are deliberate:

1. **It is the right doctrine.** Confirmed in-the-wild exploitation *should* dominate a
   remediation ranking. This is why "critical" is a KEV-only band and why that isn't a defect.
2. **It must not be re-derived as a bug.** A future reader comparing the weight table to the
   correlation will see double-counting and be tempted to drop the SSVC exploitation term. Dropping
   it lowers every KEV row by 6 and changes nothing about ordering *within* KEV — it is nearly a
   no-op, which is itself the argument for leaving it alone rather than churning the bands.

The other two SSVC factors are genuinely independent (13,338 non-active CVEs carry
`automatable=yes` AND `technical_impact=total`) and are what let a non-KEV CVE climb into the high
band.

### 3.6 `previous_probability` in the rationale, not the sum

Per the sketch: a CVE whose EPSS jumped this week is a stronger call to action than a flat one at
the same score. `probability - previous_probability` is free (already in the row), but it is a
*derivative*, not a risk level, and folding it into the weighted sum would make the score
non-monotone in EPSS. Surface it in `rationale` when the delta exceeds ~0.05
(`"EPSS rose 0.31 → 0.78 since 2026-07-28"`) and leave it out of the arithmetic.

---

## 4. The `v_cve_risk` view

### CVE universe

Base the view on the **union of NVD and KEV CVE IDs**, not on `nvd_vulnerabilities` alone. Every
join is a `LEFT JOIN` off that universe.

To be accurate about the payoff: in production today **all 1,655 KEV CVEs are present in NVD**, so
the union currently costs a `UNION` and buys nothing. It is a cheap guard against a case that
would be maximally damaging if it ever occurred — a KEV entry invisible to the ranking is the worst
possible omission for a tool whose job is deciding what to patch first — and the loaders are
independent, so nothing structurally guarantees the containment holds. If profiling shows the
`UNION` materially hurts (§4 performance), swapping to a plain `nvd_vulnerabilities` base plus a
monitoring assertion that `kev_missing_from_nvd = 0` is a legitimate trade.

### Shape

```sql
CREATE OR REPLACE VIEW v_cve_risk AS
WITH universe AS (
    SELECT cve_id FROM nvd_vulnerabilities
    UNION
    SELECT cve_id FROM kev_vulnerabilities
),
cwe_class(cwe_id, severity) AS (
    VALUES ('CWE-787', 1.0), ('CWE-416', 1.0), ('CWE-78', 1.0)  -- generated from rag/risk.py
    -- ...
)
SELECT
    u.cve_id,
    ROUND(100 * (c_cvss + c_epss + c_kev + c_ransomware + c_ssvc + c_cwe), 1) AS risk_score,
    c_cvss, c_epss, c_kev, c_ransomware, c_ssvc, c_cwe,   -- component columns, for explainability
    COALESCE(n.cvss_v31_score, n.cvss_v2_score) AS cvss_score,
    e.probability AS epss_probability,
    e.percentile  AS epss_percentile,
    e.previous_probability,
    e.scored_at   AS epss_scored_at,
    (k.cve_id IS NOT NULL) AS kev_listed,
    k.known_ransomware_campaign_use,
    n.ssvc_exploitation, n.ssvc_automatable, n.ssvc_technical_impact,
    (n.cvss_v31_score IS NULL AND n.cvss_v2_score IS NULL) AS cvss_imputed
FROM universe u
LEFT JOIN nvd_vulnerabilities n ON n.cve_id = u.cve_id
LEFT JOIN kev_vulnerabilities  k ON k.cve_id = u.cve_id
LEFT JOIN epss_scores          e ON e.cve_id = u.cve_id
LEFT JOIN LATERAL (
    -- Concatenate, don't coalesce: see §3.3. NVD and KEV each carry their own
    -- cwes[], and 93 KEV CVEs have real weakness data in KEV while NVD holds
    -- only NVD-CWE-* placeholders. Max-member-wins already defines the merge.
    SELECT MAX(cc.severity) AS severity
    FROM unnest(COALESCE(n.cwes, '{}') || COALESCE(k.cwes, '{}')) AS t(cwe_id)
    JOIN cwe_class cc ON cc.cwe_id = t.cwe_id
) cw ON TRUE;
```

The component columns are what make the score defensible: `risk_score` alone is a black box,
`risk_score` beside its six contributions is an argument. They also give the `query` tool a way to
answer "why is this ranked here?" without calling `risk_score` at all.

Exposing `cvss_imputed` as a column (rather than only in the tool's prose) lets bulk queries filter
out imputed rows when precision matters — `WHERE NOT cvss_imputed`.

### Performance

A plain view re-computes on every access: three LEFT JOINs plus a lateral unnest over the full
CVE universe (371,323 rows in production), then a sort for `ORDER BY risk_score DESC`. The
equivalent inline query used for the §3.4 calibration returned aggregates over the whole corpus
through the MCP endpoint without timing out, so this is in the seconds range, not minutes —
acceptable, and always current.

**Ship the plain view first.** If measured p95 for `ORDER BY risk_score DESC LIMIT 100` exceeds
~2s, promote to a materialized view:

```sql
CREATE MATERIALIZED VIEW v_cve_risk AS <same query>;
CREATE UNIQUE INDEX v_cve_risk_cve_id_idx ON v_cve_risk (cve_id);  -- required for CONCURRENTLY
CREATE INDEX v_cve_risk_score_idx ON v_cve_risk (risk_score DESC);
-- then, as a 4th step in run_etl.py:
REFRESH MATERIALIZED VIEW CONCURRENTLY v_cve_risk;
```

The trade is staleness bounded by the ETL cadence (~12h) and an added ETL step, in exchange for
indexed millisecond ranking. Defer it until measurement justifies it — the name stays the same, so
promoting is a rollout change, not a code change.

> **Outcome: promoted.** The estimate above was wrong by an order of magnitude. Measured against
> the deployed plain view, `EXPLAIN ANALYZE` on that exact query reported **12,769 ms** — six times
> the budget, not "seconds range, acceptable". No index could have rescued it, because `risk_score`
> is computed and every row must be built before the sort begins.
>
> The promotion shipped rather than staying deferred, and it turned out to be a code change after
> all, not merely a rollout one. Materialized views have no `OR REPLACE`, so `view_ddl()` had to
> start dropping first — and branch on `pg_class.relkind`, since `DROP VIEW IF EXISTS` still raises
> on a relation of the wrong kind, which is what makes it a migration path off the plain view.
>
> The refresh also could not be issued directly. `REFRESH MATERIALIZED VIEW` is owner-only, and the
> route to making `app_etl` the owner ends at `GRANT CREATE ON SCHEMA public`, which would give the
> ETL role the DDL rights it exists to not have. `refresh_sql()` calls a `SECURITY DEFINER` wrapper
> instead. Both are detailed in [docs/risk-scoring.md](../docs/risk-scoring.md).

---

## 5. The `risk_score` tool

### Signature — accept a list

The sketch says `risk_score(cve_id)`. Make it **`risk_score(cve_ids: list[str])`**, capped at 25.
The dominant real question is *"rank these"*, and a singular tool forces the agent into 20 serial
round trips for a 20-CVE list — 20× the latency and 20× the tool-call tokens, against a query that
costs the same as one. A single-element list covers the singular case at no cost.

```python
class RiskComponents(BaseModel):
    cvss: float
    epss: float
    kev: float
    ransomware: float
    ssvc: float
    cwe: float

class RiskScore(BaseModel):
    cve_id: str
    score: int          # 0–100, rounded
    band: str           # low | moderate | high | critical
    components: RiskComponents
    rationale: str
```

Returning a pydantic model rather than a formatted string means the components land in Langfuse and
Logfire traces structurally, with no extra instrumentation — which is exactly what the sketch's
"log components via Langfuse, revisit once real usage data shows which CVEs analysts act on"
tuning plan needs. Both are already wired: `Agent.instrument_all()` at
[app.py:30](app.py:30) and `logfire.instrument_pydantic_ai()` at [app.py:14](app.py:14).

### Validation and safety

- Validate each ID against `^CVE-\d{4}-\d{4,}$` and reject the batch with a clear message
  otherwise. The regex is the input contract, not a security control.
- Pass IDs as a **parameter** (`WHERE cve_id = ANY($1::text[])`), never interpolated. The tool
  builds its own SQL and so does not pass through `validate_sql`, which makes parameterization the
  only thing standing between a tool argument and the database.
- Unknown CVE IDs come back as an explicit `"not found in KEV or NVD"` entry rather than being
  silently dropped — a missing row in a ranking reads as "low risk."

### Rationale text

Generated in Python from the component columns, ranked by contribution, e.g.:

> Critical (87). Listed in KEV since 2024-03-04 with known ransomware campaign use (+30).
> EPSS 0.94 (99th percentile, as of 2026-07-29) — EPSS rose 0.31 → 0.94 since 2026-07-22 (+28).
> CVSS 9.8 (+25). Memory corruption class, CWE-787 (+5).

### Mirror in the MCP server

`mcp_server/server.py` exposes the same tool for external agents, alongside adding `v_cve_risk` to
the `query` docstring's schema block. Same two-places-in-sync discipline the EPSS work established.

---

## 6. Agent surface

Edit `system_prompt` ([config.py:62](config.py:62)) and the MCP `query` docstring
([mcp_server/server.py:80](mcp_server/server.py:80)) **together** — the docstring says so itself.

**a. Add the view to both schema blocks:**

```
VIEW: v_cve_risk (
  cve_id VARCHAR(20),
  risk_score NUMERIC(4,1),          -- 0-100 composite; see the Composite Risk Score section
  c_cvss, c_epss, c_kev, c_ransomware, c_ssvc, c_cwe NUMERIC,  -- weighted contributions
  cvss_score NUMERIC(3,1),          -- COALESCE(v3.1, v2)
  cvss_imputed BOOLEAN,             -- TRUE when neither CVSS version exists (neutral prior used)
  epss_probability, epss_percentile, previous_probability NUMERIC(6,5),
  epss_scored_at DATE,
  kev_listed BOOLEAN,
  known_ransomware_campaign_use VARCHAR(20),
  ssvc_exploitation, ssvc_automatable, ssvc_technical_impact VARCHAR
)
```

**b. Add a Composite Risk Score primer**, in the shape of the existing SSVC
([config.py:121](config.py:121)) and EPSS ([config.py:141](config.py:141)) primers. It has to carry
four things the model will otherwise get wrong:

- The score is a **blend, not a fifth signal** — when asked specifically about likelihood or
  severity, cite `epss_probability` or `cvss_score` directly, not `risk_score`.
- **Bands are relative to this corpus**, with the calibrated cut-points listed explicitly.
- **`cvss_imputed = TRUE` means the CVSS input was a neutral prior**, not a measured score — say so
  when reporting such a CVE.
- **Use `risk_score` (the tool) for a handful of named CVEs; use `v_cve_risk` (the view) for
  ranking, filtering, and counting.** Without this the model will call the tool 25 times where one
  `ORDER BY` would do.

**c. Example queries:**

```sql
-- What should I patch first?
SELECT cve_id, risk_score, cvss_score, epss_probability, kev_listed
FROM v_cve_risk ORDER BY risk_score DESC LIMIT 20;

-- Early warning: high composite risk without confirmed exploitation
SELECT cve_id, risk_score, epss_probability, epss_percentile
FROM v_cve_risk
WHERE NOT kev_listed AND risk_score >= 45
ORDER BY risk_score DESC;

-- Band distribution across the corpus
SELECT CASE WHEN risk_score >= 65 THEN 'critical'
            WHEN risk_score >= 45 THEN 'high'
            WHEN risk_score >= 25 THEN 'moderate'
            ELSE 'low' END AS band,
       COUNT(*)
FROM v_cve_risk GROUP BY 1 ORDER BY 1;
```

**d. Quick-query buttons** — add 2–3 to `ACTION_BUTTONS` in **both** places it is still defined:
[.env.example:38](.env.example:38) and [k8s/configmap.yaml:32](k8s/configmap.yaml:32). The bicep
([infra/modules/app-service.bicep:136](infra/modules/app-service.bicep:136)) passes an
`actionButtons` parameter, so check whether the parameter files carry their own copy. Suggested:
*"Top 20 CVEs by composite risk score"*, *"Highest-risk CVEs not yet on KEV"*,
*"Risk score breakdown for CVE-2021-44228"*.

---

## 7. Ordered implementation steps

1. **`rag/risk.py`** — weights, CWE class map, bands, `score_expression()`, `view_ddl()`, band and
   rationale helpers. Import-time assertion that the weights sum to 1.00. Two things the §4 sketch
   elides and `score_expression()` must actually emit: `COALESCE(cw.severity, 0.5)` so an unmapped
   CWE lands on the neutral default rather than NULL-poisoning the sum (§3.2), and the concatenated
   `n.cwes || k.cwes` source (§3.3).
2. **Wire the DDL into schema setup** — `init_db()` ([rag/database.py:143](rag/database.py:143))
   executes `view_ddl()` after `SCHEMA_SQL`, under the same `db_init_schema` gate.
3. **Unit tests** for `rag/risk.py` (§8) — bands, rationale, missing-signal policy, CWE max-member.
4. **`risk_score` tool** in [rag/agent.py](rag/agent.py), returning `list[RiskScore]`.
5. **Integration tests** against a real Postgres (§8) — the view is where the arithmetic actually
   lives, so this is the tier that matters.
6. **MCP mirror** — `risk_score` tool + `v_cve_risk` in the `query` docstring.
7. **Agent surface** — system prompt + MCP docstring + action buttons (§6).
8. **Docs** — new `docs/risk-scoring.md` modeled on
   [docs/epss-integration.md](docs/epss-integration.md); index row in
   [docs/README.md](docs/README.md); link in [CLAUDE.md](CLAUDE.md); grant row in
   [docs/supabase-readonly-role.md:45](docs/supabase-readonly-role.md:45).
9. **Production rollout** (§10), including band calibration against the real corpus.
10. **Cleanup** — move the Composite Risk Score entry in
    [future-enhancements.md](future-enhancements.md) into Recently Shipped, pointing at this plan,
    and note the unblocked follow-ons.

Steps 1–8 are one reviewable PR. Step 9 is operational and follows the merge. The band cut-points
are already calibrated against the production corpus (§3.4), so step 9 verifies rather than
discovers — but if the distribution has drifted, adjusting them is a small follow-up commit to
`rag/risk.py` and the prompt.

---

## 8. Testing

**Unit — `tests/unit/test_risk.py`** (no DB), modeled on
[tests/unit/test_load_epss.py](tests/unit/test_load_epss.py):

- Weights sum to exactly 1.00 (the invariant that keeps scores ≤ 100).
- Band boundaries are exact at each cut-point — off-by-one at 44/45 and 64/65.
- `view_ddl()` output contains every CWE in the map, and the emitted `VALUES` list matches the
  Python dict — the guard against the generated SQL and the constants drifting.
- Rationale ordering: components sorted by contribution; the imputed-CVSS disclaimer appears when
  and only when `cvss_imputed`; the EPSS-movement clause appears only above the delta threshold.
- CVE ID validation accepts `CVE-2021-44228` and 5-digit sequence numbers, rejects `DROP TABLE`,
  `cve-2021-44228`, and empty strings.

**Integration — `tests/integration/test_risk_view_db.py`**, using the existing `seeded_pool`
fixture ([tests/conftest.py:73](tests/conftest.py:73)). This is the tier that actually validates
the model, since the arithmetic is SQL:

- **A CVE in KEV but not NVD appears in the view** — the universe-CTE regression, and the one most
  likely to be broken by a future "simplify the joins" refactor. Assert its **CWE component is
  sourced from `kev_vulnerabilities.cwes`**, not just that the row is non-NULL: appearing in the
  view with a silently neutralized CWE term is the failure this is guarding against.
- **A CVE whose NVD `cwes` holds only `NVD-CWE-noinfo` while KEV holds a real CWE** takes the KEV
  value — the 93-row case from §3.3, and the one a `COALESCE`-based implementation gets wrong.
- **A CVE with no EPSS row scores non-NULL**, with `c_epss = 0`.
- **A CVE with both CVSS versions NULL** gets the neutral prior and `cvss_imputed = TRUE`; a CVE
  with only `cvss_v2_score` uses it rather than imputing.
- **`NVD-CWE-Other` maps to the neutral default**, not to zero and not to a NULL that poisons the
  sum.
- **A CVE with several CWEs takes the maximum** class severity.
- **Known-value end-to-end**: seed CVE-2021-44228 with its real production inputs (CVSS 10.0,
  EPSS 0.99999, KEV + ransomware `Known`, SSVC active/yes/total, `cwes` =
  `{CWE-20, CWE-400, CWE-502, CWE-917}`) and assert the score is exactly **100**. Log4Shell maxes
  every component, so this one fixture pins the whole arithmetic — and its CWE array doubles as the
  max-member test, since only CWE-502 is in the 1.0 tier. Add CVE-2017-0144 (→ 92) as a
  partial-credit companion, since it exercises `automatable='no'` and `NVD-CWE-noinfo`.
- **Score is never NULL** across the whole seeded corpus:
  `SELECT COUNT(*) FROM v_cve_risk WHERE risk_score IS NULL` → 0.

**Tool tests** — `tests/unit/test_risk_tool.py` for the error paths (unknown CVE, malformed ID,
over-cap batch) in the fake-conn style of
[tests/unit/test_mcp_tools.py](tests/unit/test_mcp_tools.py), plus an MCP integration test
alongside [tests/integration/test_mcp_tools_db.py](tests/integration/test_mcp_tools_db.py).

---

## 9. What this is not

Worth stating so it isn't mistaken for something it can't do:

- **Not asset-aware.** It ranks CVEs, not *your* CVEs. Reachability, exposure, and compensating
  controls aren't in the data. Software Inventory Matching is what makes it personal, and this plan
  is its prerequisite, not its substitute.
- **Not a calibrated probability.** It's an ordering heuristic with fixed weights, not a fitted
  model. The bands are corpus-relative labels.
- **Not stable over time.** EPSS refreshes daily and KEV grows, so a CVE's score moves without the
  CVE changing. Any consumer that stores a score must store `epss_scored_at` alongside it.

---

## 10. Production rollout

Same constraints the EPSS rollout documented
([epss-score-integration.md](epss-score-integration.md) §10) — reuse them.

**a. Apply the view DDL manually.** Production runs `DB_INIT_SCHEMA=false` (read-only app role, no
DDL), so `v_cve_risk` will **not** exist just because it is in the code path. Print it and apply it
with the admin role over the **pooled** host, via plain `psql`:

```bash
uv run python -c "from rag.risk import view_ddl; print(view_ddl())" > /tmp/v_cve_risk.sql
```

```bash
psql "<admin-pooled-supabase-dsn>" -f /tmp/v_cve_risk.sql
```

**b. Grant SELECT — this is the step that will bite.**
[docs/supabase-readonly-role.md:53](docs/supabase-readonly-role.md:53) is explicit that grants are
per-object with no wildcard. Without this the app returns permission errors on every risk query:

```sql
GRANT SELECT ON v_cve_risk TO app_readonly;
```

`app_etl` needs no grant — nothing writes the view. A plain view runs with the **definer's**
privileges by default (`security_invoker` is off unless set), so `app_readonly` does not
additionally need SELECT on the underlying tables through the view — though it already has it on
all four.

**c. Verify.** Expected values below are the 2026-07-29 production measurements from §1/§3.4 —
a material deviation means the view doesn't match the model that was calibrated.

```sql
-- No NULL scores anywhere (the invariant)                     expect: 0
SELECT COUNT(*) FROM v_cve_risk WHERE risk_score IS NULL;

-- Universe coverage: view rows = DISTINCT union of NVD + KEV  expect: both 371,323
SELECT (SELECT COUNT(*) FROM v_cve_risk) AS view_rows,
       (SELECT COUNT(*) FROM (SELECT cve_id FROM nvd_vulnerabilities
                              UNION SELECT cve_id FROM kev_vulnerabilities) u) AS universe;

-- Known-value check: Log4Shell maxes every component          expect: risk_score = 100.0
SELECT * FROM v_cve_risk WHERE cve_id = 'CVE-2021-44228';

-- Rows leaning on the imputed CVSS prior                       expect: ~25,727 of 371,323 (6.9%)
SELECT COUNT(*) FILTER (WHERE cvss_imputed) AS imputed, COUNT(*) AS total FROM v_cve_risk;

-- EPSS join gap                                                expect: ~17,802 (4.8%)
SELECT COUNT(*) FILTER (WHERE epss_probability IS NULL) FROM v_cve_risk;
```

**d. Re-verify the band calibration.** The cut-points in §3.4 were fixed against this corpus, but
it grows daily and EPSS re-scores everything, so confirm the shape still holds:

```sql
SELECT percentile_disc(ARRAY[0.5, 0.9, 0.99, 0.999])
         WITHIN GROUP (ORDER BY risk_score) AS p50_p90_p99_p999,
       MIN(risk_score), MAX(risk_score),
       MAX(risk_score) FILTER (WHERE NOT kev_listed) AS max_nonkev
FROM v_cve_risk;
```

Expected: p50 ≈ 19, p90 ≈ 28, p99 ≈ 43, p99.9 ≈ 84, max ≈ 97.5, **max_nonkev ≈ 61**.

The load-bearing assertion is the last one: `max_nonkev` must land **inside** the high band
(45–64). If it drifts above 65, non-KEV CVEs start being labeled "critical" and the band loses its
meaning; if it drops below 45, the early-warning population goes invisible again and the bands need
re-cutting (§3.4).

Also confirm the band populations are still roughly 76% / 23% / 0.7% / 0.26%, and in particular
that the high band still contains a substantial non-KEV population (≈1,874) — that count is the
whole reason the bands were recalibrated.

**e. Measure latency** for `SELECT ... FROM v_cve_risk ORDER BY risk_score DESC LIMIT 100` and
decide on the materialized-view promotion (§4). The plan gave no query for this; use:

```sql
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT cve_id, risk_score, cvss_score, epss_probability, kev_listed
FROM v_cve_risk ORDER BY risk_score DESC LIMIT 100;
```

Run it two or three times — the first is cold. It reports server-side execution only; what an
analyst experiences also includes the round trip to Supabase.

**Done: 12,769 ms, so the view was promoted (§4 outcome).** Re-run this after the promotion to
confirm it drops to milliseconds, and again after any change to the view definition or a
significant corpus growth.

---

## 11. Deferred

| Item | Why |
| --- | --- |
| ~~Materialized `v_cve_risk` + ETL refresh step~~ **— shipped, not deferred** | §10(e) measured 12,769 ms against the ~2s budget, so this promoted immediately rather than waiting. See the §4 outcome note |
| Learned / tuned weights | Needs the Langfuse usage data this ships the instrumentation for — the tuning loop can't start before the tool exists |
| Risk score in `retrieve` result cards | Same `vector_store.search` signature change already deferred for EPSS ([rag/vector_store.py:11](rag/vector_store.py:11)); do both at once |
| Risk-weighted retrieval ranking | Retrieval Scoring Beyond Vector Similarity — needs evaluation against [eval-framework.md](eval-framework.md) first |
| Per-user risk thresholds / custom weights | No user-preference storage exists yet; belongs with Software Inventory Matching |
| KEV `due_date` overdue as a signal | Compliance-flavored, and only meaningful for the ~1,655 KEV rows; revisit with STIG/IAVA ([stig-iava-integration.md](stig-iava-integration.md)) |

---

## Open questions

1. **Does the CVSS neutral prior belong in the score at all, or should imputed rows be excluded
   from rankings?** *Recommend the prior*, with `cvss_imputed` exposed so callers can filter. New
   CVEs are exactly what an analyst wants to see; excluding them makes the ranking systematically
   blind to the newest records.
2. **Should the EPSS term be compressed (sqrt or log) so mid-range CVEs differentiate?** *Recommend
   no.* This was the main open risk before the production calibration, and the calibration answers
   it: with raw probability, **1,874 non-KEV CVEs still reach the high band**, so the score does
   discriminate within the non-KEV mass. Raw probability is also decision-theoretically honest, and
   the ordering is correct at the extremes (CVSS 6.5 / EPSS 0.90 outranks CVSS 9.8 / EPSS 0.001, as
   it should). The measured p50/p90 of 0.007/0.042 says most of the remaining mass genuinely is
   low-likelihood. If ever revisited, `sqrt(probability)` is the mildest option that preserves the
   top ranking — but note it would push the non-KEV ceiling past 65 and force a band re-cut.
3. **Batch cap of 25 for `risk_score`** — high enough for a realistic patch list, low enough to keep
   the tool result inside the `MAX_OUTPUT_CHARS` budget
   ([rag/sql_utils.py:5](rag/sql_utils.py:5)). Cheap to raise later, awkward to lower.
4. **Should `v_cve_risk` be `security_invoker = true`?** Not needed today (all four base tables are
   already granted to `app_readonly`), but setting it would keep the view honest if a future table
   joins in with narrower grants. Low cost to add now.
