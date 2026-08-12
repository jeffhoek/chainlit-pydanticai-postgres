"""Composite risk score — the single source of truth for the blend.

Four prioritization signals already live in Postgres (CVSS severity, EPSS likelihood,
KEV confirmed exploitation, SSVC urgency), plus CWE weakness class as a minor
tiebreaker. This module owns the constants and *generates the SQL* from them, so the
arithmetic exists in exactly one place: `v_cve_risk` in Postgres.

Deliberately no second Python implementation of the same formula. A `risk_score`
Python function blending the same inputs would drift from the view the first time a
weight is edited, and nothing in CI would catch it because it would still pass its own
unit tests. Python's job here is the constants, the generated DDL, and the prose
(band names and the rationale string) — never the sum.

This module imports nothing from rag.database; the dependency runs the other way so
init_db() can apply the generated DDL.

See plans/composite-risk-score.md.
"""

import re
from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from pydantic import BaseModel

# -- Weights --------------------------------------------------------------------
#
# These encode a triage doctrine: confirmed exploitation dominates, likelihood
# outranks severity, weakness class only breaks ties. They must sum to exactly 1.00
# at maximum, which is what keeps the reported score inside 0-100.

WEIGHT_CVSS = Decimal("0.25")
WEIGHT_EPSS = Decimal("0.30")
WEIGHT_KEV = Decimal("0.20")
WEIGHT_RANSOMWARE = Decimal("0.10")
WEIGHT_SSVC_EXPLOITATION = Decimal("0.06")
WEIGHT_SSVC_AUTOMATABLE = Decimal("0.02")
WEIGHT_SSVC_IMPACT = Decimal("0.02")
WEIGHT_CWE = Decimal("0.05")

WEIGHT_SSVC_TOTAL = WEIGHT_SSVC_EXPLOITATION + WEIGHT_SSVC_AUTOMATABLE + WEIGHT_SSVC_IMPACT

MAX_WEIGHT = WEIGHT_CVSS + WEIGHT_EPSS + WEIGHT_KEV + WEIGHT_RANSOMWARE + WEIGHT_SSVC_TOTAL + WEIGHT_CWE

REQUIRED_WEIGHT_TOTAL = Decimal("1.00")

# Fail fast at import. A weight edit that breaks the invariant should crash the app,
# not silently emit scores above 100.
assert MAX_WEIGHT == REQUIRED_WEIGHT_TOTAL, f"Risk weights must sum to 1.00, got {MAX_WEIGHT}"

# -- Missing-signal policy ------------------------------------------------------
#
# Absent signals are where a scoring model quietly goes wrong, and the three cases
# are not the same. A missing EPSS row and missing SSVC factors contribute 0 (both
# are additive-when-present, and over half the corpus lacks SSVC entirely). CVSS is
# the one deviation: NULL CVSS means *not yet assessed*, and unassessed CVEs skew
# heavily toward the newest records — exactly the ones an analyst wants surfaced.
# Scoring those at zero would rank a brand-new CVE with EPSS 0.4 below a
# fully-assessed CVSS 4.0 with EPSS 0.0001.

CVSS_MISSING_PRIOR = Decimal("5.0")  # out of 10, the corpus-neutral midpoint
CWE_DEFAULT_SEVERITY = Decimal("0.5")  # for unmapped CWEs and the NVD-CWE-* placeholders

# -- CWE class severity ---------------------------------------------------------
#
# A deliberately small static map: the CWEs that actually appear at volume, and
# everything else neutral. Keyed off the `cwes TEXT[]` columns directly rather than
# joining cwe_definitions, so it behaves identically in production and in a dev
# database where load_cwe.py was never run.
#
# CWE-79 (XSS) sitting at 0.6 rather than 1.0 is the highest-leverage entry here:
# it is the single most common CWE in the corpus (~14% of NVD rows), so rating it
# top-tier would inflate a seventh of the corpus.
#
# CWE-20 (Improper Input Validation) and CWE-264 (Permissions/Privileges/Access
# Controls) are deliberately absent — both are Class-level catch-alls spanning
# everything from XSS to RCE, so a severity tier for either is noise dressed as
# signal. They fall through to CWE_DEFAULT_SEVERITY.

CWE_CLASSES: dict[str, tuple[Decimal, tuple[str, ...]]] = {
    "Memory corruption": (
        Decimal("1.0"),
        ("CWE-787", "CWE-119", "CWE-125", "CWE-416", "CWE-120", "CWE-121", "CWE-122", "CWE-190"),
    ),
    "Injection / code execution": (
        Decimal("1.0"),
        ("CWE-89", "CWE-78", "CWE-94", "CWE-74", "CWE-434", "CWE-77", "CWE-502"),
    ),
    "Access control / traversal": (
        Decimal("0.8"),
        ("CWE-22", "CWE-862", "CWE-284", "CWE-863", "CWE-269", "CWE-59"),
    ),
    "Authentication bypass": (
        Decimal("0.8"),
        ("CWE-287", "CWE-306", "CWE-288"),
    ),
    "Request forgery / XSS": (
        Decimal("0.6"),
        ("CWE-352", "CWE-918", "CWE-79"),
    ),
    "Information disclosure": (
        Decimal("0.4"),
        ("CWE-200", "CWE-203"),
    ),
    "DoS / resource exhaustion": (
        Decimal("0.3"),
        ("CWE-400", "CWE-476"),
    ),
}

CWE_SEVERITY: dict[str, Decimal] = {cwe: severity for severity, cwes in CWE_CLASSES.values() for cwe in cwes}

CWE_CLASS_NAME: dict[str, str] = {cwe: label for label, (_, cwes) in CWE_CLASSES.items() for cwe in cwes}

# -- Bands ----------------------------------------------------------------------
#
# Calibrated against the production corpus, NOT the round numbers they look like.
# Because ssvc_exploitation='active' is functionally a KEV alias, a CVE that is not
# on KEV tops out around 61 — so the obvious 70/85 cut-points would make "high"
# unreachable without KEV, and the flagship "high-EPSS, not yet on KEV" query would
# return CVEs labelled "moderate". These cut-points put that early-warning
# population (~1,874 non-KEV CVEs) inside the high band, where it belongs.
#
# Re-check after each production run (plans/composite-risk-score.md §10d): the
# load-bearing assertion is that max(risk_score) among non-KEV rows stays inside
# 45-64.

BAND_CRITICAL = Decimal("65")
BAND_HIGH = Decimal("45")
BAND_MODERATE = Decimal("25")

BANDS: tuple[tuple[Decimal, str], ...] = (
    (BAND_CRITICAL, "critical"),
    (BAND_HIGH, "high"),
    (BAND_MODERATE, "moderate"),
)

# -- Tool contract --------------------------------------------------------------

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# A token-budget judgment call, not a derived limit. Nothing enforces a ceiling here:
# this tool returns pydantic models straight to the serializer, so MAX_OUTPUT_CHARS in
# rag/sql_utils.py never applies — that only guards format_query_results, which the
# `query` tools call and this one does not. At ~400 chars per entry, 25 costs roughly
# 2.5k tokens of context; 100 would cost 10k.
#
# The cap is not what limits how many CVEs can be ranked. Bulk ranking goes through
# v_cve_risk (`ORDER BY risk_score DESC`), which has no cap and sorts the whole corpus
# in one query; this tool exists to *explain* a shortlist, not to produce one. Batching
# a long list through it in chunks of 25 is the anti-pattern the system prompt steers
# away from. Cheap to raise, awkward to lower.
MAX_BATCH = 25

VIEW_NAME = "v_cve_risk"

# SECURITY DEFINER wrapper the ETL calls instead of REFRESH MATERIALIZED VIEW, which
# is owner-only. Defined in view_ddl(), invoked by refresh_sql().
REFRESH_FUNCTION = "refresh_v_cve_risk"

# Delta above which an EPSS move is worth calling out in the rationale.
EPSS_MOVEMENT_THRESHOLD = Decimal("0.05")


def band(score: float | Decimal) -> str:
    """Return the band label for a 0-100 composite score."""
    value = Decimal(str(score))
    for cut, label in BANDS:
        if value >= cut:
            return label
    return "low"


def validate_cve_ids(cve_ids: list[str]) -> str | None:
    """Return an error string if the batch is unusable, else None.

    The regex is the input contract, not a security control — IDs reach the database
    as a query parameter, never as interpolated SQL.
    """
    if not cve_ids:
        return "Error: no CVE IDs supplied."
    if len(cve_ids) > MAX_BATCH:
        return f"Error: at most {MAX_BATCH} CVE IDs per call, got {len(cve_ids)}."
    bad = [c for c in cve_ids if not CVE_ID_PATTERN.match(c)]
    if bad:
        return f"Error: malformed CVE ID(s): {', '.join(bad)}. Expected the form CVE-2021-44228."
    return None


# -- SQL generation -------------------------------------------------------------
#
# Everything below emits SQL from the constants above. The generated view is the
# only place the arithmetic runs.


def _decimal(value: Decimal) -> str:
    """Render a Decimal as a SQL numeric literal (never a float literal)."""
    return format(value, "f")


COMPONENT_NAMES: tuple[str, ...] = ("c_cvss", "c_epss", "c_kev", "c_ransomware", "c_ssvc", "c_cwe")


def component_expressions() -> dict[str, str]:
    """SQL expression for each weighted component, keyed by its view column name.

    Each is rounded to 4 decimal places so the six columns visibly sum to the score
    the view reports — a breakdown that doesn't reconcile is worse than no breakdown.
    """
    return {
        "c_cvss": (
            f"ROUND({_decimal(WEIGHT_CVSS)} * "
            f"COALESCE(n.cvss_v31_score, n.cvss_v2_score, {_decimal(CVSS_MISSING_PRIOR)}) / 10, 4)"
        ),
        "c_epss": f"ROUND({_decimal(WEIGHT_EPSS)} * COALESCE(e.probability, 0), 4)",
        "c_kev": f"CASE WHEN k.cve_id IS NOT NULL THEN {_decimal(WEIGHT_KEV)} ELSE 0 END",
        "c_ransomware": (
            f"CASE WHEN k.known_ransomware_campaign_use = 'Known' THEN {_decimal(WEIGHT_RANSOMWARE)} ELSE 0 END"
        ),
        "c_ssvc": (
            f"CASE WHEN n.ssvc_exploitation = 'active' THEN {_decimal(WEIGHT_SSVC_EXPLOITATION)} ELSE 0 END"
            f" + CASE WHEN n.ssvc_automatable = 'yes' THEN {_decimal(WEIGHT_SSVC_AUTOMATABLE)} ELSE 0 END"
            f" + CASE WHEN n.ssvc_technical_impact = 'total' THEN {_decimal(WEIGHT_SSVC_IMPACT)} ELSE 0 END"
        ),
        # COALESCE, not a bare reference: an unmapped CWE (or none at all) must land
        # on the neutral default rather than NULL-poisoning the whole sum.
        "c_cwe": (f"ROUND({_decimal(WEIGHT_CWE)} * COALESCE(cw.severity, {_decimal(CWE_DEFAULT_SEVERITY)}), 4)"),
    }


def score_expression(prefix: str = "") -> str:
    """The 0-100 score as a SQL expression over the component columns."""
    terms = " + ".join(f"{prefix}{name}" for name in COMPONENT_NAMES)
    return f"ROUND(100 * ({terms}), 1)"


def cwe_class_values() -> str:
    """The CWE severity map as a SQL VALUES list.

    Emitted inline in the view rather than loaded into a table: that keeps the map in
    these Python constants and avoids a new table, a new loader, and two new grants.
    """
    rows = sorted(CWE_SEVERITY.items())
    return ",\n        ".join(f"('{cwe}', {_decimal(severity)})" for cwe, severity in rows)


def view_ddl() -> str:
    """The DDL that (re)creates v_cve_risk and its indexes.

    A MATERIALIZED view, not a plain one. Measured 2026-08-01, the plain view took
    **12.8s** for `ORDER BY risk_score DESC LIMIT 100` against the production corpus,
    six times the ~2s budget: risk_score is computed, so no index can help and every
    one of the ~372k rows has to be built before the sort can start. Materializing
    trades staleness bounded by the ETL cadence (~12h) for indexed lookups.

    DROP then CREATE, because materialized views have no OR REPLACE. That makes this
    statement expensive — it repopulates the whole matview — so it belongs in schema
    setup, not on a hot path. refresh_sql() is what the ETL runs.

    Every interpolated fragment comes from the module constants above — there is no
    caller input anywhere in this statement, which is what makes the f-string safe.
    """
    comp = component_expressions()
    component_sql = ",\n        ".join(f"{comp[name]} AS {name}" for name in COMPONENT_NAMES)

    return f"""
-- Drop whichever kind is actually there. v_cve_risk shipped as a plain view first,
-- and DROP MATERIALIZED VIEW will not remove one (nor vice versa) — while IF EXISTS
-- only suppresses "does not exist", not "wrong object type". So a database still
-- carrying the plain view, production included, needs the relkind branch to migrate.
DO $$
DECLARE kind "char";
BEGIN
    SELECT relkind INTO kind FROM pg_class WHERE oid = to_regclass('{VIEW_NAME}');
    IF kind = 'v' THEN
        EXECUTE 'DROP VIEW {VIEW_NAME} CASCADE';
    ELSIF kind = 'm' THEN
        EXECUTE 'DROP MATERIALIZED VIEW {VIEW_NAME} CASCADE';
    END IF;
END $$;

CREATE MATERIALIZED VIEW {VIEW_NAME} AS
WITH universe AS (
    -- Union rather than nvd_vulnerabilities alone. Every KEV CVE is present in NVD
    -- today, so this currently costs a UNION and buys nothing — but the loaders are
    -- independent, nothing structurally guarantees containment, and a KEV entry
    -- invisible to the ranking is the worst possible omission for a tool whose job
    -- is deciding what to patch first.
    SELECT cve_id FROM nvd_vulnerabilities
    UNION
    SELECT cve_id FROM kev_vulnerabilities
),
cwe_class(cwe_id, severity) AS (
    -- Generated from CWE_SEVERITY in rag/risk.py — do not edit here.
    VALUES
        {cwe_class_values()}
),
components AS (
    SELECT
        u.cve_id,
        {component_sql},
        COALESCE(n.cvss_v31_score, n.cvss_v2_score) AS cvss_score,
        (n.cvss_v31_score IS NULL AND n.cvss_v2_score IS NULL) AS cvss_imputed,
        e.probability          AS epss_probability,
        e.percentile           AS epss_percentile,
        e.previous_probability AS epss_previous_probability,
        e.previous_scored_at   AS epss_previous_scored_at,
        e.scored_at            AS epss_scored_at,
        (k.cve_id IS NOT NULL)  AS kev_listed,
        k.date_added            AS kev_date_added,
        k.known_ransomware_campaign_use,
        n.ssvc_exploitation,
        n.ssvc_automatable,
        n.ssvc_technical_impact,
        cw.cwe_id AS cwe_top
    FROM universe u
    LEFT JOIN nvd_vulnerabilities n ON n.cve_id = u.cve_id
    LEFT JOIN kev_vulnerabilities  k ON k.cve_id = u.cve_id
    LEFT JOIN epss_scores          e ON e.cve_id = u.cve_id
    LEFT JOIN LATERAL (
        -- Concatenate, don't COALESCE. NVD and KEV each carry their own cwes[], and
        -- ~93 KEV CVEs hold real weakness IDs in KEV while NVD has only NVD-CWE-*
        -- placeholders. COALESCE(n.cwes, k.cwes) never fires for them, because the
        -- NVD array is non-empty — it just contains nothing useful. Merging is safe
        -- because highest-severity-member-wins is already the rule: a second source
        -- can only raise this component, never lower it.
        SELECT cc.cwe_id, cc.severity
        FROM unnest(COALESCE(n.cwes, '{{}}'::text[]) || COALESCE(k.cwes, '{{}}'::text[])) AS t(cwe_id)
        JOIN cwe_class cc ON cc.cwe_id = t.cwe_id
        ORDER BY cc.severity DESC, cc.cwe_id
        LIMIT 1
    ) cw ON TRUE
)
SELECT
    cve_id,
    {score_expression()} AS risk_score,
    {", ".join(COMPONENT_NAMES)},
    cvss_score,
    cvss_imputed,
    epss_probability,
    epss_percentile,
    epss_previous_probability,
    epss_previous_scored_at,
    epss_scored_at,
    kev_listed,
    kev_date_added,
    known_ransomware_campaign_use,
    ssvc_exploitation,
    ssvc_automatable,
    ssvc_technical_impact,
    cwe_top
FROM components;

-- UNIQUE on cve_id is not just tidiness: REFRESH ... CONCURRENTLY refuses to run
-- without a unique index, and without CONCURRENTLY the refresh takes an exclusive
-- lock that blocks every read for its whole duration.
CREATE UNIQUE INDEX {VIEW_NAME}_cve_id_idx ON {VIEW_NAME} (cve_id);
CREATE INDEX {VIEW_NAME}_score_idx ON {VIEW_NAME} (risk_score DESC);

-- REFRESH MATERIALIZED VIEW is owner-only, and no GRANT confers it. Making app_etl
-- the owner instead needs two privilege escalations — membership in app_etl, then
-- CREATE on schema public for the new owner — and that second one would let the ETL
-- role create objects in public, defeating the no-DDL posture that is the whole
-- point of the role (docs/supabase-readonly-role.md).
--
-- SECURITY DEFINER inverts it: the function runs with the privileges of whoever
-- created it (the admin role that applies this DDL), so app_etl needs nothing but
-- EXECUTE. It gains exactly one callable statement rather than schema-wide DDL.
--
-- The pinned search_path is mandatory, not stylistic: without it a caller could
-- prepend a schema of their own and have the definer-privileged body resolve
-- v_cve_risk to an object they control.
CREATE OR REPLACE FUNCTION {REFRESH_FUNCTION}()
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$ REFRESH MATERIALIZED VIEW CONCURRENTLY {VIEW_NAME} $$;

-- Not executable by the world just because it is definer-privileged.
REVOKE ALL ON FUNCTION {REFRESH_FUNCTION}() FROM PUBLIC;

-- PostgreSQL does not support RLS on materialized views, so the protection every base
-- table gets from RLS_SQL (rag/database.py) is simply unavailable here — and this view
-- is a denormalized join across all four of them, which makes it the most useful single
-- object on the API surface. Revoking the grant is the only lever there is.
--
-- This has to live inside view_ddl() rather than beside the other RLS statements: the
-- DROP/CREATE above discards every privilege on the view, so a revoke applied elsewhere
-- would be silently undone the next time the score arithmetic changed. Guarded on role
-- existence for the same reason as RLS_SQL — `anon` is Supabase-only.
DO $$
DECLARE api_roles text;
BEGIN
    SELECT string_agg(quote_ident(rolname), ', ' ORDER BY rolname) INTO api_roles
    FROM pg_roles WHERE rolname IN ('anon', 'authenticated');

    IF api_roles IS NOT NULL THEN
        EXECUTE format('REVOKE ALL ON {VIEW_NAME} FROM %s', api_roles);
    END IF;
END $$;
""".strip()


def refresh_sql() -> str:
    """The statement the ETL runs after the loaders, to pick up new data.

    Calls the SECURITY DEFINER wrapper rather than REFRESH directly, so the ETL role
    needs only EXECUTE — see the function definition in view_ddl() for why ownership
    was the wrong lever.

    The refresh inside is CONCURRENTLY so readers are never blocked: a plain REFRESH
    holds an ACCESS EXCLUSIVE lock, which would make every risk query hang for the
    duration of the rebuild rather than merely returning slightly stale scores.
    """
    return f"SELECT {REFRESH_FUNCTION}();"


# -- Rationale ------------------------------------------------------------------


def _points(component: Any) -> int:
    """A weighted component (0-1) as whole points out of 100.

    Half-up rather than Python's default half-to-even, so a 0.245 component reads as
    25 and not 24 — the prose is for humans reconciling it against the number.
    """
    return int((Decimal(str(component or 0)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _num(value: Any) -> Decimal | None:
    return None if value is None else Decimal(str(value))


def _kev_clause(row: Mapping[str, Any]) -> str | None:
    if not row.get("kev_listed"):
        return None
    text = "Listed in KEV"
    date_added = row.get("kev_date_added")
    if date_added is not None:
        text += f" since {date_added}"
    if row.get("known_ransomware_campaign_use") == "Known":
        text += " with known ransomware campaign use"
    return text


def _epss_clause(row: Mapping[str, Any]) -> str:
    probability = _num(row.get("epss_probability"))
    if probability is None:
        return "No EPSS score — this signal contributed nothing, it is not a low likelihood"

    text = f"EPSS {probability:.5f}"
    percentile = _num(row.get("epss_percentile"))
    details = []
    if percentile is not None:
        details.append(f"{float(percentile) * 100:.0f}th percentile")
    scored_at = row.get("epss_scored_at")
    if scored_at is not None:
        details.append(f"as of {scored_at}")
    if details:
        text += f" ({', '.join(details)})"

    previous = _num(row.get("epss_previous_probability"))
    if previous is not None and abs(probability - previous) >= EPSS_MOVEMENT_THRESHOLD:
        direction = "rose" if probability > previous else "fell"
        text += f" — EPSS {direction} {previous:.5f} → {probability:.5f}"
        previous_at = row.get("epss_previous_scored_at")
        if previous_at is not None:
            text += f" since {previous_at}"
    return text


def _cvss_clause(row: Mapping[str, Any]) -> str:
    if row.get("cvss_imputed"):
        return f"CVSS unassessed — scored at the neutral {CVSS_MISSING_PRIOR} prior"
    score = _num(row.get("cvss_score"))
    return f"CVSS {score}" if score is not None else "CVSS unavailable"


def _ssvc_clause(row: Mapping[str, Any]) -> str | None:
    factors = [
        ("exploitation", row.get("ssvc_exploitation")),
        ("automatable", row.get("ssvc_automatable")),
        ("technical impact", row.get("ssvc_technical_impact")),
    ]
    present = [f"{label}={value}" for label, value in factors if value]
    return f"SSVC {', '.join(present)}" if present else None


def _cwe_clause(row: Mapping[str, Any]) -> str:
    cwe = row.get("cwe_top")
    if cwe is None:
        return "No rated weakness class — scored at the neutral default"
    return f"{CWE_CLASS_NAME.get(cwe, 'Weakness')} class, {cwe}"


def build_rationale(row: Mapping[str, Any]) -> str:
    """Explain a v_cve_risk row in prose, clauses ranked by contribution.

    The score alone is a black box; the score beside its ranked contributions is an
    argument. Takes a view row (asyncpg Record or dict) so it stays in step with the
    columns rather than re-deriving anything.

    Each clause's points are rounded independently, so they can sum to within a point
    of the headline score (a 0.125 CVSS component reads as "+13", not "+12.5"). That
    is a deliberate readability trade, not a rounding bug — the exact values are in
    the c_* view columns and in RiskScore.components.
    """
    score = _num(row.get("risk_score")) or Decimal("0")

    def component(name: str) -> Decimal:
        return _num(row.get(name)) or Decimal(0)

    # KEV listing and the ransomware flag read as one fact, so they share a clause
    # and their contributions are summed for ranking.
    kev_contribution = component("c_kev") + component("c_ransomware")

    # (contribution, clause, keep_at_zero). A clause that contributed nothing is
    # dropped — except a missing EPSS score, which has to be said out loud, since a
    # silently absent likelihood signal reads as "low likelihood".
    candidates: list[tuple[Decimal, str | None, bool]] = [
        (kev_contribution, _kev_clause(row), False),
        (component("c_epss"), _epss_clause(row), row.get("epss_probability") is None),
        (component("c_cvss"), _cvss_clause(row), True),
        (component("c_ssvc"), _ssvc_clause(row), False),
        (component("c_cwe"), _cwe_clause(row), False),
    ]

    parts = [
        f"{clause} (+{_points(contribution)})."
        for contribution, clause, keep_at_zero in sorted(candidates, key=lambda c: c[0], reverse=True)
        if clause is not None and (contribution > 0 or keep_at_zero)
    ]

    header = f"{band(score).capitalize()} ({_points(score / 100)})."
    return " ".join([header, *parts])


# -- Tool implementation --------------------------------------------------------
#
# Shared by the pydantic-ai tool in rag/agent.py and the MCP tool in
# mcp_server/server.py, so the two surfaces cannot drift.


class RiskComponents(BaseModel):
    """Each signal's weighted contribution, 0-1. Sums to the score / 100."""

    cvss: float
    epss: float
    kev: float
    ransomware: float
    ssvc: float
    cwe: float


class RiskScore(BaseModel):
    """One CVE's composite risk.

    `score`, `band`, and `components` are None only when the CVE is in neither KEV
    nor NVD — an unknown ID is reported explicitly rather than dropped, because a
    silently missing row in a ranking reads as "low risk".
    """

    cve_id: str
    score: int | None = None
    band: str | None = None
    components: RiskComponents | None = None
    rationale: str


# Parameterized, never interpolated. This tool builds its own SQL and so does not
# pass through validate_sql() — the bound parameter is the only thing between a tool
# argument and the database.
RISK_QUERY = f"SELECT * FROM {VIEW_NAME} WHERE cve_id = ANY($1::text[])"


def row_to_risk_score(row: Mapping[str, Any]) -> RiskScore:
    """Build a RiskScore from a v_cve_risk row. No blending — the view did that."""
    score = _num(row["risk_score"]) or Decimal(0)
    return RiskScore(
        cve_id=row["cve_id"],
        score=_points(score / 100),
        band=band(score),
        components=RiskComponents(
            cvss=float(row["c_cvss"]),
            epss=float(row["c_epss"]),
            kev=float(row["c_kev"]),
            ransomware=float(row["c_ransomware"]),
            ssvc=float(row["c_ssvc"]),
            cwe=float(row["c_cwe"]),
        ),
        rationale=build_rationale(row),
    )


async def score_cves(pool: Any, cve_ids: list[str]) -> list[RiskScore] | str:
    """Score a batch of CVEs against v_cve_risk, ranked highest-risk first.

    Returns an error string rather than raising when the batch is unusable, so both
    tool surfaces report the same message to the model.
    """
    error = validate_cve_ids(cve_ids)
    if error:
        return error

    async with pool.acquire() as conn:
        rows = await conn.fetch(RISK_QUERY, cve_ids)

    scored = sorted(
        (row_to_risk_score(row) for row in rows),
        key=lambda r: r.score or 0,
        reverse=True,
    )
    found = {r.cve_id for r in scored}
    missing = [
        RiskScore(cve_id=cve_id, rationale="Not found in KEV or NVD — unscored, not low risk.")
        for cve_id in dict.fromkeys(cve_ids)
        if cve_id not in found
    ]
    return scored + missing
