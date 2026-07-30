"""Integration tests for v_cve_risk against a real PostgreSQL database.

Requires TEST_DATABASE_URL env var.

This is the tier that matters. The composite-score arithmetic deliberately lives in
SQL and nowhere else (see rag/risk.py), so the unit tests can only check that the
generated DDL matches the constants — whether the model actually behaves is only
observable here.
"""

import datetime
from decimal import Decimal

import pytest

from rag.risk import score_cves

# Real CVEs whose inputs pin the top of the scale, plus synthetic ones exercising the
# missing-signal policy. The synthetic IDs use year 2090 so they cannot collide with
# anything a loader might insert.
LOG4SHELL = "CVE-2021-44228"
ETERNALBLUE = "CVE-2017-0144"
HEARTBLEED = "CVE-2014-0160"

KEV_ONLY = "CVE-2090-10001"  # in KEV, absent from NVD
KEV_CWE_RESCUE = "CVE-2090-10002"  # NVD holds only a placeholder, KEV holds a real CWE
NO_EPSS = "CVE-2090-10003"
NO_CVSS = "CVE-2090-10004"
V2_ONLY = "CVE-2090-10005"
PLACEHOLDER_CWE = "CVE-2090-10006"
MULTI_CWE = "CVE-2090-10007"

FIXTURE_IDS = [
    LOG4SHELL,
    ETERNALBLUE,
    HEARTBLEED,
    KEV_ONLY,
    KEV_CWE_RESCUE,
    NO_EPSS,
    NO_CVSS,
    V2_ONLY,
    PLACEHOLDER_CWE,
    MULTI_CWE,
]

# (cve_id, cvss_v31, cvss_v2, cwes, ssvc_exploitation, ssvc_automatable, ssvc_impact)
NVD_ROWS = [
    (LOG4SHELL, Decimal("10.0"), None, ["CWE-20", "CWE-400", "CWE-502", "CWE-917"], "active", "yes", "total"),
    (ETERNALBLUE, Decimal("8.8"), None, ["NVD-CWE-noinfo"], "active", "no", "total"),
    (HEARTBLEED, Decimal("7.5"), None, ["CWE-125"], "active", "yes", "partial"),
    (KEV_CWE_RESCUE, Decimal("7.0"), None, ["NVD-CWE-noinfo"], None, None, None),
    (NO_EPSS, Decimal("9.0"), None, ["CWE-79"], None, None, None),
    (NO_CVSS, None, None, ["CWE-79"], None, None, None),
    (V2_ONLY, None, Decimal("6.0"), ["CWE-79"], None, None, None),
    (PLACEHOLDER_CWE, Decimal("5.0"), None, ["NVD-CWE-Other"], None, None, None),
    # CWE-502 (1.0) must win over CWE-200 (0.4) and CWE-400 (0.3).
    (MULTI_CWE, Decimal("5.0"), None, ["CWE-200", "CWE-502", "CWE-400"], None, None, None),
]

# (cve_id, ransomware, cwes, date_added)
KEV_ROWS = [
    (LOG4SHELL, "Known", ["CWE-502"], datetime.date(2021, 12, 10)),
    (ETERNALBLUE, "Known", [], datetime.date(2022, 3, 3)),
    (HEARTBLEED, "Unknown", ["CWE-125"], datetime.date(2022, 5, 4)),
    (KEV_ONLY, "Unknown", ["CWE-787"], datetime.date(2026, 1, 15)),
    (KEV_CWE_RESCUE, "Unknown", ["CWE-787"], datetime.date(2026, 1, 16)),
]

# (cve_id, probability, percentile)
EPSS_ROWS = [
    (LOG4SHELL, Decimal("0.99999"), Decimal("0.99999")),
    (ETERNALBLUE, Decimal("0.99230"), Decimal("0.99980")),
    (HEARTBLEED, Decimal("0.99999"), Decimal("0.99999")),
    (KEV_CWE_RESCUE, Decimal("0.01000"), Decimal("0.50000")),
    (NO_CVSS, Decimal("0.01000"), Decimal("0.50000")),
    (V2_ONLY, Decimal("0.01000"), Decimal("0.50000")),
    (PLACEHOLDER_CWE, Decimal("0.01000"), Decimal("0.50000")),
    (MULTI_CWE, Decimal("0.01000"), Decimal("0.50000")),
]


@pytest.fixture(scope="module")
async def risk_pool(seeded_pool):
    """Seed the risk fixtures, yield the pool, then remove them again.

    Cleanup matters because seeded_pool is session-scoped and shared: leaving these
    rows behind would change row counts for every test that runs after.
    """
    async with seeded_pool.acquire() as conn:
        await conn.executemany(
            """
            INSERT INTO nvd_vulnerabilities
                (cve_id, content, cvss_v31_score, cvss_v2_score, cwes,
                 ssvc_exploitation, ssvc_automatable, ssvc_technical_impact)
            VALUES ($1, 'fixture', $2, $3, $4, $5, $6, $7)
            ON CONFLICT (cve_id) DO UPDATE SET
                cvss_v31_score = EXCLUDED.cvss_v31_score,
                cvss_v2_score = EXCLUDED.cvss_v2_score,
                cwes = EXCLUDED.cwes,
                ssvc_exploitation = EXCLUDED.ssvc_exploitation,
                ssvc_automatable = EXCLUDED.ssvc_automatable,
                ssvc_technical_impact = EXCLUDED.ssvc_technical_impact
            """,
            NVD_ROWS,
        )
        await conn.executemany(
            """
            INSERT INTO kev_vulnerabilities
                (cve_id, content, known_ransomware_campaign_use, cwes, date_added)
            VALUES ($1, 'fixture', $2, $3, $4)
            ON CONFLICT (cve_id) DO UPDATE SET
                known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
                cwes = EXCLUDED.cwes,
                date_added = EXCLUDED.date_added
            """,
            KEV_ROWS,
        )
        await conn.executemany(
            """
            INSERT INTO epss_scores (cve_id, probability, percentile, scored_at)
            VALUES ($1, $2, $3, '2026-07-29')
            ON CONFLICT (cve_id) DO UPDATE SET
                probability = EXCLUDED.probability, percentile = EXCLUDED.percentile
            """,
            EPSS_ROWS,
        )

    yield seeded_pool

    async with seeded_pool.acquire() as conn:
        await conn.execute("DELETE FROM epss_scores WHERE cve_id = ANY($1::text[])", FIXTURE_IDS)
        await conn.execute("DELETE FROM nvd_vulnerabilities WHERE cve_id = ANY($1::text[])", FIXTURE_IDS)
        # CVE-2021-44228 belongs to the base session seed; strip the columns this
        # module added rather than deleting the row out from under other tests.
        await conn.execute(
            "DELETE FROM kev_vulnerabilities WHERE cve_id = ANY($1::text[]) AND cve_id <> $2",
            FIXTURE_IDS,
            LOG4SHELL,
        )
        await conn.execute(
            """
            UPDATE kev_vulnerabilities
               SET known_ransomware_campaign_use = NULL, cwes = NULL, date_added = NULL
             WHERE cve_id = $1
            """,
            LOG4SHELL,
        )


async def fetch_risk(pool, cve_id: str):
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM v_cve_risk WHERE cve_id = $1", cve_id)


# -- Known values: these pin the whole arithmetic --


async def test_log4shell_maxes_every_component_and_scores_exactly_100(risk_pool):
    """The one CVE in the corpus that maxes all six components.

    If the weights, the normalization, or the rounding drift, this is the fixture
    that notices.
    """
    row = await fetch_risk(risk_pool, LOG4SHELL)

    assert row["risk_score"] == Decimal("100.0")
    assert row["c_cvss"] == Decimal("0.2500")
    assert row["c_epss"] == Decimal("0.3000")
    assert row["c_kev"] == Decimal("0.20")
    assert row["c_ransomware"] == Decimal("0.10")
    assert row["c_ssvc"] == Decimal("0.10")
    assert row["c_cwe"] == Decimal("0.0500")


async def test_eternalblue_scores_partial_credit(risk_pool):
    """Exercises automatable='no' and a CWE placeholder falling to the default."""
    row = await fetch_risk(risk_pool, ETERNALBLUE)

    assert row["risk_score"] == Decimal("92.3")
    assert row["c_ssvc"] == Decimal("0.08")  # active + total, no automatable
    assert row["c_cwe"] == Decimal("0.0250")  # NVD-CWE-noinfo -> neutral 0.5


async def test_heartbleed_scores_without_the_ransomware_flag(risk_pool):
    row = await fetch_risk(risk_pool, HEARTBLEED)

    assert row["risk_score"] == Decimal("81.8")
    assert row["c_ransomware"] == Decimal("0")


async def test_components_sum_to_the_reported_score(risk_pool):
    """The breakdown has to reconcile, or it is not an explanation."""
    async with risk_pool.acquire() as conn:
        mismatches = await conn.fetchval(
            """
            SELECT COUNT(*) FROM v_cve_risk
             WHERE risk_score <> ROUND(100 * (c_cvss + c_epss + c_kev + c_ransomware + c_ssvc + c_cwe), 1)
            """
        )
    assert mismatches == 0


# -- The universe CTE --


async def test_kev_only_cve_appears_in_the_view(risk_pool):
    """The regression a future 'simplify the joins' refactor is most likely to break.

    A KEV entry invisible to the ranking is the worst possible omission for a tool
    whose job is deciding what to patch first.
    """
    row = await fetch_risk(risk_pool, KEV_ONLY)

    assert row is not None
    assert row["risk_score"] is not None
    assert row["kev_listed"] is True


async def test_kev_only_cve_sources_its_cwe_from_kev(risk_pool):
    """Not just 'the row exists' — appearing with a neutralized CWE is the failure."""
    row = await fetch_risk(risk_pool, KEV_ONLY)

    assert row["cwe_top"] == "CWE-787"
    assert row["c_cwe"] == Decimal("0.0500")  # 1.0 severity, not the 0.5 default


async def test_kev_only_cve_imputes_the_cvss_prior(risk_pool):
    """No NVD row means no CVSS at all — the prior applies, and says so."""
    row = await fetch_risk(risk_pool, KEV_ONLY)

    assert row["cvss_imputed"] is True
    assert row["c_cvss"] == Decimal("0.1250")


# -- CWE sourcing --


async def test_kev_cwe_wins_when_nvd_holds_only_a_placeholder(risk_pool):
    """The ~93-row case a COALESCE(n.cwes, k.cwes) implementation gets wrong.

    The NVD array is non-empty, so a COALESCE never fires — it just contains
    nothing useful. Concatenating is what rescues the real weakness ID from KEV.
    """
    row = await fetch_risk(risk_pool, KEV_CWE_RESCUE)

    assert row["cwe_top"] == "CWE-787"
    assert row["c_cwe"] == Decimal("0.0500")


async def test_placeholder_cwe_maps_to_the_neutral_default(risk_pool):
    """NVD-CWE-Other joins nothing — it must not become zero or a NULL that poisons."""
    row = await fetch_risk(risk_pool, PLACEHOLDER_CWE)

    assert row["cwe_top"] is None
    assert row["c_cwe"] == Decimal("0.0250")
    assert row["risk_score"] is not None


async def test_highest_severity_cwe_member_wins(risk_pool):
    row = await fetch_risk(risk_pool, MULTI_CWE)

    assert row["cwe_top"] == "CWE-502"
    assert row["c_cwe"] == Decimal("0.0500")


async def test_log4shell_cwe_array_resolves_through_its_one_rated_member(risk_pool):
    """CWE-20 and CWE-917 are unrated, CWE-400 is 0.3 — CWE-502 at 1.0 must win."""
    row = await fetch_risk(risk_pool, LOG4SHELL)

    assert row["cwe_top"] == "CWE-502"


# -- Missing-signal policy --


async def test_missing_epss_row_contributes_zero_without_nulling_the_score(risk_pool):
    row = await fetch_risk(risk_pool, NO_EPSS)

    assert row["epss_probability"] is None
    assert row["c_epss"] == Decimal("0.0000")
    assert row["risk_score"] is not None


async def test_missing_cvss_uses_the_neutral_prior_and_flags_it(risk_pool):
    row = await fetch_risk(risk_pool, NO_CVSS)

    assert row["cvss_imputed"] is True
    assert row["cvss_score"] is None
    assert row["c_cvss"] == Decimal("0.1250")  # 5.0/10 * 0.25


async def test_cvss_v2_only_is_used_rather_than_imputed(risk_pool):
    """37.6% of the corpus has no v3.1 score — imputing over a real v2 score would
    discard a measured input for a third of the data."""
    row = await fetch_risk(risk_pool, V2_ONLY)

    assert row["cvss_imputed"] is False
    assert row["cvss_score"] == Decimal("6.0")
    assert row["c_cvss"] == Decimal("0.1500")


async def test_missing_ssvc_factors_contribute_zero(risk_pool):
    row = await fetch_risk(risk_pool, NO_EPSS)

    assert row["ssvc_exploitation"] is None
    assert row["c_ssvc"] == Decimal("0")


async def test_score_is_never_null_across_the_whole_corpus(risk_pool):
    """The invariant: no absent signal may ever produce a NULL score."""
    async with risk_pool.acquire() as conn:
        nulls = await conn.fetchval("SELECT COUNT(*) FROM v_cve_risk WHERE risk_score IS NULL")
    assert nulls == 0


async def test_view_covers_the_union_of_nvd_and_kev(risk_pool):
    async with risk_pool.acquire() as conn:
        view_rows, universe = await conn.fetchrow(
            """
            SELECT (SELECT COUNT(*) FROM v_cve_risk),
                   (SELECT COUNT(*) FROM (SELECT cve_id FROM nvd_vulnerabilities
                                          UNION SELECT cve_id FROM kev_vulnerabilities) u)
            """
        )
    assert view_rows == universe


# -- The risk_score tool, end to end --


async def test_score_cves_ranks_highest_risk_first(risk_pool):
    results = await score_cves(risk_pool, [NO_CVSS, LOG4SHELL, ETERNALBLUE])

    assert [r.cve_id for r in results] == [LOG4SHELL, ETERNALBLUE, NO_CVSS]
    assert results[0].score == 100
    assert results[0].band == "critical"


async def test_score_cves_returns_components_that_sum_to_the_score(risk_pool):
    (result,) = await score_cves(risk_pool, [LOG4SHELL])
    c = result.components

    assert round(c.cvss + c.epss + c.kev + c.ransomware + c.ssvc + c.cwe, 4) == 1.0


async def test_score_cves_reports_unknown_ids_explicitly(risk_pool):
    """A dropped row in a ranking reads as 'low risk'."""
    results = await score_cves(risk_pool, [LOG4SHELL, "CVE-2090-99999"])

    unknown = next(r for r in results if r.cve_id == "CVE-2090-99999")
    assert unknown.score is None
    assert "Not found in KEV or NVD" in unknown.rationale


async def test_score_cves_rationale_discloses_an_imputed_cvss(risk_pool):
    (result,) = await score_cves(risk_pool, [NO_CVSS])

    assert "CVSS unassessed" in result.rationale


async def test_score_cves_rejects_a_malformed_id_before_querying(risk_pool):
    result = await score_cves(risk_pool, ["'; DROP TABLE kev_vulnerabilities; --"])

    assert isinstance(result, str)
    assert "malformed" in result
    # And the table is still there.
    async with risk_pool.acquire() as conn:
        assert await conn.fetchval("SELECT COUNT(*) FROM kev_vulnerabilities") > 0
