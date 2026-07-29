"""Integration tests for the EPSS upsert against a real PostgreSQL database.

Requires TEST_DATABASE_URL env var. These cover what the unit tests structurally
cannot: the movement-tracking guard and the new/modified split live in the upsert
SQL, not in Python.
"""

import datetime
from decimal import Decimal

import pytest

from rag.database import SCHEMA_SQL
from scripts.load_epss import upsert_scores

DAY1 = datetime.date(2026, 7, 28)
DAY2 = datetime.date(2026, 7, 29)

META_DAY1 = {"scored_at": DAY1, "model_version": "v2026.06.15"}
META_DAY2 = {"scored_at": DAY2, "model_version": "v2026.06.15"}

ROWS_DAY1 = [
    ("CVE-2021-44228", Decimal("0.94000"), Decimal("0.99900")),
    ("CVE-1999-0001", Decimal("0.03351"), Decimal("0.87435")),
]
# Next publication: the first CVE climbs, the second is unchanged.
ROWS_DAY2 = [
    ("CVE-2021-44228", Decimal("0.99999"), Decimal("1.00000")),
    ("CVE-1999-0001", Decimal("0.03351"), Decimal("0.87435")),
]


@pytest.fixture
async def epss_conn(db_pool):
    """A connection with the schema applied and epss_scores emptied."""
    async with db_pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
        await conn.execute("TRUNCATE epss_scores")
        yield conn


async def test_first_load_inserts_all_with_no_previous_score(epss_conn):
    counts = await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)

    assert counts == {"new": 2, "modified": 0}
    row = await epss_conn.fetchrow("SELECT * FROM epss_scores WHERE cve_id = 'CVE-2021-44228'")
    assert row["probability"] == Decimal("0.94000")
    assert row["scored_at"] == DAY1
    assert row["model_version"] == "v2026.06.15"
    assert row["previous_probability"] is None


async def test_same_day_rerun_does_not_clobber_the_baseline(epss_conn):
    """The ETL runs ~2x/day while EPSS publishes once — the second run must be a no-op.

    Without the scored_at guard, the rerun would shift today's own value into
    previous_probability and flatten every delta to zero.
    """
    await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)
    counts = await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)

    assert counts == {"new": 0, "modified": 2}
    row = await epss_conn.fetchrow("SELECT * FROM epss_scores WHERE cve_id = 'CVE-2021-44228'")
    assert row["previous_probability"] is None
    assert row["previous_scored_at"] is None


async def test_next_publication_shifts_previous_score(epss_conn):
    await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)
    await upsert_scores(epss_conn, ROWS_DAY2, META_DAY2)

    row = await epss_conn.fetchrow("SELECT * FROM epss_scores WHERE cve_id = 'CVE-2021-44228'")
    assert row["probability"] == Decimal("0.99999")
    assert row["scored_at"] == DAY2
    assert row["previous_probability"] == Decimal("0.94000")
    assert row["previous_scored_at"] == DAY1


async def test_movers_query_ranks_by_delta(epss_conn):
    await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)
    await upsert_scores(epss_conn, ROWS_DAY2, META_DAY2)

    movers = await epss_conn.fetch(
        """
        SELECT cve_id, probability - previous_probability AS delta
        FROM epss_scores
        WHERE previous_probability IS NOT NULL
        ORDER BY delta DESC
        """
    )
    assert movers[0]["cve_id"] == "CVE-2021-44228"
    assert movers[0]["delta"] == Decimal("0.05999")
    assert movers[-1]["delta"] == Decimal("0.00000")  # unchanged CVE


async def test_left_join_keeps_unscored_cves(epss_conn):
    """EPSS and NVD only partially overlap, so consumers must LEFT JOIN.

    A missing epss_scores row means *unscored*, never *zero risk* — an INNER JOIN
    would silently drop those CVEs from any ranking.
    """
    await epss_conn.execute(
        """
        INSERT INTO nvd_vulnerabilities (cve_id, content) VALUES ('CVE-2021-44228', 'scored'),
                                                                 ('CVE-9999-0001', 'unscored')
        ON CONFLICT (cve_id) DO UPDATE SET content = EXCLUDED.content
        """
    )
    await upsert_scores(epss_conn, ROWS_DAY1, META_DAY1)

    rows = await epss_conn.fetch(
        """
        SELECT n.cve_id, e.probability
        FROM nvd_vulnerabilities n
        LEFT JOIN epss_scores e ON e.cve_id = n.cve_id
        WHERE n.cve_id IN ('CVE-2021-44228', 'CVE-9999-0001')
        ORDER BY n.cve_id
        """
    )
    by_cve = {r["cve_id"]: r["probability"] for r in rows}
    assert by_cve == {"CVE-2021-44228": Decimal("0.94000"), "CVE-9999-0001": None}

    await epss_conn.execute("DELETE FROM nvd_vulnerabilities WHERE cve_id IN ('CVE-2021-44228', 'CVE-9999-0001')")


async def test_probability_threshold_compares_exactly(epss_conn):
    """NUMERIC, not REAL: a stored 0.9 must not read as 0.89999998 and drop at the boundary."""
    await upsert_scores(epss_conn, [("CVE-BOUNDARY", Decimal("0.90000"), Decimal("0.95000"))], META_DAY1)

    hit = await epss_conn.fetchval("SELECT COUNT(*) FROM epss_scores WHERE probability >= 0.9")
    assert hit == 1
