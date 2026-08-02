"""Refresh the v_cve_risk materialized view.

Runs as the final ETL step, after the three loaders. v_cve_risk reads all of
nvd_vulnerabilities, kev_vulnerabilities, and epss_scores, so it is stale the moment
any loader commits — and unlike a plain view it does not recompute itself.

Materialized because the plain view measured 12.8s for a top-100 ranking against the
production corpus (see docs/risk-scoring.md). The cost of that choice is exactly this
step, and the staleness window is the ETL cadence.
"""

import asyncio
import time

import asyncpg

from config import settings
from rag.risk import VIEW_NAME, refresh_sql
from scripts.etl_report import LoaderReport


async def run() -> LoaderReport:
    started = time.time()
    conn = await asyncpg.connect(dsn=settings.get_database_dsn())
    try:
        await conn.execute(refresh_sql())
        rows = await conn.fetchval(f"SELECT COUNT(*) FROM {VIEW_NAME}")  # noqa: S608 — constant
    finally:
        await conn.close()

    elapsed = time.time() - started
    print(f"Refreshed {VIEW_NAME}: {rows:,} rows in {elapsed:.1f}s", flush=True)
    return LoaderReport(
        summary=f"Refreshed {rows:,} risk scores in {elapsed:.1f}s",
        metrics={"rows": rows},
    )


if __name__ == "__main__":
    asyncio.run(run())
