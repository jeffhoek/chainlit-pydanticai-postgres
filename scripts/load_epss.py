"""ETL script: Download the FIRST.org EPSS daily feed and load into PostgreSQL.

Usage:
    uv run python scripts/load_epss.py              # Fetch and upsert
    uv run python scripts/load_epss.py --dry-run    # Fetch and parse only, no writes

EPSS (Exploit Prediction Scoring System) scores each CVE with the probability of
exploitation in the wild within the next 30 days, plus a percentile rank. It is the
leading indicator to KEV's lagging one. No API key required; safe to re-run.

See plans/epss-score-integration.md and docs/epss-integration.md.
"""

import argparse
import asyncio
import csv
import datetime
import gzip
import io
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg
import httpx

from config import settings
from scripts.etl_report import LoaderReport

# Cyentia's EPSS hosting moved to Empirical Security; the old epss.cyentia.com host
# still resolves but only via redirect. "-current" itself redirects to a dated file
# (epss_scores-YYYY-MM-DD.csv.gz), so redirect-following is required either way —
# see FETCH_TIMEOUT usage below, which passes follow_redirects=True.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
FETCH_TIMEOUT = 60
EXPECTED_COLUMNS = {"cve", "epss", "percentile"}

CREATE_STAGING_SQL = """
    CREATE TEMP TABLE _epss_staging (
        cve_id VARCHAR(20),
        probability NUMERIC(6,5),
        percentile NUMERIC(6,5)
    ) ON COMMIT DROP
"""

# scored_at / model_version are identical for every row in a publication, so they are
# bound once as parameters here rather than carried through the COPY.
#
# The previous_* shift is guarded on scored_at actually advancing: the scheduled ETL
# runs roughly every 12h while EPSS publishes once daily, so an unguarded shift would,
# on the day's second run, overwrite yesterday's baseline with today's own value and
# flatten every delta to zero. The guard also makes a same-day re-run idempotent.
UPSERT_FROM_STAGING_SQL = """
    INSERT INTO epss_scores (cve_id, probability, percentile, scored_at, model_version)
    SELECT cve_id, probability, percentile, $1, $2
    FROM _epss_staging
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
"""


async def fetch_epss_csv() -> bytes:
    """Download the gzipped EPSS feed, returning the raw compressed bytes.

    httpx does not follow redirects by default (unlike requests), and this URL
    redirects twice — host and then -current -> dated file — so a plain get() would
    return a 302 with an empty body and surface as "no rows parsed".
    """
    print(f"Downloading EPSS scores from {EPSS_URL}...")
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(EPSS_URL)
        resp.raise_for_status()
    return resp.content


def parse_metadata_line(line: str) -> dict:
    """Parse the feed's leading '#' comment into model_version and scored_at.

    Shape: ``#model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z``
    Returns ``{}`` for a line that isn't a metadata comment. A malformed or absent
    date falls back to today so a feed-format tweak degrades rather than fails.
    """
    if not line.startswith("#"):
        return {}

    fields: dict[str, str] = {}
    for part in line.lstrip("#").strip().split(","):
        key, _, value = part.partition(":")
        if key.strip():
            fields[key.strip()] = value.strip()

    meta: dict = {"model_version": fields.get("model_version")}
    raw_date = fields.get("score_date", "")
    try:
        meta["scored_at"] = datetime.datetime.fromisoformat(raw_date.replace("Z", "+00:00")).date()
    except ValueError:
        meta["scored_at"] = None
    return meta


def parse_epss_csv(raw: bytes) -> tuple[list[tuple], dict]:
    """Decompress and parse the feed into (rows, meta).

    ``rows`` is a list of ``(cve_id, probability, percentile)`` tuples ready for COPY;
    ``meta`` carries model_version, scored_at, and a ``skipped`` count.

    The first line is a '#' metadata comment, NOT the header — handing the stream
    straight to DictReader would make '#model_version:v2026.06.15' the field name and
    silently yield zero usable rows. It is consumed explicitly here.
    """
    text = gzip.decompress(raw).decode("utf-8", errors="replace")
    stream = io.StringIO(text)

    meta: dict = {"model_version": None, "scored_at": None}
    # Consume leading comment/blank lines, keeping the first that parses as metadata.
    while True:
        pos = stream.tell()
        line = stream.readline()
        if not line:
            raise ValueError("EPSS feed contained no CSV header")
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if meta["model_version"] is None:
                meta.update(parse_metadata_line(stripped))
            continue
        stream.seek(pos)  # first non-comment line is the header — hand it to DictReader
        break

    reader = csv.DictReader(stream)
    missing = EXPECTED_COLUMNS - set(reader.fieldnames or [])
    if missing:
        raise ValueError(f"EPSS CSV missing expected columns: {missing} (got {reader.fieldnames})")

    if meta["scored_at"] is None:
        # No parseable score_date in the header comment; fall back to today so the
        # load still lands with an honest-enough freshness stamp.
        meta["scored_at"] = datetime.datetime.now(datetime.UTC).date()
        print("  WARNING: no score_date in feed metadata; falling back to today")

    # Dedupe last-wins: ON CONFLICT DO UPDATE raises cardinality_violation if one
    # staged batch holds a key twice. The feed shouldn't duplicate, but this turns a
    # hard ETL failure into a non-event.
    by_cve: dict[str, tuple] = {}
    skipped = 0
    for row in reader:
        cve_id = (row.get("cve") or "").strip()
        if not cve_id:
            skipped += 1
            continue
        try:
            # Decimal(str), not float(): the columns are NUMERIC, and asyncpg's numeric
            # codec requires Decimal — a float raises on COPY. Parsing the text directly
            # also keeps the feed's 5 decimals exact instead of routing through binary
            # float. InvalidOperation (an ArithmeticError) is what garbage input raises.
            probability = Decimal(row["epss"].strip())
            percentile = Decimal(row["percentile"].strip())
        except (TypeError, AttributeError, ArithmeticError):
            skipped += 1
            continue
        by_cve[cve_id] = (cve_id, probability, percentile)

    meta["skipped"] = skipped
    suffix = f", skipped {skipped} malformed" if skipped else ""
    print(f"Parsed {len(by_cve)} EPSS scores (model {meta['model_version']}, scored {meta['scored_at']}){suffix}")
    return list(by_cve.values()), meta


async def upsert_scores(conn: asyncpg.Connection, rows: list[tuple], meta: dict) -> dict[str, int]:
    """Bulk-upsert scores via a temp staging table; return {"new": n, "modified": n}.

    Uses COPY + a single INSERT ... SELECT rather than load_cwe.py's per-row loop:
    at ~353k rows, one statement per row would be that many round trips.

    Counts come from a before/after COUNT(*) delta rather than RETURNING (xmax = 0)
    — the trick load_kev.py uses — because that would materialize a row per score.
    """
    async with conn.transaction():
        before = await conn.fetchval("SELECT COUNT(*) FROM epss_scores")

        await conn.execute("DROP TABLE IF EXISTS _epss_staging")
        await conn.execute(CREATE_STAGING_SQL)
        await conn.copy_records_to_table(
            "_epss_staging",
            records=rows,
            columns=["cve_id", "probability", "percentile"],
        )
        await conn.execute(UPSERT_FROM_STAGING_SQL, meta["scored_at"], meta["model_version"])

        after = await conn.fetchval("SELECT COUNT(*) FROM epss_scores")

    new = after - before
    return {"new": new, "modified": len(rows) - new}


async def run() -> LoaderReport:
    """ETL entrypoint: fetch, parse, and upsert the EPSS feed; return a report."""
    print("Starting FIRST.org EPSS ETL...")

    raw = await fetch_epss_csv()
    rows, meta = parse_epss_csv(raw)
    if not rows:
        print("No EPSS scores parsed. Exiting.")
        return LoaderReport(summary="No EPSS scores returned by the feed", metrics={"fetched": 0, "loaded": 0})

    print("Connecting to PostgreSQL...")
    conn = await asyncpg.connect(dsn=settings.get_database_dsn())
    try:
        print("Upserting scores...")
        counts = await upsert_scores(conn, rows, meta)
    finally:
        await conn.close()

    new, modified = counts["new"], counts["modified"]
    print(f"Done! Loaded {len(rows)} EPSS scores ({new} new, {modified} updated).")
    return LoaderReport(
        summary=f"Loaded {len(rows)} EPSS scores ({new} new, {modified} updated, scored {meta['scored_at']})",
        metrics={
            "fetched": len(rows),
            "new": new,
            "modified": modified,
            "skipped": meta.get("skipped", 0),
            "loaded": len(rows),
        },
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description="FIRST.org EPSS ETL")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and parse without writing (use when the upstream format changes)",
    )
    args = parser.parse_args()

    if args.dry_run:
        rows, meta = parse_epss_csv(await fetch_epss_csv())
        print(f"Dry run: {len(rows)} scores parsed, nothing written.")
        for row in rows[:5]:
            print(f"  {row[0]}: probability={row[1]} percentile={row[2]}")
        return

    await run()


if __name__ == "__main__":
    asyncio.run(main())
