"""Unit tests for the FIRST.org EPSS loader (parsing + count reporting).

Fixtures are built in-test from the verified live feed shape; no network access.
The SQL-level movement guard is covered in tests/integration/test_load_epss_db.py,
since that logic lives in the upsert statement rather than in Python.
"""

import datetime
import gzip
from decimal import Decimal

import pytest

from scripts.load_epss import parse_epss_csv, parse_metadata_line, run, upsert_scores

METADATA_LINE = "#model_version:v2026.06.15,score_date:2026-07-28T12:00:27Z"


def build_feed(body: str, metadata: str | None = METADATA_LINE, header: str = "cve,epss,percentile") -> bytes:
    """Gzip a feed the same way FIRST.org serves it."""
    lines = ([metadata] if metadata is not None else []) + [header, body]
    return gzip.compress("\n".join(line for line in lines if line != "").encode())


# -- Metadata line --


def test_parse_metadata_line_extracts_version_and_date():
    meta = parse_metadata_line(METADATA_LINE)
    assert meta["model_version"] == "v2026.06.15"
    assert meta["scored_at"] == datetime.date(2026, 7, 28)


def test_parse_metadata_line_ignores_non_comment():
    assert parse_metadata_line("cve,epss,percentile") == {}


def test_parse_metadata_line_tolerates_unparseable_date():
    meta = parse_metadata_line("#model_version:v1,score_date:not-a-date")
    assert meta["model_version"] == "v1"
    assert meta["scored_at"] is None


# -- Feed parsing --


def test_metadata_comment_is_not_mistaken_for_the_header():
    """The regression that matters most: line 1 is a '#' comment, not the CSV header.

    Handing the stream straight to DictReader makes '#model_version:v2026.06.15' a
    field name and silently yields zero usable rows.
    """
    rows, meta = parse_epss_csv(build_feed("CVE-1999-0001,0.03351,0.87435"))

    assert rows == [("CVE-1999-0001", Decimal("0.03351"), Decimal("0.87435"))]
    assert meta["model_version"] == "v2026.06.15"
    assert meta["scored_at"] == datetime.date(2026, 7, 28)


def test_values_keep_five_decimal_fidelity_as_decimal():
    """NUMERIC columns need Decimal (asyncpg rejects float), and exactness is the point."""
    rows, _ = parse_epss_csv(build_feed("CVE-1,0.03351,0.87435"))
    _, probability, percentile = rows[0]

    assert isinstance(probability, Decimal)
    assert isinstance(percentile, Decimal)
    assert probability == Decimal("0.03351")
    assert str(probability) == "0.03351"


def test_missing_header_columns_raise():
    feed = build_feed("CVE-1,0.5", header="cve,epss")
    with pytest.raises(ValueError, match="missing expected columns"):
        parse_epss_csv(feed)


def test_feed_without_any_csv_content_raises():
    with pytest.raises(ValueError, match="no CSV header"):
        parse_epss_csv(gzip.compress(METADATA_LINE.encode()))


def test_malformed_rows_are_skipped_and_counted_not_fatal():
    body = "\n".join(
        [
            "CVE-1,0.10000,0.50000",
            ",0.20000,0.60000",  # blank CVE id
            "CVE-3,not-a-number,0.70000",  # unparseable probability
            "CVE-4,0.40000,",  # empty percentile
            "CVE-5,0.50000,0.90000",
        ]
    )
    rows, meta = parse_epss_csv(build_feed(body))

    assert [r[0] for r in rows] == ["CVE-1", "CVE-5"]
    assert meta["skipped"] == 3


def test_duplicate_cve_collapses_last_wins():
    """A duplicate key in one staged batch would raise cardinality_violation on upsert."""
    body = "CVE-1,0.10000,0.50000\nCVE-1,0.90000,0.99000"
    rows, _ = parse_epss_csv(build_feed(body))

    assert rows == [("CVE-1", Decimal("0.90000"), Decimal("0.99000"))]


def test_missing_metadata_falls_back_to_today():
    rows, meta = parse_epss_csv(build_feed("CVE-1,0.1,0.5", metadata=None))

    assert rows
    assert meta["model_version"] is None
    assert meta["scored_at"] == datetime.datetime.now(datetime.UTC).date()


def test_blank_and_extra_comment_lines_are_tolerated():
    raw = gzip.compress(
        "\n".join([METADATA_LINE, "# an extra note", "", "cve,epss,percentile", "CVE-1,0.1,0.5"]).encode()
    )
    rows, meta = parse_epss_csv(raw)

    assert rows == [("CVE-1", Decimal("0.1"), Decimal("0.5"))]
    assert meta["model_version"] == "v2026.06.15"


# -- Upsert counting --


class _FakeEpssConn:
    """Counts rows the way Postgres would: a cve_id already present is an update."""

    def __init__(self, existing=()):
        self.existing = set(existing)
        self.staged: list[tuple] = []

    def transaction(self):
        conn = self

        class _Txn:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return _Txn()

    async def fetchval(self, _sql, *_args):
        return len(self.existing)

    async def execute(self, sql, *_args):
        if sql.strip().startswith("INSERT"):
            self.existing.update(cve_id for cve_id, *_ in self.staged)

    async def copy_records_to_table(self, _table, *, records, columns):
        self.staged = list(records)

    async def close(self):
        pass


META = {"scored_at": datetime.date(2026, 7, 28), "model_version": "v2026.06.15"}


async def test_upsert_scores_splits_new_from_modified():
    rows = [
        ("CVE-1", Decimal("0.1"), Decimal("0.5")),
        ("CVE-2", Decimal("0.2"), Decimal("0.6")),
        ("CVE-3", Decimal("0.3"), Decimal("0.7")),
    ]
    conn = _FakeEpssConn(existing={"CVE-2"})  # one already present

    counts = await upsert_scores(conn, rows, META)

    assert counts == {"new": 2, "modified": 1}


async def test_upsert_scores_on_empty_table_is_all_new():
    rows = [("CVE-1", Decimal("0.1"), Decimal("0.5"))]

    counts = await upsert_scores(_FakeEpssConn(), rows, META)

    assert counts == {"new": 1, "modified": 0}


# -- Orchestrator entrypoint --


async def test_run_threads_counts_into_summary_and_metrics(monkeypatch):
    feed = build_feed("CVE-1,0.10000,0.50000\nCVE-2,0.20000,0.60000")

    async def fake_fetch():
        return feed

    async def fake_connect(**_kwargs):
        return _FakeEpssConn(existing={"CVE-2"})

    monkeypatch.setattr("scripts.load_epss.fetch_epss_csv", fake_fetch)
    monkeypatch.setattr("scripts.load_epss.asyncpg.connect", fake_connect)

    report = await run()

    assert report.metrics["fetched"] == 2
    assert report.metrics["new"] == 1
    assert report.metrics["modified"] == 1
    assert report.metrics["skipped"] == 0
    assert "1 new" in report.summary
    assert "2026-07-28" in report.summary


async def test_run_reports_cleanly_when_feed_is_empty(monkeypatch):
    async def fake_fetch():
        return build_feed("")

    monkeypatch.setattr("scripts.load_epss.fetch_epss_csv", fake_fetch)

    report = await run()

    assert report.metrics == {"fetched": 0, "loaded": 0}
    assert "No EPSS scores" in report.summary
