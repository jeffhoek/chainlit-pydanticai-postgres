"""ETL script: Fetch the full NVD database, generate embeddings, and load into PostgreSQL.

Uses paginated bulk fetching from NVD API 2.0 (2000 CVEs per page).
Supports incremental sync, checkpoint/resume, and separate embedding backfill.

Usage:
    uv run python scripts/load_nvd_full.py                         # Full load
    uv run python scripts/load_nvd_full.py --incremental           # Sync since last run
    uv run python scripts/load_nvd_full.py --incremental --since 2026-04-14  # Override start date
    uv run python scripts/load_nvd_full.py --skip-embeddings       # Data only, no embeddings
    uv run python scripts/load_nvd_full.py --backfill-embeddings   # Fill missing embeddings
    uv run python scripts/load_nvd_full.py --backfill-ssvc         # Fill SSVC columns from raw_json
    uv run python scripts/load_nvd_full.py --limit 3               # Test with first 3 pages

Incremental sync runs two phases: new CVEs (by published date) first, then all modified CVEs.
Use --since to override the start date after an interrupted run.
Use 'caffeinate -i' on macOS to prevent sleep during long Phase 2 runs.

Set NVD_API_KEY env var to increase rate limit from 5 to 50 requests per 30 seconds.
"""

import argparse
import asyncio
import contextlib
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg
import numpy as np
from openai import AsyncOpenAI
from pgvector.asyncpg import register_vector
from pgvector.vector import Vector

from config import settings
from scripts.etl_report import LoaderReport
from scripts.nvd_utils import (
    build_content,
    extract_affected_products,
    extract_cvss_v2,
    extract_cvss_v31,
    extract_cwes,
    extract_description,
    extract_reference_urls,
    extract_ssvc,
    nvd_get_with_backoff,
    parse_date,
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
EMBEDDING_BATCH_SIZE = 500
BACKFILL_BATCH_SIZE = 100
SSVC_BACKFILL_BATCH_SIZE = 5000  # pure SQL/Python, no API — batches can be large
CHECKPOINT_FILE = Path(__file__).resolve().parent.parent / "data" / "nvd_checkpoint.json"
DB_RETRY_EXCEPTIONS = (
    ConnectionResetError,
    OSError,
    asyncpg.ConnectionDoesNotExistError,
    asyncio.TimeoutError,
    asyncpg.exceptions.ReadOnlySQLTransactionError,
)
DB_CONNECT_TIMEOUT = 10
MAX_RETRIES = 3

# Rate limiting: 5 req/30s without key, 50 req/30s with key
NVD_API_KEY = os.getenv("NVD_API_KEY")
REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.0

STAGING_COLUMNS = [
    "cve_id",
    "description",
    "cvss_v31_score",
    "cvss_v31_severity",
    "cvss_v31_vector",
    "cvss_v2_score",
    "cvss_v2_severity",
    "cwes",
    "affected_products",
    "reference_urls",
    "published",
    "last_modified",
    "ssvc_exploitation",
    "ssvc_automatable",
    "ssvc_technical_impact",
    "ssvc_decision",
    "ssvc_version",
    "raw_json",
    "content",
    "embedding",
]

CREATE_STAGING_SQL = """
    CREATE TEMP TABLE _nvd_staging (
        cve_id VARCHAR(20),
        description TEXT,
        cvss_v31_score NUMERIC(3,1),
        cvss_v31_severity VARCHAR(10),
        cvss_v31_vector TEXT,
        cvss_v2_score NUMERIC(3,1),
        cvss_v2_severity VARCHAR(10),
        cwes TEXT[],
        affected_products TEXT[],
        reference_urls TEXT[],
        published DATE,
        last_modified DATE,
        ssvc_exploitation VARCHAR(8),
        ssvc_automatable VARCHAR(4),
        ssvc_technical_impact VARCHAR(8),
        ssvc_decision VARCHAR(8),
        ssvc_version VARCHAR(8),
        raw_json JSONB,
        content TEXT,
        embedding vector(1536)
    ) ON COMMIT DROP
"""

UPSERT_FROM_STAGING_SQL = """
    INSERT INTO nvd_vulnerabilities (
        cve_id, description, cvss_v31_score, cvss_v31_severity,
        cvss_v31_vector, cvss_v2_score, cvss_v2_severity,
        cwes, affected_products, reference_urls,
        published, last_modified,
        ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
        ssvc_decision, ssvc_version,
        raw_json, content, embedding
    )
    SELECT
        cve_id, description, cvss_v31_score, cvss_v31_severity,
        cvss_v31_vector, cvss_v2_score, cvss_v2_severity,
        cwes, affected_products, reference_urls,
        published, last_modified,
        ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
        ssvc_decision, ssvc_version,
        raw_json, content, embedding
    FROM _nvd_staging
    ON CONFLICT (cve_id) DO UPDATE SET
        description = EXCLUDED.description,
        cvss_v31_score = EXCLUDED.cvss_v31_score,
        cvss_v31_severity = EXCLUDED.cvss_v31_severity,
        cvss_v31_vector = EXCLUDED.cvss_v31_vector,
        cvss_v2_score = EXCLUDED.cvss_v2_score,
        cvss_v2_severity = EXCLUDED.cvss_v2_severity,
        cwes = EXCLUDED.cwes,
        affected_products = EXCLUDED.affected_products,
        reference_urls = EXCLUDED.reference_urls,
        published = EXCLUDED.published,
        last_modified = EXCLUDED.last_modified,
        ssvc_exploitation = EXCLUDED.ssvc_exploitation,
        ssvc_automatable = EXCLUDED.ssvc_automatable,
        ssvc_technical_impact = EXCLUDED.ssvc_technical_impact,
        ssvc_decision = EXCLUDED.ssvc_decision,
        ssvc_version = EXCLUDED.ssvc_version,
        raw_json = EXCLUDED.raw_json,
        content = EXCLUDED.content,
        embedding = COALESCE(EXCLUDED.embedding, nvd_vulnerabilities.embedding)
"""


def format_elapsed(started_at: float) -> str:
    elapsed = time.time() - started_at
    return f"{int(elapsed // 60)}m{int(elapsed % 60):02d}s"


# -- Checkpoint --


def load_checkpoint() -> dict | None:
    if CHECKPOINT_FILE.exists():
        return json.loads(CHECKPOINT_FILE.read_text())
    return None


def save_checkpoint(data: dict) -> None:
    CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_FILE.write_text(json.dumps(data, indent=2))


def clear_checkpoint() -> None:
    if CHECKPOINT_FILE.exists():
        CHECKPOINT_FILE.unlink()


# -- NVD API --


async def fetch_nvd_page(
    session,
    start_index: int,
    last_mod_start: str | None = None,
    last_mod_end: str | None = None,
    pub_start: str | None = None,
    pub_end: str | None = None,
) -> dict:
    """Fetch a page of CVEs from the NVD API 2.0."""
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    if last_mod_start:
        params["lastModStartDate"] = last_mod_start
    if last_mod_end:
        params["lastModEndDate"] = last_mod_end
    if pub_start:
        params["pubStartDate"] = pub_start
    if pub_end:
        params["pubEndDate"] = pub_end

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # NVD 2.0 frequently returns 403/429/503 under load; nvd_get_with_backoff
    # retries those (and transport errors) with capped exponential backoff,
    # honoring Retry-After. A persistent non-retryable status still raises here.
    resp = await nvd_get_with_backoff(session, NVD_API_URL, params=params, headers=headers)
    resp.raise_for_status()
    return resp.json()


def parse_cve_records(vulnerabilities: list[dict]) -> list[dict]:
    """Extract cve objects from NVD API response vulnerabilities array."""
    return [v["cve"] for v in vulnerabilities if "cve" in v]


# -- Database --


def _prepare_row(cve_data: dict, embedding: list[float] | None) -> tuple:
    """Prepare a single CVE record as a tuple for bulk insert."""
    metrics = cve_data.get("metrics", {})
    cvss_v31_score, cvss_v31_severity, cvss_v31_vector = extract_cvss_v31(metrics)
    cvss_v2_score, cvss_v2_severity = extract_cvss_v2(metrics)
    ssvc = extract_ssvc(metrics)
    emb = np.array(embedding, dtype=np.float32) if embedding else None

    return (
        cve_data.get("id"),
        extract_description(cve_data.get("descriptions", [])),
        cvss_v31_score,
        cvss_v31_severity,
        cvss_v31_vector,
        cvss_v2_score,
        cvss_v2_severity,
        extract_cwes(cve_data.get("weaknesses", [])),
        extract_affected_products(cve_data.get("configurations", [])),
        extract_reference_urls(cve_data.get("references", [])),
        parse_date(cve_data.get("published")),
        parse_date(cve_data.get("lastModified")),
        ssvc.get("exploitation"),
        ssvc.get("automatable"),
        ssvc.get("technical_impact"),
        ssvc.get("decision"),
        ssvc.get("version"),
        json.dumps(cve_data),
        build_content(cve_data),
        emb,
    )


async def upsert_batch(conn: asyncpg.Connection, cve_records: list[dict], embeddings: list[list[float]] | None) -> None:
    """Upsert a batch of CVE records using a temp table + INSERT ON CONFLICT."""
    rows = [_prepare_row(cve, embeddings[i] if embeddings else None) for i, cve in enumerate(cve_records)]

    async with conn.transaction():
        await conn.execute("DROP TABLE IF EXISTS _nvd_staging")
        await conn.execute(CREATE_STAGING_SQL)
        await conn.copy_records_to_table(
            "_nvd_staging",
            records=rows,
            columns=STAGING_COLUMNS,
        )
        await conn.execute(UPSERT_FROM_STAGING_SQL)


async def upsert_with_retry(dsn: str, cve_records: list[dict], embeddings: list[list[float]] | None) -> None:
    """Connect, upsert a batch, and retry on transient connection errors."""
    for attempt in range(MAX_RETRIES):
        try:
            conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
            await register_vector(conn)
            await conn.execute("SET statement_timeout = 0")
            await upsert_batch(conn, cve_records, embeddings)
            await conn.close()
            return
        except DB_RETRY_EXCEPTIONS as e:
            if attempt < MAX_RETRIES - 1:
                print(f"  DB connection error: {e}, retrying in 5s...")
                await asyncio.sleep(5)
            else:
                raise


# -- Embeddings --


async def generate_embeddings(
    openai_client: AsyncOpenAI,
    texts: list[str],
    already_loaded: int = 0,
    total: int = 0,
) -> list[list[float]]:
    """Generate embeddings in batches, splitting further if needed to stay under token limits."""
    all_embeddings: list[list[float]] = []
    for i in range(0, len(texts), EMBEDDING_BATCH_SIZE):
        batch = texts[i : i + EMBEDDING_BATCH_SIZE]
        batch_embeddings = await _embed_with_token_limit(openai_client, batch)
        all_embeddings.extend(batch_embeddings)
        batch_done = already_loaded + min(i + EMBEDDING_BATCH_SIZE, len(texts))
        suffix = f"/{total}" if total else ""
        print(f"  Embedded {batch_done}{suffix}")
    return all_embeddings


async def embed_and_upsert(
    dsn: str,
    cve_records: list[dict],
    openai_client: AsyncOpenAI | None,
    already_loaded: int = 0,
    total: int = 0,
) -> int:
    """Generate embeddings (if client provided) and upsert records. Returns count loaded."""
    suffix = f"/{total}" if total else ""
    embeddings = None
    if openai_client and cve_records:
        contents = [build_content(cve) for cve in cve_records]
        end = already_loaded + len(cve_records)
        print(f"  Generating embeddings for records {already_loaded + 1}–{end}{suffix}...")
        embeddings = await generate_embeddings(openai_client, contents, already_loaded=already_loaded, total=total)

    end = already_loaded + len(cve_records)
    print(f"  Upserting records {already_loaded + 1}–{end}{suffix}...")
    upsert_start = time.time()
    await upsert_with_retry(dsn, cve_records, embeddings)
    print(f"  Upserted in {format_elapsed(upsert_start)}")
    return len(cve_records)


# -- Full load --


async def _get_total_results(start_index: int) -> tuple[dict, int, int]:
    """Fetch the first page and return (page_data, total_results, total_pages)."""
    import httpx

    print("Fetching first page to determine total CVE count...")
    async with httpx.AsyncClient(timeout=60) as session:
        first_page = await fetch_nvd_page(session, start_index)

    total_results = first_page.get("totalResults", 0)
    total_pages = (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
    print(f"Total CVEs in NVD: {total_results} ({total_pages} pages)")
    return first_page, total_results, total_pages


async def _process_full_load_page(
    session,
    current_index: int,
    first_page: dict | None,
    openai_client: AsyncOpenAI | None,
    dsn: str,
) -> int:
    """Fetch one page, embed, and upsert. Returns number of records loaded."""
    if first_page is not None:
        data = first_page
    else:
        data = await fetch_nvd_page(session, current_index)
        await asyncio.sleep(REQUEST_DELAY)

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        print("  No vulnerabilities in response, advancing...")
        return 0

    cve_records = parse_cve_records(vulnerabilities)
    return await embed_and_upsert(dsn, cve_records, openai_client)


async def full_load(args) -> None:
    """Fetch all CVEs from NVD API using pagination."""
    import httpx

    dsn = settings.get_database_dsn()

    checkpoint = load_checkpoint()
    start_index = 0
    if checkpoint and checkpoint.get("mode") == "full":
        start_index = checkpoint["start_index"]
        print(f"Resuming from checkpoint at index {start_index}")

    first_page, total_results, total_pages = await _get_total_results(start_index)

    openai_client = None
    if not args.skip_embeddings:
        openai_client = AsyncOpenAI(api_key=settings.openai_api_key)

    started_at = time.time()
    total_loaded = 0
    current_index = start_index
    page_num = current_index // RESULTS_PER_PAGE + 1

    async with httpx.AsyncClient(timeout=60) as session:
        while current_index < total_results:
            if args.limit and page_num > args.limit + (start_index // RESULTS_PER_PAGE):
                print(f"Reached page limit ({args.limit}), stopping.")
                break

            print(
                f"Page {page_num}/{total_pages} | index {current_index}/{total_results}"
                f" | elapsed: {format_elapsed(started_at)}"
            )

            use_first_page = first_page if current_index == start_index else None
            loaded = await _process_full_load_page(
                session,
                current_index,
                use_first_page,
                openai_client,
                dsn,
            )

            total_loaded += loaded
            current_index += RESULTS_PER_PAGE
            page_num += 1

            save_checkpoint(
                {
                    "mode": "full",
                    "start_index": current_index,
                    "total_results": total_results,
                    "started_at": datetime.now(UTC).isoformat(),
                }
            )

    clear_checkpoint()
    print(f"Done! Loaded {total_loaded} CVEs in {format_elapsed(started_at)}")


# -- Incremental sync --


async def _sync_window(
    session,
    start_str: str,
    end_str: str,
    openai_client: AsyncOpenAI | None,
    dsn: str,
    label: str = "modified",
    pub_filter: bool = False,
) -> int:
    """Paginate through one date window, returning total records synced.

    Set pub_filter=True to filter by pubStartDate/pubEndDate instead of lastModStartDate/lastModEndDate.
    """
    loaded = 0
    current_index = 0

    while True:
        if pub_filter:
            data = await fetch_nvd_page(session, current_index, pub_start=start_str, pub_end=end_str)
        else:
            data = await fetch_nvd_page(session, current_index, last_mod_start=start_str, last_mod_end=end_str)
        await asyncio.sleep(REQUEST_DELAY)

        total_in_window = data.get("totalResults", 0)
        if current_index == 0:
            print(f"  {total_in_window} {label} CVEs in this window")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        cve_records = parse_cve_records(vulnerabilities)
        loaded += await embed_and_upsert(dsn, cve_records, openai_client, already_loaded=loaded, total=total_in_window)
        current_index += RESULTS_PER_PAGE

        if current_index >= total_in_window:
            break

    return loaded


async def incremental_sync(since: str | None = None, skip_embeddings: bool = False) -> dict[str, int]:
    """Fetch CVEs published or modified since the last sync.

    Runs two phases: new CVEs (by published date) first, then modified CVEs.
    This ensures newly published vulnerabilities are available immediately
    rather than being buried behind ~76k metadata-refresh updates.
    """
    import httpx

    dsn = settings.get_database_dsn()
    conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
    row = await conn.fetchrow(
        "SELECT MAX(last_modified) as max_modified, MAX(published) as max_published FROM nvd_vulnerabilities"
    )
    await conn.close()

    if not row or not row["max_modified"]:
        print("No existing records found. Run a full load first.")
        return {"new": 0, "modified": 0, "synced": 0}

    now = datetime.now(UTC)

    if since:
        mod_high_water = datetime.fromisoformat(since).replace(tzinfo=UTC)
        pub_high_water = mod_high_water
        print(f"Overriding start date to {mod_high_water.date()} (--since)")
    else:
        mod_high_water = datetime.combine(row["max_modified"], datetime.min.time(), tzinfo=UTC)
        pub_high_water = datetime.combine(row["max_published"], datetime.min.time(), tzinfo=UTC)

    openai_client = None
    if not skip_embeddings:
        openai_client = AsyncOpenAI(api_key=settings.openai_api_key)

    new_loaded = 0
    modified_loaded = 0
    started_at = time.time()

    async with httpx.AsyncClient(timeout=60) as session:
        # Phase 1: newly published CVEs
        print(f"\nPhase 1 — new CVEs published from {pub_high_water.date()} to {now.date()}")
        window_start = pub_high_water
        while window_start < now:
            window_end = min(window_start + timedelta(days=120), now)
            start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            print(f"Window: {window_start.date()} to {window_end.date()}")
            new_loaded += await _sync_window(
                session, start_str, end_str, openai_client, dsn, label="new", pub_filter=True
            )
            window_start = window_end

        # Phase 2: modified CVEs (includes new ones again, but upsert is idempotent)
        print(f"\nPhase 2 — CVEs modified from {mod_high_water.date()} to {now.date()}")
        window_start = mod_high_water
        while window_start < now:
            window_end = min(window_start + timedelta(days=120), now)
            start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            print(f"Window: {window_start.date()} to {window_end.date()}")
            modified_loaded += await _sync_window(
                session, start_str, end_str, openai_client, dsn, label="modified", pub_filter=False
            )
            window_start = window_end

    total_loaded = new_loaded + modified_loaded
    print(f"\nDone! Synced {total_loaded} CVEs in {format_elapsed(started_at)}")
    return {"new": new_loaded, "modified": modified_loaded, "synced": total_loaded}


async def run_incremental() -> LoaderReport:
    """ETL-orchestrator entrypoint: plain incremental sync with a structured report."""
    rate_info = "with API key (50 req/30s)" if NVD_API_KEY else "without API key (5 req/30s)"
    print(f"NVD Full ETL | Rate limiting: {rate_info}")
    counts = await incremental_sync()
    summary = f"Synced {counts['synced']} CVEs ({counts['new']} new, {counts['modified']} modified)"
    return LoaderReport(summary=summary, metrics=counts)


BACKFILL_MAX_RETRIES = 5


# -- Backfill embeddings --

# OpenAI allows max 300k tokens per embedding request; rough estimate ~4 chars/token.
# Use a conservative limit to stay safely under the cap.
MAX_TOKENS_PER_REQUEST = 250_000
CHARS_PER_TOKEN_ESTIMATE = 4
MAX_CHARS_PER_TEXT = 8000 * 4  # ~8000 tokens per input, model hard limit is 8191


async def _embed_with_token_limit(openai_client: AsyncOpenAI, texts: list[str]) -> list[list[float]]:
    """Split texts into sub-batches that fit within the API token limit and embed them."""
    sub_batches: list[list[str]] = []
    current_batch: list[str] = []
    current_tokens = 0

    for text in texts:
        text = text[:MAX_CHARS_PER_TEXT]
        est_tokens = len(text) // CHARS_PER_TOKEN_ESTIMATE
        if current_batch and current_tokens + est_tokens > MAX_TOKENS_PER_REQUEST:
            sub_batches.append(current_batch)
            current_batch = []
            current_tokens = 0
        current_batch.append(text)
        current_tokens += est_tokens

    if current_batch:
        sub_batches.append(current_batch)

    all_embeddings: list[list[float]] = []
    for i, batch in enumerate(sub_batches):
        if len(sub_batches) > 1:
            print(f"    Embedding sub-batch {i + 1}/{len(sub_batches)} ({len(batch)} texts)")
        for embed_attempt in range(3):
            try:
                resp = await openai_client.embeddings.create(model=settings.embedding_model, input=batch, timeout=60)
                all_embeddings.extend(item.embedding for item in resp.data)
                break
            except Exception as e:
                if embed_attempt < 2:
                    wait = 2**embed_attempt
                    print(f"  Embedding API error: {e}, retrying in {wait}s...")
                    await asyncio.sleep(wait)
                else:
                    raise

    return all_embeddings


async def _backfill_batch(dsn: str, openai_client: AsyncOpenAI) -> int:
    """Fetch one batch of rows missing embeddings, generate and save them. Returns count processed."""
    for attempt in range(BACKFILL_MAX_RETRIES):
        try:
            conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
            await conn.execute("SET statement_timeout = 0")
            await register_vector(conn)

            rows = await conn.fetch(
                """
                SELECT cve_id, content FROM nvd_vulnerabilities
                WHERE embedding IS NULL
                ORDER BY cve_id
                LIMIT $1
                """,
                BACKFILL_BATCH_SIZE,
            )

            if not rows:
                await conn.close()
                return 0

            texts = [row["content"] for row in rows]
            cve_ids = [row["cve_id"] for row in rows]

            embeddings = await _embed_with_token_limit(openai_client, texts)

            embedding_vectors = [Vector(emb) for emb in embeddings]
            await conn.execute(
                """
                UPDATE nvd_vulnerabilities AS n
                SET embedding = u.embedding
                FROM unnest($1::varchar[], $2::vector[]) AS u(cve_id, embedding)
                WHERE n.cve_id = u.cve_id
                """,
                cve_ids,
                embedding_vectors,
            )

            await conn.close()
            return len(rows)
        except DB_RETRY_EXCEPTIONS as e:
            with contextlib.suppress(Exception):
                await conn.close()
            if attempt < BACKFILL_MAX_RETRIES - 1:
                wait = 5 * (2**attempt)
                print(f"  Connection error: {e}, retrying in {wait}s...")
                await asyncio.sleep(wait)
            else:
                raise
    return 0


async def backfill_embeddings() -> None:
    """Generate embeddings for records that don't have them."""
    print(
        "TIP: Run with 'caffeinate -i' to prevent sleep: "
        "caffeinate -i uv run python scripts/load_nvd_full.py --backfill-embeddings"
    )

    dsn = settings.get_database_dsn()
    openai_client = AsyncOpenAI(api_key=settings.openai_api_key)

    conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
    await conn.execute("SET statement_timeout = 0")
    await register_vector(conn)
    total = await conn.fetchval("SELECT COUNT(*) FROM nvd_vulnerabilities WHERE embedding IS NULL")
    await conn.close()

    print(f"Found {total} records without embeddings")
    if total == 0:
        return

    processed = 0
    while processed < total:
        batch_count = await _backfill_batch(dsn, openai_client)
        if batch_count == 0:
            break
        processed += batch_count
        print(f"  Backfilled {processed}/{total}")

    print(f"Done! Backfilled embeddings for {processed} records")


async def backfill_ssvc() -> None:
    """Populate the five SSVC columns from raw_json for already-synced rows.

    Pure SQL/Python — no NVD API calls. Reads metrics.ssvcV203 out of raw_json
    via extract_ssvc() and writes the typed columns. Idempotent and resumable:
    keyset pagination over cve_id visits each SSVC-bearing row exactly once per
    pass, so a row whose factors resolve to NULL can't cause a re-select loop.
    """
    dsn = settings.get_database_dsn()
    conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
    await conn.execute("SET statement_timeout = 0")
    try:
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM nvd_vulnerabilities WHERE raw_json->'metrics' ? 'ssvcV203'"
        )
        print(f"Found {total} records with SSVC data in raw_json")
        if not total:
            return

        processed = 0
        after = ""  # keyset cursor on cve_id ("" sorts before any real CVE ID)
        while True:
            rows = await conn.fetch(
                """
                SELECT cve_id, raw_json->'metrics' AS metrics
                FROM nvd_vulnerabilities
                WHERE raw_json->'metrics' ? 'ssvcV203' AND cve_id > $1
                ORDER BY cve_id
                LIMIT $2
                """,
                after,
                SSVC_BACKFILL_BATCH_SIZE,
            )
            if not rows:
                break

            params = []
            for row in rows:
                metrics = row["metrics"]
                if isinstance(metrics, str):  # asyncpg returns jsonb as text
                    metrics = json.loads(metrics)
                ssvc = extract_ssvc(metrics or {})
                params.append(
                    (
                        row["cve_id"],
                        ssvc.get("exploitation"),
                        ssvc.get("automatable"),
                        ssvc.get("technical_impact"),
                        ssvc.get("decision"),
                        ssvc.get("version"),
                    )
                )

            await conn.executemany(
                """
                UPDATE nvd_vulnerabilities SET
                    ssvc_exploitation = $2,
                    ssvc_automatable = $3,
                    ssvc_technical_impact = $4,
                    ssvc_decision = $5,
                    ssvc_version = $6
                WHERE cve_id = $1
                """,
                params,
            )
            processed += len(rows)
            after = rows[-1]["cve_id"]
            print(f"  Backfilled {processed}/{total}")

        print(f"Done! Backfilled SSVC columns for {processed} records")
    finally:
        await conn.close()


# -- Entrypoint --


async def main() -> None:
    parser = argparse.ArgumentParser(description="Full NVD ETL")
    parser.add_argument("--incremental", action="store_true", help="Sync changes since last run")
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        metavar="DATE",
        help="Override incremental start date (YYYY-MM-DD); use after an interrupted run",
    )
    parser.add_argument("--skip-embeddings", action="store_true", help="Load data without generating embeddings")
    parser.add_argument("--backfill-embeddings", action="store_true", help="Generate embeddings for rows missing them")
    parser.add_argument(
        "--backfill-ssvc",
        action="store_true",
        help="Populate SSVC columns from raw_json (pure SQL/Python, no API)",
    )
    parser.add_argument("--limit", type=int, default=None, help="Limit to N pages (for testing)")
    args = parser.parse_args()

    rate_info = "with API key (50 req/30s)" if NVD_API_KEY else "without API key (5 req/30s)"
    print(f"NVD Full ETL | Rate limiting: {rate_info}")

    if args.backfill_ssvc:
        await backfill_ssvc()
    elif args.backfill_embeddings:
        await backfill_embeddings()
    elif args.incremental:
        await incremental_sync(since=args.since, skip_embeddings=args.skip_embeddings)
    else:
        print("Connecting to database...")
        dsn = settings.get_database_dsn()
        conn = await asyncpg.connect(dsn=dsn, timeout=DB_CONNECT_TIMEOUT)
        print("Connected. Ensuring schema...")
        from rag.database import SCHEMA_SQL

        await conn.execute(SCHEMA_SQL)
        await conn.close()
        print("Schema verified.")
        await full_load(args)


if __name__ == "__main__":
    asyncio.run(main())
