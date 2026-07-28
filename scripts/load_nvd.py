"""ETL script: Fetch NVD data for KEV CVEs, generate embeddings, and load into PostgreSQL.

Queries the NVD API 2.0 for each CVE ID found in the kev_vulnerabilities table,
enriching the dataset with CVSS scores, affected products, and detailed descriptions.

Usage: uv run python scripts/load_nvd.py

Set NVD_API_KEY env var to increase rate limit from 5 to 50 requests per 30 seconds.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg
import httpx
import numpy as np
from openai import AsyncOpenAI
from pgvector.asyncpg import register_vector

from config import settings
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
BATCH_SIZE = 500

UPSERT_SQL = """
    INSERT INTO nvd_vulnerabilities (
        cve_id, description, cvss_v31_score, cvss_v31_severity,
        cvss_v31_vector, cvss_v2_score, cvss_v2_severity,
        cwes, affected_products, reference_urls,
        published, last_modified,
        ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
        ssvc_decision, ssvc_version,
        raw_json, content, embedding
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
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
        embedding = EXCLUDED.embedding
"""

# Rate limiting: 5 req/30s without key, 50 req/30s with key
NVD_API_KEY = os.getenv("NVD_API_KEY")
REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.0


async def fetch_kev_cve_ids(conn: asyncpg.Connection) -> list[str]:
    """Get all CVE IDs from the KEV table."""
    rows = await conn.fetch("SELECT cve_id FROM kev_vulnerabilities ORDER BY cve_id")
    return [row["cve_id"] for row in rows]


async def fetch_nvd_cve(client: httpx.AsyncClient, cve_id: str) -> dict | None:
    """Fetch a single CVE from the NVD API."""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # NVD 2.0 frequently returns 403/429/503 under load; back off and retry those
    # transient statuses instead of skipping the CVE on the first failure.
    resp = await nvd_get_with_backoff(client, NVD_API_URL, params={"cveId": cve_id}, headers=headers)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0].get("cve")


async def fetch_nvd_batch(
    client: httpx.AsyncClient, cve_ids: list[str], offset: int, total: int
) -> tuple[list[dict], int]:
    """Fetch a batch of CVEs from the NVD API. Returns (records, skipped)."""
    results = []
    skipped = 0

    for i, cve_id in enumerate(cve_ids):
        try:
            cve_data = await fetch_nvd_cve(client, cve_id)
            if cve_data:
                results.append(cve_data)
            else:
                skipped += 1
        except Exception as e:
            # Transient 403/429/5xx are already retried with backoff inside
            # fetch_nvd_cve; reaching here means the failure persisted, so skip it.
            print(f"  Error fetching {cve_id}: {e}")
            skipped += 1

        absolute = offset + i + 1
        if absolute % 50 == 0:
            print(f"  Fetched {absolute}/{total}")

        await asyncio.sleep(REQUEST_DELAY)

    return results, skipped


async def generate_embeddings(openai_client: AsyncOpenAI, texts: list[str]) -> list[list[float]]:
    """Generate embeddings in batches."""
    all_embeddings = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i : i + BATCH_SIZE]
        resp = await openai_client.embeddings.create(model=settings.embedding_model, input=batch)
        all_embeddings.extend([item.embedding for item in resp.data])
        print(f"  Embedded {min(i + BATCH_SIZE, len(texts))}/{len(texts)}")
    return all_embeddings


def build_upsert_params(cve_data: dict, embedding: list[float]) -> tuple:
    """Build the parameter tuple for a single NVD upsert."""
    metrics = cve_data.get("metrics", {})
    cvss_v31_score, cvss_v31_severity, cvss_v31_vector = extract_cvss_v31(metrics)
    cvss_v2_score, cvss_v2_severity = extract_cvss_v2(metrics)
    ssvc = extract_ssvc(metrics)

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
        np.array(embedding, dtype=np.float32),
    )


async def upsert_records(conn: asyncpg.Connection, cve_records: list[dict], embeddings: list[list[float]]) -> None:
    """Upsert NVD records into PostgreSQL."""
    for i, (cve_data, emb) in enumerate(zip(cve_records, embeddings, strict=True)):
        params = build_upsert_params(cve_data, emb)
        await conn.execute(UPSERT_SQL, *params)
        if (i + 1) % 500 == 0:
            print(f"  Upserted {i + 1}/{len(cve_records)}")

    print(f"  Upserted {len(cve_records)}/{len(cve_records)} total")


async def process_batch(
    client: httpx.AsyncClient,
    openai_client: AsyncOpenAI,
    dsn: str,
    batch_ids: list[str],
    batch_num: int,
    total_batches: int,
    offset: int,
    total: int,
) -> tuple[int, int]:
    """Fetch, embed, and upsert a single batch. Returns (loaded, skipped)."""
    print(f"Batch {batch_num}/{total_batches}: fetching {len(batch_ids)} CVEs...")

    cve_records, skipped = await fetch_nvd_batch(client, batch_ids, offset, total)

    if not cve_records:
        print(f"  No records in batch {batch_num}, skipping embed/upsert.")
        return 0, skipped

    contents = [build_content(cve) for cve in cve_records]
    print(f"  Generating embeddings for {len(cve_records)} records...")
    embeddings = await generate_embeddings(openai_client, contents)

    print(f"  Upserting {len(cve_records)} records...")
    conn = await asyncpg.connect(dsn=dsn)
    await register_vector(conn)
    await upsert_records(conn, cve_records, embeddings)
    await conn.close()

    print(f"  Batch {batch_num} complete. Total loaded so far: {len(cve_records)}")
    return len(cve_records), skipped


async def main() -> None:
    print("Starting NVD ETL (scoped to KEV CVEs)...")
    rate_info = "with API key (50 req/30s)" if NVD_API_KEY else "without API key (5 req/30s)"
    print(f"  Rate limiting: {rate_info}")

    # Connect to database for ID queries, then close.
    # Connection is reopened per batch to avoid idle timeout on long fetches.
    print("Connecting to PostgreSQL...")
    dsn = settings.get_database_dsn()
    conn = await asyncpg.connect(dsn=dsn)
    await register_vector(conn)

    # Get CVE IDs from KEV table
    cve_ids = await fetch_kev_cve_ids(conn)
    if not cve_ids:
        print("No KEV records found. Run load_kev.py first.")
        await conn.close()
        return
    print(f"Found {len(cve_ids)} CVE IDs in KEV table")

    # Check which CVE IDs already exist in NVD table
    existing = await conn.fetch("SELECT cve_id FROM nvd_vulnerabilities")
    existing_ids = {row["cve_id"] for row in existing}
    new_ids = [cve_id for cve_id in cve_ids if cve_id not in existing_ids]
    print(f"  {len(existing_ids)} already loaded, {len(new_ids)} new to fetch")
    await conn.close()

    if not new_ids:
        print("All NVD records already loaded. Nothing to do.")
        return

    # Process in batches: fetch → embed → upsert, then move to next batch.
    # A fresh DB connection is opened for each upsert to avoid idle timeout.
    print(f"Fetching {len(new_ids)} CVEs from NVD API (batch size: {BATCH_SIZE})...")
    openai_client = AsyncOpenAI(api_key=settings.openai_api_key)
    total_loaded = 0
    total_skipped = 0

    async with httpx.AsyncClient(timeout=30) as client:
        for batch_start in range(0, len(new_ids), BATCH_SIZE):
            batch_ids = new_ids[batch_start : batch_start + BATCH_SIZE]
            batch_num = batch_start // BATCH_SIZE + 1
            total_batches = (len(new_ids) + BATCH_SIZE - 1) // BATCH_SIZE

            loaded, skipped = await process_batch(
                client,
                openai_client,
                dsn,
                batch_ids,
                batch_num,
                total_batches,
                batch_start,
                len(new_ids),
            )
            total_loaded += loaded
            total_skipped += skipped

    print(f"Done! Loaded {total_loaded} NVD records ({total_skipped} skipped).")


if __name__ == "__main__":
    asyncio.run(main())
