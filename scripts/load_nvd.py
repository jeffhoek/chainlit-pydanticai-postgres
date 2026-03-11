"""ETL script: Fetch NVD data for KEV CVEs, generate embeddings, and load into PostgreSQL.

Queries the NVD API 2.0 for each CVE ID found in the kev_vulnerabilities table,
enriching the dataset with CVSS scores, affected products, and detailed descriptions.

Usage: uv run python scripts/load_nvd.py

Set NVD_API_KEY env var to increase rate limit from 5 to 50 requests per 30 seconds.
"""

import asyncio
import datetime
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EMBEDDING_MODEL = "text-embedding-3-small"
BATCH_SIZE = 500

# Rate limiting: 5 req/30s without key, 50 req/30s with key
NVD_API_KEY = os.getenv("NVD_API_KEY")
REQUEST_DELAY = 0.7 if NVD_API_KEY else 6.0


def extract_cvss_v31(metrics: dict) -> tuple:
    """Extract CVSS v3.1 score, severity, and vector string."""
    for entry in metrics.get("cvssMetricV31", []):
        data = entry.get("cvssData", {})
        return (
            data.get("baseScore"),
            data.get("baseSeverity"),
            data.get("vectorString"),
        )
    return None, None, None


def extract_cvss_v2(metrics: dict) -> tuple:
    """Extract CVSS v2 score and severity."""
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        return data.get("baseScore"), entry.get("baseSeverity")
    return None, None


def extract_cwes(weaknesses: list) -> list[str]:
    """Extract CWE IDs from weaknesses."""
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                cwes.append(desc["value"])
    return cwes


def extract_affected_products(configurations: list) -> list[str]:
    """Extract CPE strings from configurations."""
    products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    products.append(match.get("criteria", ""))
    return products


def extract_description(descriptions: list) -> str:
    """Extract English description."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def extract_reference_urls(references: list) -> list[str]:
    """Extract reference URLs."""
    return [ref.get("url", "") for ref in references[:10]]


def parse_date(date_str: str | None) -> datetime.date | None:
    """Parse ISO-8601 date string to date object."""
    if not date_str:
        return None
    return datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()


def build_content(cve_data: dict) -> str:
    """Build content string for embedding from NVD CVE data."""
    description = extract_description(cve_data.get("descriptions", []))
    metrics = cve_data.get("metrics", {})
    cvss_score, cvss_severity, cvss_vector = extract_cvss_v31(metrics)
    cwes = extract_cwes(cve_data.get("weaknesses", []))
    products = extract_affected_products(cve_data.get("configurations", []))

    parts = [
        f"CVE ID: {cve_data.get('id', '')}",
        f"Description: {description}",
    ]
    if cvss_score is not None:
        parts.append(f"CVSS v3.1 Score: {cvss_score} ({cvss_severity})")
    if cvss_vector:
        parts.append(f"CVSS Vector: {cvss_vector}")
    if cwes:
        parts.append(f"CWEs: {', '.join(cwes)}")
    if products:
        parts.append(f"Affected Products: {', '.join(products[:5])}")

    return "\n".join(parts)


async def fetch_kev_cve_ids(conn: asyncpg.Connection) -> list[str]:
    """Get all CVE IDs from the KEV table."""
    rows = await conn.fetch("SELECT cve_id FROM kev_vulnerabilities ORDER BY cve_id")
    return [row["cve_id"] for row in rows]


async def fetch_nvd_cve(client: httpx.AsyncClient, cve_id: str) -> dict | None:
    """Fetch a single CVE from the NVD API."""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0].get("cve")


async def fetch_all_nvd(cve_ids: list[str]) -> list[dict]:
    """Fetch NVD data for all CVE IDs with rate limiting."""
    results = []
    skipped = 0

    async with httpx.AsyncClient(timeout=30) as client:
        for i, cve_id in enumerate(cve_ids):
            try:
                cve_data = await fetch_nvd_cve(client, cve_id)
                if cve_data:
                    results.append(cve_data)
                else:
                    skipped += 1
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    print(f"  Rate limited at {cve_id}, waiting 30s...")
                    await asyncio.sleep(30)
                    cve_data = await fetch_nvd_cve(client, cve_id)
                    if cve_data:
                        results.append(cve_data)
                else:
                    print(f"  Error fetching {cve_id}: {e}")
                    skipped += 1
            except Exception as e:
                print(f"  Error fetching {cve_id}: {e}")
                skipped += 1

            if (i + 1) % 50 == 0:
                print(f"  Fetched {i + 1}/{len(cve_ids)} ({len(results)} found, {skipped} skipped)")

            await asyncio.sleep(REQUEST_DELAY)

    print(f"  Fetched {len(results)} NVD records ({skipped} skipped)")
    return results


async def generate_embeddings(openai_client: AsyncOpenAI, texts: list[str]) -> list[list[float]]:
    """Generate embeddings in batches."""
    all_embeddings = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i : i + BATCH_SIZE]
        resp = await openai_client.embeddings.create(model=EMBEDDING_MODEL, input=batch)
        all_embeddings.extend([item.embedding for item in resp.data])
        print(f"  Embedded {min(i + BATCH_SIZE, len(texts))}/{len(texts)}")
    return all_embeddings


async def upsert_records(conn: asyncpg.Connection, cve_records: list[dict], embeddings: list[list[float]]) -> None:
    """Upsert NVD records into PostgreSQL."""
    for i, (cve_data, emb) in enumerate(zip(cve_records, embeddings)):
        metrics = cve_data.get("metrics", {})
        cvss_v31_score, cvss_v31_severity, cvss_v31_vector = extract_cvss_v31(metrics)
        cvss_v2_score, cvss_v2_severity = extract_cvss_v2(metrics)

        await conn.execute(
            """
            INSERT INTO nvd_vulnerabilities (
                cve_id, description, cvss_v31_score, cvss_v31_severity,
                cvss_v31_vector, cvss_v2_score, cvss_v2_severity,
                cwes, affected_products, reference_urls,
                published, last_modified, content, embedding
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding
            """,
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
            build_content(cve_data),
            np.array(emb, dtype=np.float32),
        )
        if (i + 1) % 500 == 0:
            print(f"  Upserted {i + 1}/{len(cve_records)}")

    print(f"  Upserted {len(cve_records)}/{len(cve_records)} total")


async def main() -> None:
    print("Starting NVD ETL (scoped to KEV CVEs)...")
    rate_info = "with API key (50 req/30s)" if NVD_API_KEY else "without API key (5 req/30s)"
    print(f"  Rate limiting: {rate_info}")

    # Connect to database
    print("Connecting to PostgreSQL...")
    conn = await asyncpg.connect(dsn=settings.get_database_dsn())
    from rag.database import SCHEMA_SQL
    await conn.execute(SCHEMA_SQL)
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

    if not new_ids:
        print("All NVD records already loaded. Nothing to do.")
        await conn.close()
        return

    # Fetch NVD data
    print(f"Fetching {len(new_ids)} CVEs from NVD API...")
    cve_records = await fetch_all_nvd(new_ids)
    if not cve_records:
        print("No NVD records fetched. Exiting.")
        await conn.close()
        return

    # Build content and generate embeddings
    contents = [build_content(cve) for cve in cve_records]
    print("Generating embeddings...")
    openai_client = AsyncOpenAI(api_key=settings.openai_api_key)
    embeddings = await generate_embeddings(openai_client, contents)

    # Upsert
    print("Upserting records...")
    await upsert_records(conn, cve_records, embeddings)
    await conn.close()

    print(f"Done! Loaded {len(cve_records)} NVD records.")


if __name__ == "__main__":
    asyncio.run(main())
