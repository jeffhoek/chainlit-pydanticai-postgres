"""ETL script: Fetch CISA KEV data, generate embeddings, and load into PostgreSQL.

Usage: uv run python scripts/load_kev.py
"""

import asyncio
import datetime
import sys
from pathlib import Path

# Add project root to path so we can import config/rag modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg
import httpx
import numpy as np
from openai import AsyncOpenAI
from pgvector.asyncpg import register_vector

from config import settings

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EMBEDDING_MODEL = "text-embedding-3-small"
BATCH_SIZE = 500


def build_content(vuln: dict) -> str:
    """Concatenate vulnerability fields into a single text block for embedding."""
    parts = [
        f"CVE ID: {vuln.get('cveID', '')}",
        f"Vendor/Project: {vuln.get('vendorProject', '')}",
        f"Product: {vuln.get('product', '')}",
        f"Vulnerability Name: {vuln.get('vulnerabilityName', '')}",
        f"Description: {vuln.get('shortDescription', '')}",
        f"Required Action: {vuln.get('requiredAction', '')}",
        f"Date Added: {vuln.get('dateAdded', '')}",
        f"Due Date: {vuln.get('dueDate', '')}",
        f"Known Ransomware Campaign Use: {vuln.get('knownRansomwareCampaignUse', '')}",
    ]
    if vuln.get("notes"):
        parts.append(f"Notes: {vuln['notes']}")
    if vuln.get("cwes"):
        parts.append(f"CWEs: {', '.join(vuln['cwes'])}")
    return "\n".join(parts)


async def fetch_kev_data() -> list[dict]:
    """Fetch the CISA KEV JSON feed."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    print(f"Fetched {len(vulns)} vulnerabilities from CISA KEV")
    return vulns


async def generate_embeddings(openai_client: AsyncOpenAI, texts: list[str]) -> list[list[float]]:
    """Generate embeddings in batches."""
    all_embeddings = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i : i + BATCH_SIZE]
        resp = await openai_client.embeddings.create(model=EMBEDDING_MODEL, input=batch)
        all_embeddings.extend([item.embedding for item in resp.data])
        print(f"  Embedded {min(i + BATCH_SIZE, len(texts))}/{len(texts)}")
    return all_embeddings


async def upsert_records(conn: asyncpg.Connection, vulns: list[dict], embeddings: list[list[float]]) -> None:
    """Upsert vulnerability records into PostgreSQL."""
    for i, (vuln, emb) in enumerate(zip(vulns, embeddings)):
        cwes = vuln.get("cwes") or []
        await conn.execute(
            """
            INSERT INTO kev_vulnerabilities (
                cve_id, vendor_project, product, vulnerability_name,
                short_description, required_action, notes,
                date_added, due_date, known_ransomware_campaign_use,
                cwes, content, embedding
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT (cve_id) DO UPDATE SET
                vendor_project = EXCLUDED.vendor_project,
                product = EXCLUDED.product,
                vulnerability_name = EXCLUDED.vulnerability_name,
                short_description = EXCLUDED.short_description,
                required_action = EXCLUDED.required_action,
                notes = EXCLUDED.notes,
                date_added = EXCLUDED.date_added,
                due_date = EXCLUDED.due_date,
                known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
                cwes = EXCLUDED.cwes,
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding
            """,
            vuln.get("cveID"),
            vuln.get("vendorProject"),
            vuln.get("product"),
            vuln.get("vulnerabilityName"),
            vuln.get("shortDescription"),
            vuln.get("requiredAction"),
            vuln.get("notes"),
            datetime.date.fromisoformat(vuln["dateAdded"]) if vuln.get("dateAdded") else None,
            datetime.date.fromisoformat(vuln["dueDate"]) if vuln.get("dueDate") else None,
            vuln.get("knownRansomwareCampaignUse"),
            cwes,
            build_content(vuln),
            np.array(emb, dtype=np.float32),
        )
        if (i + 1) % 500 == 0:
            print(f"  Upserted {i + 1}/{len(vulns)}")

    print(f"  Upserted {len(vulns)}/{len(vulns)} total")


async def main() -> None:
    print("Starting CISA KEV ETL...")

    # Fetch data
    vulns = await fetch_kev_data()
    if not vulns:
        print("No vulnerabilities found. Exiting.")
        return

    # Build content strings
    contents = [build_content(v) for v in vulns]

    # Generate embeddings
    print("Generating embeddings...")
    openai_client = AsyncOpenAI(api_key=settings.openai_api_key)
    embeddings = await generate_embeddings(openai_client, contents)

    # Connect and load
    print("Connecting to PostgreSQL...")
    conn = await asyncpg.connect(dsn=settings.get_database_dsn())

    # Create extension and table before registering the vector codec
    from rag.database import SCHEMA_SQL
    await conn.execute(SCHEMA_SQL)
    await register_vector(conn)

    print("Upserting records...")
    await upsert_records(conn, vulns, embeddings)
    await conn.close()

    print(f"Done! Loaded {len(vulns)} KEV records.")


if __name__ == "__main__":
    asyncio.run(main())
