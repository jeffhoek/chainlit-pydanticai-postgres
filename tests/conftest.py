import os

# Must be set before any project module is imported so Settings() validation passes.
os.environ.setdefault("OPENAI_API_KEY", "sk-test-placeholder")
# Importing app.py constructs the pydantic-ai Agent, which resolves the Anthropic
# provider and requires this key even though tests never call the model.
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test-placeholder")
# Chainlit's @cl.oauth_callback raises at import time unless at least one OAuth
# provider is configured. Placeholders satisfy that check; tests never hit GitHub.
os.environ.setdefault("OAUTH_GITHUB_CLIENT_ID", "test-client-id")
os.environ.setdefault("OAUTH_GITHUB_CLIENT_SECRET", "test-client-secret")
# app.py refuses to import with an empty ADMIN_SECRET (the /admin startup guard).
os.environ.setdefault("ADMIN_SECRET", "test-admin-secret")

from unittest.mock import AsyncMock, MagicMock

import asyncpg
import numpy as np
import pytest
from pgvector.asyncpg import register_vector

from rag.database import SCHEMA_SQL
from rag.risk import refresh_sql, view_ddl
from rag.vector_store import PgVectorStore

# Unit embeddings used for seeded golden data.
# kev row closest to GOLDEN_KEV; nvd row closest to GOLDEN_NVD.
GOLDEN_KEV_EMBEDDING: list[float] = [1.0] + [0.0] * 1535
GOLDEN_NVD_EMBEDDING: list[float] = [0.0, 1.0] + [0.0] * 1534


async def _init_connection(conn: asyncpg.Connection) -> None:
    await register_vector(conn)


async def _seed_tables(conn: asyncpg.Connection) -> None:
    await conn.execute(SCHEMA_SQL)
    # view_ddl() drops and recreates, so a stale v_cve_risk from an earlier revision
    # of rag/risk.py can't wedge the run.
    await conn.execute(view_ddl())
    await conn.execute(
        """
        INSERT INTO kev_vulnerabilities (cve_id, content, embedding)
        VALUES ($1, $2, $3)
        ON CONFLICT (cve_id) DO UPDATE
            SET content = EXCLUDED.content, embedding = EXCLUDED.embedding
        """,
        "CVE-2021-44228",
        "Log4Shell remote code execution vulnerability in Apache Log4j2",
        np.array(GOLDEN_KEV_EMBEDDING, dtype=np.float32),
    )
    await conn.execute(
        """
        INSERT INTO nvd_vulnerabilities (cve_id, content, embedding)
        VALUES ($1, $2, $3)
        ON CONFLICT (cve_id) DO UPDATE
            SET content = EXCLUDED.content, embedding = EXCLUDED.embedding
        """,
        "CVE-2021-34527",
        "PrintNightmare Windows Print Spooler privilege escalation vulnerability",
        np.array(GOLDEN_NVD_EMBEDDING, dtype=np.float32),
    )
    # v_cve_risk is materialized — a snapshot, not a live query — so rows inserted
    # after it was created are invisible until refreshed. Every fixture that seeds
    # data the view should see has to do this.
    await conn.execute(refresh_sql())


@pytest.fixture(scope="session")
async def db_pool() -> asyncpg.Pool:
    pool = await asyncpg.create_pool(
        dsn=os.environ["TEST_DATABASE_URL"],
        min_size=1,
        max_size=5,
        init=_init_connection,
    )
    yield pool
    await pool.close()


@pytest.fixture(scope="session")
async def seeded_pool(db_pool: asyncpg.Pool) -> asyncpg.Pool:
    async with db_pool.acquire() as conn:
        await _seed_tables(conn)
    return db_pool


@pytest.fixture
def mock_openai() -> AsyncMock:
    client = AsyncMock()
    embedding_data = MagicMock()
    embedding_data.embedding = GOLDEN_KEV_EMBEDDING
    response = MagicMock()
    response.data = [embedding_data]
    client.embeddings.create = AsyncMock(return_value=response)
    return client


@pytest.fixture(autouse=False)
def mock_settings(monkeypatch) -> None:
    import config

    monkeypatch.setattr(config.settings, "embedding_model", "text-embedding-3-small")


@pytest.fixture(scope="session")
async def vector_store(seeded_pool: asyncpg.Pool) -> PgVectorStore:
    return PgVectorStore(seeded_pool)
