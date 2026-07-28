import asyncpg
from pgvector.asyncpg import register_vector

from config import settings

_pool: asyncpg.Pool | None = None

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    short_description TEXT,
    required_action TEXT,
    notes TEXT,
    date_added DATE,
    due_date DATE,
    known_ransomware_campaign_use VARCHAR(20),
    cwes TEXT[],
    content TEXT NOT NULL,
    embedding vector(1536)
);

CREATE INDEX IF NOT EXISTS kev_embedding_idx
    ON kev_vulnerabilities
    USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
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
    content TEXT NOT NULL,
    embedding vector(1536)
);

-- Migration: add raw_json to existing tables
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS raw_json JSONB;

-- Migration: add CISA-ADP SSVC v2.0.3 factor columns (see plans/ssvc-affected-integration.md)
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_exploitation     VARCHAR(8);   -- none|poc|active
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_automatable      VARCHAR(4);   -- yes|no
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_technical_impact VARCHAR(8);   -- partial|total
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision         VARCHAR(8);   -- Act|Attend|Track|Track* (nullable)
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_version          VARCHAR(8);   -- "2.0.3"

CREATE INDEX IF NOT EXISTS nvd_embedding_idx
    ON nvd_vulnerabilities
    USING hnsw (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS nvd_raw_json_gin_idx
    ON nvd_vulnerabilities USING gin (raw_json jsonb_path_ops);

CREATE INDEX IF NOT EXISTS nvd_ssvc_exploitation_idx
    ON nvd_vulnerabilities (ssvc_exploitation);

CREATE INDEX IF NOT EXISTS nvd_ssvc_decision_idx
    ON nvd_vulnerabilities (ssvc_decision);

CREATE INDEX IF NOT EXISTS nvd_vuln_status_idx
    ON nvd_vulnerabilities ((raw_json->>'vulnStatus'));

CREATE TABLE IF NOT EXISTS cwe_definitions (
    cwe_id      VARCHAR(20) PRIMARY KEY,
    name        TEXT NOT NULL,
    abstraction VARCHAR(20),
    description TEXT,
    url         TEXT
);

CREATE TABLE IF NOT EXISTS etl_runs (
    id            SERIAL PRIMARY KEY,
    run_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    status        VARCHAR(10) NOT NULL,        -- SUCCESS | FAILED
    total_elapsed NUMERIC(8,2) NOT NULL,       -- seconds
    results       JSONB        NOT NULL        -- per-loader list: label, ok, elapsed, summary, metrics, error
);

CREATE INDEX IF NOT EXISTS etl_runs_run_at_idx ON etl_runs (run_at DESC);

CREATE TABLE IF NOT EXISTS user_usage (
    id              SERIAL PRIMARY KEY,
    user_identifier TEXT     NOT NULL,
    query_date      DATE     NOT NULL DEFAULT CURRENT_DATE,
    query_count     INTEGER  NOT NULL DEFAULT 0,
    input_tokens    INTEGER  NOT NULL DEFAULT 0,
    output_tokens   INTEGER  NOT NULL DEFAULT 0,
    UNIQUE (user_identifier, query_date)
);
CREATE INDEX IF NOT EXISTS user_usage_date_idx ON user_usage (query_date DESC);
-- user_identifier-only index omitted: the UNIQUE (user_identifier, query_date) constraint
-- already creates a B-tree on both columns with user_identifier as the leading key, which
-- PostgreSQL can use for single-column lookups on user_identifier.
"""


async def _init_connection(conn: asyncpg.Connection) -> None:
    await register_vector(conn)


async def init_db() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool

    # On a fresh database the `vector` type doesn't exist yet, so register_vector()
    # (run by _init_connection on every pooled connection) would fail during pool
    # creation. Create the extension first on a plain connection so the type exists
    # before the pool opens. A read-only app role can't run DDL, so this is gated on
    # db_init_schema just like the rest of SCHEMA_SQL below
    # (see docs/supabase-readonly-role.md).
    if settings.db_init_schema:
        conn = await asyncpg.connect(dsn=settings.get_database_dsn())
        try:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        finally:
            await conn.close()

    _pool = await asyncpg.create_pool(
        dsn=settings.get_database_dsn(),
        min_size=2,
        max_size=10,
        init=_init_connection,
    )

    # A read-only app role can't run DDL; schema is created by the admin/ETL
    # connection instead (see settings.db_init_schema / docs/supabase-readonly-role.md).
    if settings.db_init_schema:
        async with _pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)

    return _pool


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized. Call init_db() first.")
    return _pool


async def close_db() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
