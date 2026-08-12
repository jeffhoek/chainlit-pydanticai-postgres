import asyncpg
from pgvector.asyncpg import register_vector

from config import settings
from rag.risk import view_ddl

_pool: asyncpg.Pool | None = None

_TABLES_SQL = """
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
    ssvc_automatable VARCHAR(8),
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
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_automatable      VARCHAR(8);   -- yes|no
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_technical_impact VARCHAR(8);   -- partial|total
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_decision         VARCHAR(8);   -- Act|Attend|Track*
ALTER TABLE nvd_vulnerabilities ADD COLUMN IF NOT EXISTS ssvc_version          VARCHAR(8);   -- "2.0.3"

-- Migration: widen ssvc_automatable from its original VARCHAR(4). CISA back-publishes
-- its 2021-2022 decisions using SSVC v1's "Virulence" names (slow/rapid); 'rapid' is
-- 5 chars and aborted the whole NVD incremental sync when a routine NVD metadata
-- refresh touched four such CVEs on 2026-08-01. extract_ssvc() now maps slow->no /
-- rapid->yes, and the extra width keeps a future vocabulary change from being a hard stop.
--
-- Guarded because this whole file is replayed on every full load: ALTER COLUMN TYPE is
-- rejected outright whenever a view depends on the column, even when the type already
-- matches, so an unconditional statement here would break full loads on any database
-- carrying the v_cve_risk materialized view. Skipping when the width is already correct
-- makes the replay a no-op (and a fresh CREATE TABLE above is already VARCHAR(8)).
DO $$
DECLARE
    current_width int;
BEGIN
    SELECT character_maximum_length INTO current_width
    FROM information_schema.columns
    WHERE table_name = 'nvd_vulnerabilities' AND column_name = 'ssvc_automatable';

    IF current_width IS NULL OR current_width >= 8 THEN
        RETURN;  -- already widened, or column absent on a brand-new database
    END IF;

    -- A dependent view blocks the widen; Postgres's own error names the view but not
    -- the remedy, and v_cve_risk is created out-of-band rather than by this file.
    IF EXISTS (
        SELECT 1 FROM pg_depend d
        JOIN pg_rewrite r ON r.oid = d.objid
        WHERE d.refobjid = 'nvd_vulnerabilities'::regclass
          AND d.refobjsubid = (
              SELECT attnum FROM pg_attribute
              WHERE attrelid = 'nvd_vulnerabilities'::regclass
                AND attname = 'ssvc_automatable'
          )
          AND d.classid = 'pg_rewrite'::regclass
          AND r.ev_class <> 'nvd_vulnerabilities'::regclass
    ) THEN
        RAISE EXCEPTION
            'ssvc_automatable is still VARCHAR(4) but a view depends on it. '
            'Drop the dependent view(s), rerun this migration, then recreate them '
            '(as admin: DROP MATERIALIZED VIEW v_cve_risk; ALTER TABLE ...; CREATE MATERIALIZED VIEW ...).';
    END IF;

    ALTER TABLE nvd_vulnerabilities ALTER COLUMN ssvc_automatable TYPE VARCHAR(8);
END
$$;

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

-- FIRST.org EPSS daily scores (see plans/epss-score-integration.md).
-- Deliberately a separate narrow table rather than columns on nvd_vulnerabilities:
-- EPSS republishes every score daily, and under MVCC an UPDATE rewrites the whole
-- heap tuple — which there would mean rewriting raw_json and the 1536-dim embedding
-- (plus HNSW index maintenance) for all ~353k rows, every day.
-- No FK to nvd_vulnerabilities: the row sets only partially overlap in both
-- directions (EPSS skips REJECTED/RESERVED CVEs; it can also score a CVE before
-- our NVD sync picks it up), so consumers must LEFT JOIN.
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id               VARCHAR(20) PRIMARY KEY,  -- natural PK; no SERIAL, so no sequence grant
    probability          NUMERIC(6,5) NOT NULL,    -- 0–1 chance of exploitation in next 30 days
    percentile           NUMERIC(6,5) NOT NULL,    -- rank against all scored CVEs
    scored_at            DATE NOT NULL,            -- the feed's score_date
    model_version        VARCHAR(16),              -- e.g. 'v2026.06.15'
    previous_probability NUMERIC(6,5),             -- prior publication's score (movement queries)
    previous_scored_at   DATE
);

-- NUMERIC over REAL so threshold filters (WHERE probability >= 0.9) compare exactly;
-- binary float would let a stored 0.9 read as 0.89999998 and drop boundary rows.

CREATE INDEX IF NOT EXISTS epss_probability_idx ON epss_scores (probability DESC);

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

# Every base table in `public`. Kept as a Python constant, not just an array literal
# inside the SQL, so a unit test can assert it matches the CREATE TABLE statements
# above — a new table that slips into _TABLES_SQL without being listed here is
# exactly the mistake that produced the Supabase alert in the first place.
RLS_TABLES: tuple[str, ...] = (
    "kev_vulnerabilities",
    "nvd_vulnerabilities",
    "epss_scores",
    "cwe_definitions",
    "etl_runs",
    "user_usage",
)

_RLS_TABLE_ARRAY = ", ".join(f"'{name}'" for name in RLS_TABLES)

# Row-Level Security. See docs/supabase-rls.md.
#
# Supabase serves every table in `public` over the PostgREST Data API, where requests
# arrive as the built-in `anon` / `authenticated` roles — and Supabase's own default
# privileges grant those roles ALL on tables created here. RLS is therefore the only
# thing standing between a leaked publishable key and full read/write on the corpus,
# and its absence is what Supabase's linter reports as `rls_disabled_in_public`.
#
# Enabling it is not consequence-free: RLS applies to every role except the table
# owner, so `app_readonly` and `app_etl` (docs/supabase-readonly-role.md) go from
# working to silently returning zero rows the instant it is switched on. The policies
# below restore exactly the access the GRANTs already describe. A policy filters rows,
# it never confers a privilege, so `USING (true)` for both roles leaves the read-only
# and no-DELETE posture of those roles fully intact.
#
# Split out from _TABLES_SQL so production can apply just this part with the admin
# role (see docs/supabase-rls.md), the same way view_ddl() is applied.
RLS_SQL = f"""
DO $$
DECLARE
    tbl       text;
    api_roles text;
    app_roles text;
    protected text[] := ARRAY[{_RLS_TABLE_ARRAY}];
BEGIN
    -- Both role sets are resolved against pg_catalog first because none of them exist
    -- on a local dev or CI database: `anon` and `authenticated` are created by
    -- Supabase, `app_readonly` and `app_etl` by hand. REVOKE and CREATE POLICY have no
    -- IF EXISTS, so unguarded statements would abort this whole file off-Supabase.
    -- They are interpolated as a *list* rather than bound one at a time because
    -- neither statement accepts a role parameter.
    SELECT string_agg(quote_ident(rolname), ', ' ORDER BY rolname) INTO api_roles
    FROM pg_roles WHERE rolname IN ('anon', 'authenticated');

    SELECT string_agg(quote_ident(rolname), ', ' ORDER BY rolname) INTO app_roles
    FROM pg_roles WHERE rolname IN ('app_readonly', 'app_etl');

    FOREACH tbl IN ARRAY protected LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);

        -- CREATE POLICY has neither OR REPLACE nor IF NOT EXISTS; dropping first is
        -- what keeps this file replayable, which every other statement here relies on.
        EXECUTE format('DROP POLICY IF EXISTS app_roles_rw ON %I', tbl);

        IF app_roles IS NOT NULL THEN
            EXECUTE format(
                'CREATE POLICY app_roles_rw ON %I FOR ALL TO %s '
                'USING (true) WITH CHECK (true)', tbl, app_roles);
        END IF;

        -- Defence in depth behind the policies: with no grant at all, a Data API
        -- request never gets as far as the RLS check.
        IF api_roles IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON %I FROM %s', tbl, api_roles);
        END IF;
    END LOOP;

    IF api_roles IS NOT NULL THEN
        EXECUTE format(
            'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %s', api_roles);

        -- Supabase ships ALTER DEFAULT PRIVILEGES ... GRANT ALL ON TABLES TO anon,
        -- authenticated. Without countermanding it, the next table added to
        -- _TABLES_SQL arrives publicly readable again the moment it is created.
        -- Scoped to the role running this, which is the admin role that owns every
        -- object here — default privileges are per-creator, so that is the one that
        -- matters.
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
            'REVOKE ALL ON TABLES FROM %s', api_roles);
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
            'REVOKE ALL ON SEQUENCES FROM %s', api_roles);
    END IF;
END $$;
"""

SCHEMA_SQL = _TABLES_SQL + RLS_SQL


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
            # v_cve_risk is generated from the constants in rag/risk.py rather than
            # written out here, so the composite-score arithmetic has one home. It
            # must run after SCHEMA_SQL — the view reads all four base tables.
            #
            # Production runs DB_INIT_SCHEMA=false, so the view does NOT appear just
            # because it is in this code path; apply it with the admin role and
            # GRANT SELECT to app_readonly (see docs/risk-scoring.md).
            await conn.execute(view_ddl())

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
