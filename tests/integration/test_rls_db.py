"""Integration tests for RLS_SQL against a real database.

Requires TEST_DATABASE_URL env var. Fails loudly if absent.

Scope note: the test database has none of the Supabase roles (`anon`,
`authenticated`, `app_readonly`, `app_etl`), and creating them would mean mutating
cluster-wide state from a test run. So what these cover is the shape every developer
and CI run actually hits — RLS switched on, no policies attempted, and the owning
connection unaffected. The role-dependent half (policies created, Data API roles
revoked, app roles still able to read and write) is verified against the live project
by the steps in docs/supabase-rls.md.
"""

import uuid

import pytest

from rag.database import RLS_TABLES


async def test_rls_is_enabled_on_every_protected_table(seeded_pool):
    rows = await seeded_pool.fetch(
        "SELECT relname, relrowsecurity FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'"
    )
    enabled = {r["relname"]: r["relrowsecurity"] for r in rows}

    missing = [t for t in RLS_TABLES if not enabled.get(t)]
    assert not missing, f"RLS not enabled on: {missing}"


async def test_no_public_table_escapes_rls(seeded_pool):
    # Catches a table created outside SCHEMA_SQL as well as one that drifted out of
    # RLS_TABLES — on Supabase either is publicly readable over the Data API.
    unprotected = await seeded_pool.fetch(
        "SELECT relname FROM pg_class "
        "WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' "
        "  AND NOT relrowsecurity"
    )
    assert not [r["relname"] for r in unprotected]


async def test_no_policies_created_when_the_app_roles_are_absent(seeded_pool):
    # The guard in RLS_SQL: CREATE POLICY ... TO app_readonly would abort the whole
    # file on a database where that role was never created.
    have_roles = await seeded_pool.fetchval(
        "SELECT count(*) FROM pg_roles WHERE rolname IN ('app_readonly', 'app_etl')"
    )
    if have_roles:
        pytest.skip("test database has the Supabase app roles; guard not exercised")

    count = await seeded_pool.fetchval("SELECT count(*) FROM pg_policies WHERE schemaname = 'public'")
    assert count == 0


async def test_the_owning_connection_still_reads_and_writes(seeded_pool):
    # RLS exempts the table owner, which is what keeps local dev and the ETL's admin
    # path working without a single policy.
    user_id = f"github:rls-{uuid.uuid4()}"
    await seeded_pool.execute(
        "INSERT INTO user_usage (user_identifier, query_count) VALUES ($1, 1) "
        "ON CONFLICT (user_identifier, query_date) DO UPDATE "
        "SET query_count = user_usage.query_count + 1",
        user_id,
    )
    count = await seeded_pool.fetchval(
        "SELECT query_count FROM user_usage WHERE user_identifier = $1 AND query_date = CURRENT_DATE",
        user_id,
    )
    assert count == 1

    rows = await seeded_pool.fetchval("SELECT count(*) FROM kev_vulnerabilities")
    assert rows > 0
