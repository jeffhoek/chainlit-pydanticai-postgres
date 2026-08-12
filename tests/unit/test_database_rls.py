"""Unit tests for the Row-Level Security block in rag/database.py.

No database. The behaviour of the generated SQL — policies created, `anon` revoked,
`app_readonly`/`app_etl` still able to work — is a property of PostgreSQL and is
exercised by tests/integration/test_rls_db.py. What is tested here is the one thing
Python owns: that RLS_TABLES stays in step with the tables _TABLES_SQL creates.

That drift is the whole failure mode. A table added to _TABLES_SQL but not to
RLS_TABLES is created without RLS, and on Supabase that means it is served publicly
over the Data API — the exact condition that produced the `rls_disabled_in_public`
alert (docs/supabase-rls.md).
"""

import re

from rag.database import _TABLES_SQL, RLS_SQL, RLS_TABLES, SCHEMA_SQL


def created_tables() -> set[str]:
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _TABLES_SQL))


def test_every_created_table_is_covered_by_rls():
    assert created_tables() == set(RLS_TABLES)


def test_rls_tables_names_no_table_that_does_not_exist():
    assert set(RLS_TABLES) <= created_tables()


def test_rls_sql_enables_row_security_and_creates_a_policy():
    assert "ENABLE ROW LEVEL SECURITY" in RLS_SQL
    assert "CREATE POLICY app_roles_rw" in RLS_SQL


def test_rls_sql_drops_the_policy_before_creating_it():
    # CREATE POLICY has no OR REPLACE, so without the DROP the second application of
    # SCHEMA_SQL — which happens on every startup with DB_INIT_SCHEMA=true — aborts.
    assert RLS_SQL.index("DROP POLICY IF EXISTS app_roles_rw") < RLS_SQL.index("CREATE POLICY app_roles_rw")


def test_rls_sql_guards_every_role_reference_on_role_existence():
    # None of these roles exist on a local dev or CI database; an unguarded statement
    # would abort the whole file with "role does not exist".
    assert RLS_SQL.count("FROM pg_roles WHERE rolname IN") == 2
    assert "IF app_roles IS NOT NULL THEN" in RLS_SQL
    assert "IF api_roles IS NOT NULL THEN" in RLS_SQL


def test_rls_sql_revokes_the_data_api_roles():
    assert "REVOKE ALL ON %I FROM %s" in RLS_SQL
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA public " in RLS_SQL


def test_schema_sql_applies_rls_after_the_tables_exist():
    # ALTER TABLE ... ENABLE ROW LEVEL SECURITY cannot run before CREATE TABLE.
    assert SCHEMA_SQL == _TABLES_SQL + RLS_SQL
