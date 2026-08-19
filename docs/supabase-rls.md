# Row-Level Security on Supabase

Closing the `rls_disabled_in_public` finding Supabase raises against this project — what it
actually means here, the fix, and how to apply it to production without locking the app out of
its own database.

Related: [supabase-readonly-role.md](supabase-readonly-role.md) (the `app_readonly` / `app_etl`
roles this interacts with), [risk-scoring.md](risk-scoring.md) (the `v_cve_risk` materialized view).

---

## The finding

> **Table publicly accessible.** Anyone with your project URL can read, edit, and delete all data
> in this table because Row-Level Security is not enabled.

Supabase serves every table in the `public` schema over its PostgREST **Data API** at
`https://<project-ref>.supabase.co/rest/v1/<table>`. Requests on that path authenticate as the
built-in `anon` or `authenticated` roles, and Supabase's own default privileges grant those roles
`ALL` on tables created in `public`. Row-Level Security is the only remaining gate. With it off,
the grant is the whole story.

All six base tables were affected: `kev_vulnerabilities`, `nvd_vulnerabilities`, `epss_scores`,
`cwe_definitions`, `etl_runs`, `user_usage`.

### How exposed was it, really

Worth being precise, because the alert's wording overstates one part and understates another.

**Overstated:** the project URL alone is not enough. A caller also needs the anon/publishable key.
This app never uses PostgREST — it connects with `asyncpg` over the pooler using the dedicated
roles in [supabase-readonly-role.md](supabase-readonly-role.md) — so that key is not embedded in a
shipped client bundle the way it would be in a `supabase-js` app, and it appears in no committed
file. That is a meaningful difference from the typical instance of this finding.

**Understated:** the exposure is read *and write*. The datasets themselves are public information
(CISA KEV, NVD, EPSS, MITRE CWE are all freely published), so disclosure is close to a non-event —
but an attacker who can `DELETE` or `UPDATE` can silently poison the corpus this tool answers
from. A vulnerability assistant that under-reports a KEV entry because someone edited the row is a
worse outcome than the data leaking. And `user_usage` is not public data: it holds OAuth
identifiers (`github:<user>`) alongside per-day query and token counts.

The anon key is designed to be publishable and is one leaked config file away from being public.
Treating it as a secret is not a security control.

---

## The fix

Three layers, applied together by `RLS_SQL` in [rag/database.py](../rag/database.py) and the tail
of `view_ddl()` in [rag/risk.py](../rag/risk.py).

### 1. RLS, with policies for the app roles

`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` on all six tables. **This is the step that can take
the app down**, and it is worth understanding before running it: RLS applies to every role except
the table owner. `app_readonly` and `app_etl` are not owners — `postgres` is — so the instant RLS
is on and no policy matches, the live app's queries start returning **zero rows** and the ETL's
upserts start failing. Nothing errors at connection time; reads just quietly go empty.

`BYPASSRLS` would sidestep it but is not available — Supabase does not grant it on the `postgres`
role. Policies are the only route:

```sql
CREATE POLICY app_roles_rw ON <table> FOR ALL TO app_readonly, app_etl
  USING (true) WITH CHECK (true);
```

`USING (true)` looks like it gives everything away; it does not. **A policy filters rows, it never
confers a privilege.** What `app_readonly` may do is still bounded entirely by its `GRANT`s —
`SELECT` on the vulnerability tables, `SELECT/INSERT/UPDATE` on `user_usage`, no `DELETE`
anywhere. The policy restores exactly the access that already existed and nothing more, while
`anon` — which now holds no grant and matches no policy — is stopped twice over.

### 2. Revoke the Data API roles

Defence in depth behind the policies. With no grant at all, a Data API request never reaches the
RLS check:

```sql
REVOKE ALL ON <table> FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
```

That last statement is the one that keeps this fixed. Supabase installs
`ALTER DEFAULT PRIVILEGES ... GRANT ALL ON TABLES TO anon, authenticated`, so without
countermanding it, the next table added to `SCHEMA_SQL` arrives publicly readable the moment it is
created — and the alert comes back. Default privileges are per-creating-role, so this must run as
the admin role that owns the schema.

### 3. `v_cve_risk`, which RLS cannot protect

PostgreSQL does not support RLS on materialized views. The protection every base table gets is
simply unavailable for `v_cve_risk` — which, being a denormalized join across all four datasets,
is the single most useful object on the API surface. Revoking the grant is the only lever, and
Supabase lints this separately as `materialized_view_in_api`.

The revoke lives inside `view_ddl()` rather than beside the other RLS statements for a specific
reason: `view_ddl()` drops and recreates the view, which discards every privilege on it. A revoke
applied anywhere else would be silently undone the next time the score arithmetic changed.

### Optional, and stronger: turn the Data API off

Because nothing in this project uses PostgREST, the exposed schema list can simply be emptied:
**Project Settings → API → Exposed schemas**, remove `public`. That removes the attack surface
rather than filtering it, and breaks nothing here — the dashboard's Table Editor and SQL Editor do
not go through PostgREST. The three layers above stay worth applying regardless: they are what
holds if the Data API is ever re-enabled, and enabling RLS is what actually clears the advisor.

---

## Applying it

### Local / dev / CI

Nothing to do. `RLS_SQL` is part of `SCHEMA_SQL`, so `init_db()` applies it under the existing
`db_init_schema` gate.

None of `anon`, `authenticated`, `app_readonly`, or `app_etl` exist outside Supabase, and neither
`REVOKE` nor `CREATE POLICY` supports `IF EXISTS` — so every role reference in `RLS_SQL` is
guarded on a `pg_roles` lookup. Off Supabase the statements are skipped rather than aborting the
file. RLS still gets switched on locally, which is harmless: the dev connection owns the tables
and owners are exempt.

### Production

Production runs `DB_INIT_SCHEMA=false` (read-only app role, no DDL), so **none of this arrives
just because it is in the code path.** Apply it with the admin role, the same way `view_ddl()` is
applied:

```bash
uv run python -c "from rag.database import RLS_SQL; print(RLS_SQL)" > /tmp/rls.sql
```

```bash
psql "<admin-pooled-supabase-dsn>" -f /tmp/rls.sql
```

Every statement is idempotent and safe to replay: `ENABLE ROW LEVEL SECURITY` is a no-op when
already on, and each policy is dropped before being recreated (`CREATE POLICY` has neither
`OR REPLACE` nor `IF NOT EXISTS`).

**Order matters if you are also reapplying `view_ddl()`.** The view's `DROP`/`CREATE` discards its
grants, so re-issue them *after*, not before — otherwise the app loses `v_cve_risk` while
appearing to have been granted it:

```sql
GRANT SELECT ON v_cve_risk TO app_readonly, app_etl;
GRANT EXECUTE ON FUNCTION refresh_v_cve_risk() TO app_etl;
```

---

## Verify

```sql
-- 1. RLS on every base table. Expect six rows, all t.
SELECT relname, relrowsecurity
FROM pg_class
WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'
ORDER BY relname;
```

```sql
-- 2. One policy per table, scoped to both app roles.
SELECT tablename, policyname, roles, cmd
FROM pg_policies WHERE schemaname = 'public'
ORDER BY tablename;
```

```sql
-- 3. The Data API roles hold nothing. Expect zero rows — this is the finding itself.
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('anon', 'authenticated') AND table_schema = 'public';
```

Then re-run the linter in the dashboard: **Advisors → Security Advisor**. `rls_disabled_in_public`
should be gone for all six tables.

The end-to-end check that matters more than any of the above is that the app still works, because
the failure mode of this change is silent. Run a query and confirm it returns results **and**
records a `user_usage` row:

```bash
uv run chainlit run app.py
```

```sql
SELECT * FROM user_usage WHERE query_date = CURRENT_DATE ORDER BY id DESC LIMIT 5;
```

If reads come back empty, the policies did not apply — check that `app_readonly` existed at the
time `RLS_SQL` ran, since the guard skips policy creation entirely when the role is absent. That
is the one way this can leave the app locked out: applying the file to a database where the app
roles have not been created yet.

Then run the ETL and confirm it still writes ([data-loading.md](data-loading.md)) — `app_etl` goes
through the same policies.

---

## Coverage

`RLS_TABLES` in [rag/database.py](../rag/database.py) is the list the SQL loops over, and
[tests/unit/test_database_rls.py](../tests/unit/test_database_rls.py) asserts it matches the
`CREATE TABLE` statements in the same file. A table added to the schema but not to that tuple
would be created without RLS and served publicly — the exact drift that produced this finding —
so the test fails the build instead.

[tests/integration/test_rls_db.py](../tests/integration/test_rls_db.py) covers the rest against a
real database, including a check that *no* table in `public` has RLS off, which catches tables
created outside `SCHEMA_SQL` as well.
