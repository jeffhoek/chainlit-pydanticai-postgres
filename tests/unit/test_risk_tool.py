"""Unit tests for the risk_score tool's error paths — no real DB required.

The happy path needs the view, so it lives in
tests/integration/test_risk_view_db.py. What is testable without a database is
everything that must happen *before* the query runs, plus the two tool surfaces
staying in sync.
"""

from unittest.mock import AsyncMock, MagicMock

import asyncpg

import mcp_server.server as server_module
import rag.agent as agent_module
from mcp_server.server import McpContext
from rag.risk import MAX_BATCH, score_cves
from rag.vector_store import PgVectorStore


class _AcquireCtx:
    def __init__(self, conn: AsyncMock) -> None:
        self._conn = conn

    async def __aenter__(self) -> AsyncMock:
        return self._conn

    async def __aexit__(self, *_) -> None:
        pass


def _pool_with_conn(conn: AsyncMock) -> MagicMock:
    pool = MagicMock()
    pool.acquire.return_value = _AcquireCtx(conn)
    return pool


def _mock_context_with_conn(conn: AsyncMock) -> McpContext:
    pool = _pool_with_conn(conn)
    return McpContext(pool=pool, openai_client=AsyncMock(), vector_store=PgVectorStore(pool))


# -- Validation happens before the query --


async def test_malformed_id_is_rejected_without_touching_the_database():
    conn = AsyncMock()
    result = await score_cves(_pool_with_conn(conn), ["DROP TABLE kev_vulnerabilities"])

    assert isinstance(result, str)
    assert "malformed" in result
    conn.fetch.assert_not_called()


async def test_over_cap_batch_is_rejected_without_touching_the_database():
    conn = AsyncMock()
    ids = [f"CVE-2021-{n:05d}" for n in range(MAX_BATCH + 1)]
    result = await score_cves(_pool_with_conn(conn), ids)

    assert isinstance(result, str)
    assert str(MAX_BATCH) in result
    conn.fetch.assert_not_called()


async def test_empty_batch_is_rejected():
    conn = AsyncMock()
    result = await score_cves(_pool_with_conn(conn), [])

    assert isinstance(result, str)
    conn.fetch.assert_not_called()


async def test_cve_ids_are_passed_as_a_bound_parameter_not_interpolated():
    """The tool builds its own SQL and so never passes through validate_sql —
    parameterization is the only thing between a tool argument and the database."""
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])

    await score_cves(_pool_with_conn(conn), ["CVE-2021-44228"])

    sql, param = conn.fetch.call_args.args
    assert "CVE-2021-44228" not in sql
    assert "$1" in sql
    assert param == ["CVE-2021-44228"]


async def test_all_unknown_ids_come_back_as_explicit_entries():
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])

    results = await score_cves(_pool_with_conn(conn), ["CVE-2021-44228", "CVE-2021-44229"])

    assert [r.cve_id for r in results] == ["CVE-2021-44228", "CVE-2021-44229"]
    assert all(r.score is None for r in results)
    assert all("Not found" in r.rationale for r in results)


async def test_duplicate_unknown_ids_are_reported_once():
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])

    results = await score_cves(_pool_with_conn(conn), ["CVE-2021-44228", "CVE-2021-44228"])

    assert len(results) == 1


# -- MCP surface error handling --


async def test_mcp_risk_score_before_set_mcp_context_returns_error(monkeypatch):
    monkeypatch.setattr(server_module, "_mcp_context", None)
    result = await server_module.risk_score(["CVE-2021-44228"])
    assert "not initialised" in result


async def test_mcp_risk_score_postgres_error_returns_db_error_string(monkeypatch):
    conn = AsyncMock()
    conn.fetch = AsyncMock(side_effect=asyncpg.PostgresError("boom"))
    monkeypatch.setattr(server_module, "_mcp_context", _mock_context_with_conn(conn))

    result = await server_module.risk_score(["CVE-2021-44228"])
    assert result == "Error: Database error computing risk scores."


async def test_mcp_risk_score_unexpected_error_returns_internal_error_string(monkeypatch):
    conn = AsyncMock()
    conn.fetch = AsyncMock(side_effect=RuntimeError("unexpected"))
    monkeypatch.setattr(server_module, "_mcp_context", _mock_context_with_conn(conn))

    result = await server_module.risk_score(["CVE-2021-44228"])
    assert result == "Error: Internal error computing risk scores."


# -- The two surfaces stay in sync --


def test_both_tool_docstrings_state_the_current_batch_cap():
    """MAX_BATCH is a constant but the docstrings spell it out for the model."""
    for doc in (agent_module.risk_score.__doc__, server_module.risk_score.__doc__):
        assert f"At most {MAX_BATCH} per call" in doc


def test_both_tool_docstrings_route_bulk_ranking_to_the_view():
    """Without this the model calls the tool 25 times where one ORDER BY would do."""
    for doc in (agent_module.risk_score.__doc__, server_module.risk_score.__doc__):
        assert "v_cve_risk" in doc


def test_mcp_query_docstring_documents_the_view():
    doc = server_module.query.__doc__
    assert "VIEW v_cve_risk (" in doc
    assert "cvss_imputed BOOLEAN" in doc
