"""Integration tests for MCP query and retrieve tools against a real database.

Requires TEST_DATABASE_URL env var.  Fails loudly if absent.
The mock_openai fixture returns GOLDEN_KEV_EMBEDDING, matching the seeded kev row.
"""

import pytest

import mcp_server.server as server_module


@pytest.fixture
async def mcp_context(seeded_pool, mock_openai):
    server_module.set_mcp_context(seeded_pool, mock_openai)
    yield
    server_module._mcp_context = None


async def test_query_valid_select_returns_formatted_table(mcp_context):
    result = await server_module.query("SELECT cve_id, content FROM kev_vulnerabilities LIMIT 5")
    assert "CVE-2021-44228" in result
    assert "row(s) returned." in result


async def test_query_non_select_returns_permission_error(mcp_context):
    result = await server_module.query("INSERT INTO kev_vulnerabilities (cve_id, content) VALUES ('x', 'y')")
    assert "Only SELECT" in result


async def test_query_no_matching_rows_returns_no_results(mcp_context):
    result = await server_module.query("SELECT * FROM kev_vulnerabilities WHERE cve_id = 'CVE-0000-00000'")
    assert result == "No results found."


async def test_retrieve_returns_nonempty_context_string(mcp_context):
    result = await server_module.retrieve("log4j remote code execution")
    assert result.startswith("Retrieved context:")
    assert "Log4Shell" in result


async def test_query_can_select_from_the_risk_view(mcp_context):
    """The view has to exist for the agent, not just for the tool."""
    result = await server_module.query("SELECT cve_id, risk_score FROM v_cve_risk ORDER BY risk_score DESC LIMIT 5")
    assert "risk_score" in result
    assert "row(s) returned." in result


async def test_risk_score_returns_a_scored_entry(mcp_context):
    (result,) = await server_module.risk_score(["CVE-2021-44228"])

    assert result.cve_id == "CVE-2021-44228"
    assert 0 <= result.score <= 100
    assert result.band in ("low", "moderate", "high", "critical")
    assert result.rationale


async def test_risk_score_rejects_a_malformed_id(mcp_context):
    result = await server_module.risk_score(["not-a-cve"])
    assert isinstance(result, str)
    assert "malformed" in result
