import asyncio
import logging
import secrets
from dataclasses import dataclass

import asyncpg
from fastmcp import FastMCP
from openai import AsyncOpenAI
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from config import settings
from rag.embeddings import generate_embedding
from rag.risk import RiskScore, score_cves
from rag.sql_utils import apply_row_limit, format_query_results, validate_sql
from rag.vector_store import PgVectorStore

logger = logging.getLogger(__name__)

mcp = FastMCP("kev-nvd-rag")


@dataclass
class McpContext:
    pool: asyncpg.Pool
    openai_client: AsyncOpenAI
    vector_store: PgVectorStore


_mcp_context: McpContext | None = None


def set_mcp_context(pool: asyncpg.Pool, openai_client: AsyncOpenAI) -> None:
    """Called from app.py lifespan to inject the shared pool and client."""
    global _mcp_context
    _mcp_context = McpContext(
        pool=pool,
        openai_client=openai_client,
        vector_store=PgVectorStore(pool),
    )


@mcp.tool
async def retrieve(query: str) -> str:
    """Retrieve relevant context from the KEV/NVD knowledge base using semantic search.

    Use this for conceptual or thematic questions ("tell me about Log4j",
    "prompt injection vulns") where document excerpts are what you want.
    For counts, top-N, date filters, grouping, JOINs, or specific CVE ID
    lookups, use the `query` tool instead — semantic search returns a fixed
    top-k of similar text, not exact or complete rows.

    Args:
        query: Natural language search query (e.g. "log4j remote code execution").

    Returns:
        Relevant document excerpts from the knowledge base.
    """
    if _mcp_context is None:
        return "Error: MCP context not initialised."

    query_embedding = await generate_embedding(_mcp_context.openai_client, query)
    results = await _mcp_context.vector_store.search(query_embedding, top_k=settings.top_k)

    if not results:
        return "No relevant context found."

    context = "\n\n---\n\n".join(results)
    return f"Retrieved context:\n\n{context}"


@mcp.tool
async def risk_score(cve_ids: list[str]) -> list[RiskScore] | str:
    """Composite 0-100 risk score for specific CVEs, with a per-signal breakdown.

    Blends CVSS severity, EPSS likelihood, KEV listing, SSVC urgency, and CWE
    weakness class into one number. Use this for a handful of NAMED CVEs. For
    ranking, filtering, or counting across the corpus, query the `v_cve_risk` view
    with the `query` tool instead — one ORDER BY beats 25 tool calls.

    The score is a blend, not a fifth signal: when the question is specifically
    about likelihood or severity, cite epss_probability or cvss_score directly.
    Bands are relative to this corpus: 0-24 low, 25-44 moderate, 45-64 high,
    65-100 critical (critical effectively requires KEV listing).

    Args:
        cve_ids: CVE IDs to score, e.g. ["CVE-2021-44228"]. At most 25 per call;
            they are ranked highest-risk first in the result.

    Returns:
        One entry per CVE with score, band, weighted components, and a rationale;
        an entry with a null score means the CVE is in neither KEV nor NVD.
    """
    if _mcp_context is None:
        return "Error: MCP context not initialised."

    try:
        return await score_cves(_mcp_context.pool, cve_ids)
    except asyncpg.PostgresError as e:
        logger.warning("Database error in MCP risk_score tool: %s", e)
        return "Error: Database error computing risk scores."
    except Exception:
        logger.exception("Unexpected error in MCP risk_score tool")
        return "Error: Internal error computing risk scores."


@mcp.tool
async def query(sql: str) -> str:
    """Execute a read-only SQL SELECT query against the KEV/NVD database.

    Use this for counts, top-N, date filters, grouping, listing, JOINs across
    tables, and specific CVE ID lookups. For a CVE ID lookup, query BOTH
    kev_vulnerabilities AND nvd_vulnerabilities before concluding a CVE is
    absent — a CVE may exist in NVD without appearing in KEV.

    Schema (mirrors config.py's system prompt — keep the two in sync):

    TABLE kev_vulnerabilities (
      cve_id VARCHAR(20),
      vendor_project TEXT,
      product TEXT,
      vulnerability_name TEXT,
      short_description TEXT,
      required_action TEXT,
      notes TEXT,
      date_added DATE,
      due_date DATE,
      known_ransomware_campaign_use VARCHAR(20),
      cwes TEXT[]
    )

    TABLE nvd_vulnerabilities (
      cve_id VARCHAR(20),
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
      ssvc_exploitation VARCHAR(8),     -- none|poc|active (CISA SSVC decision factor)
      ssvc_automatable VARCHAR(4),      -- yes|no
      ssvc_technical_impact VARCHAR(8), -- partial|total
      ssvc_decision VARCHAR(8),         -- Act|Attend|Track|Track* (usually NULL today)
      ssvc_version VARCHAR(8),          -- SSVC schema version, e.g. '2.0.3'
      raw_json JSONB                    -- full NVD API response; query with -> and ->>
    )

    TABLE cwe_definitions (
      cwe_id VARCHAR(20),       -- e.g. 'CWE-79'
      name TEXT,                -- human-readable weakness name
      abstraction VARCHAR(20),  -- Pillar, Class, Base, Variant, Compound
      description TEXT,
      url TEXT
    )

    TABLE epss_scores (
      cve_id VARCHAR(20),
      probability NUMERIC(6,5),           -- 0-1, chance of exploitation in next 30 days
      percentile NUMERIC(6,5),            -- rank vs all scored CVEs
      scored_at DATE,                     -- date of this EPSS publication
      model_version VARCHAR(16),
      previous_probability NUMERIC(6,5),  -- prior publication's score (movement queries)
      previous_scored_at DATE
    )

    All four signals pre-blended and pre-joined, one row per CVE in NVD or KEV:

    VIEW v_cve_risk (
      cve_id VARCHAR(20),
      risk_score NUMERIC(4,1),          -- 0-100 composite; see Composite Risk Score below
      c_cvss, c_epss, c_kev, c_ransomware, c_ssvc, c_cwe NUMERIC,  -- weighted contributions
      cvss_score NUMERIC(3,1),          -- COALESCE(v3.1, v2)
      cvss_imputed BOOLEAN,             -- TRUE when neither CVSS version exists (neutral prior used)
      epss_probability, epss_percentile NUMERIC(6,5),
      epss_previous_probability NUMERIC(6,5), epss_previous_scored_at DATE,
      epss_scored_at DATE,
      kev_listed BOOLEAN,
      kev_date_added DATE,
      known_ransomware_campaign_use VARCHAR(20),
      ssvc_exploitation, ssvc_automatable, ssvc_technical_impact VARCHAR,
      cwe_top VARCHAR(20)               -- highest-severity rated CWE, NULL if none rated
    )

    JOIN kev_vulnerabilities and nvd_vulnerabilities on cve_id. Resolve CWE IDs
    to names via cwe_id = ANY(nvd_vulnerabilities.cwes) or
    cwe_id = ANY(kev_vulnerabilities.cwes).

    SSVC (prioritization — complements CVSS; severity != urgency):
    - ssvc_exploitation: none < poc < active (active = exploited in the wild;
      KEV-listed CVEs are typically 'active').
    - ssvc_automatable: yes|no (whether attackers can automate at scale).
    - ssvc_technical_impact: partial|total.
    Top remediation priority = ssvc_exploitation='active' AND
    ssvc_automatable='yes' AND ssvc_technical_impact='total'.

    EPSS (exploitation likelihood — the leading indicator to KEV's lagging one):
    - Four distinct signals: cvss_v31_score = severity, epss_scores.probability =
      likelihood, KEV listing = confirmed exploitation, ssvc_* = urgency. Rank by
      the one the question actually asks for.
    - ALWAYS LEFT JOIN epss_scores. Coverage is partial (EPSS skips
      REJECTED/RESERVED CVEs and may score a CVE before the NVD sync sees it), and
      a missing row means UNSCORED, never zero risk — an INNER JOIN silently drops
      those CVEs from rankings.
    - Heavily skewed: most CVEs are below 0.01. Bands: probability >= 0.5 high,
      >= 0.1 elevated, percentile >= 0.95 top-5%. Report percentile alongside a
      raw probability. Scores refresh daily — cite scored_at.
    - High EPSS + absent from KEV is early warning, not a contradiction.
    - CVSS v3.1 only exists for CVEs from ~2015 onward; older records carry
      cvss_v2_score alone, while EPSS scores the corpus back to 1999. A severity
      filter written against cvss_v31_score therefore drops every pre-2015 CVE
      from an EPSS comparison — use COALESCE(cvss_v31_score, cvss_v2_score)
      whenever a severity threshold is combined with EPSS.

    Composite Risk Score (v_cve_risk — the four signals pre-blended):
    - risk_score is a BLEND, not a fifth signal. When the question is specifically
      about likelihood or severity, cite epss_probability or cvss_score directly.
    - Bands are relative to this corpus, not absolute: 0-24 low, 25-44 moderate,
      45-64 high, 65-100 critical. Critical effectively requires KEV listing; a CVE
      not on KEV tops out around 61, so 45+ without KEV is the early-warning signal.
    - cvss_imputed = TRUE means the CVSS input was a neutral 5.0 prior, NOT a
      measured score (the CVE has not been assessed yet). Say so when reporting such
      a CVE, and filter with WHERE NOT cvss_imputed when precision matters.
    - Use the `risk_score` TOOL for a handful of named CVEs; use this view for
      ranking, filtering, and counting.
    Example queries:
    - What to patch first: SELECT cve_id, risk_score, cvss_score, epss_probability,
      kev_listed FROM v_cve_risk ORDER BY risk_score DESC LIMIT 20;
    - Early warning: SELECT cve_id, risk_score, epss_probability, epss_percentile
      FROM v_cve_risk WHERE NOT kev_listed AND risk_score >= 45
      ORDER BY risk_score DESC;
    - Band distribution: SELECT CASE WHEN risk_score >= 65 THEN 'critical' WHEN
      risk_score >= 45 THEN 'high' WHEN risk_score >= 25 THEN 'moderate' ELSE 'low'
      END AS band, COUNT(*) FROM v_cve_risk GROUP BY 1 ORDER BY 1;

    Args:
        sql: A read-only SELECT statement against the tables above.

    Returns:
        Query results as a formatted table, or an error message.
    """
    if _mcp_context is None:
        return "Error: MCP context not initialised."

    error = validate_sql(sql)
    if error:
        return error

    sql = apply_row_limit(sql)

    try:
        async with _mcp_context.pool.acquire() as conn:
            rows = await conn.fetch(sql)
    except asyncpg.PostgresError as e:
        logger.warning("Database error in MCP query tool: %s", e)
        return "Error: Database error executing query."
    except Exception:
        logger.exception("Unexpected error in MCP query tool")
        return "Error: Internal error executing query."

    if not rows:
        return "No results found."

    return format_query_results(rows)


class McpRouterMiddleware:
    """
    Starlette middleware that intercepts /mcp* requests before Chainlit's router,
    enforces API key auth, and delegates to FastMCP's ASGI app.
    All other requests pass through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        if settings.mcp_api_key is None:
            logger.warning(
                "MCP_API_KEY is not set — /mcp endpoint is UNAUTHENTICATED. "
                "Set MCP_API_KEY in .env or Key Vault before deploying."
            )
        self._mcp_asgi: ASGIApp = mcp.http_app(transport="streamable-http", stateless_http=True)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._handle_lifespan(scope, receive, send)
            return

        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not (path == "/mcp" or path.startswith("/mcp/")):
            await self.app(scope, receive, send)
            return

        # Auth check
        if settings.mcp_api_key is not None:
            headers = dict(scope.get("headers", []))
            api_key = headers.get(b"x-api-key", b"").decode()
            if not secrets.compare_digest(api_key, settings.mcp_api_key):
                response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
                await response(scope, receive, send)
                return

        await self._mcp_asgi(scope, receive, send)

    async def _handle_lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run Chainlit and FastMCP lifespans concurrently."""
        mcp_startup_done: asyncio.Event = asyncio.Event()
        mcp_should_shutdown: asyncio.Event = asyncio.Event()

        async def mcp_receive() -> dict:
            if not mcp_startup_done.is_set():
                return {"type": "lifespan.startup"}
            await mcp_should_shutdown.wait()
            return {"type": "lifespan.shutdown"}

        async def mcp_send(message: dict) -> None:
            if message["type"] == "lifespan.startup.complete":
                mcp_startup_done.set()

        async def patched_receive() -> dict:
            message = await receive()
            if message.get("type") == "lifespan.shutdown":
                mcp_should_shutdown.set()
            return message

        mcp_task = asyncio.ensure_future(self._mcp_asgi({**scope}, mcp_receive, mcp_send))
        await mcp_startup_done.wait()

        try:
            await self.app(scope, patched_receive, send)
        finally:
            mcp_should_shutdown.set()
            try:
                await asyncio.wait_for(asyncio.shield(mcp_task), timeout=5.0)
            except (TimeoutError, asyncio.CancelledError):
                mcp_task.cancel()
