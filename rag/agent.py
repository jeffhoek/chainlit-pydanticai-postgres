import logging
from dataclasses import dataclass

import asyncpg
from openai import AsyncOpenAI
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.anthropic import AnthropicModelSettings

from config import settings
from rag.embeddings import generate_embedding
from rag.risk import RiskScore, score_cves
from rag.sql_utils import apply_row_limit, format_query_results, validate_sql
from rag.vector_store import PgVectorStore


@dataclass
class Deps:
    openai_client: AsyncOpenAI
    vector_store: PgVectorStore


rag_agent = Agent(
    settings.llm_model,
    deps_type=Deps,
    system_prompt=settings.system_prompt,
    model_settings=(AnthropicModelSettings(anthropic_effort=settings.llm_effort) if settings.llm_effort else None),
)


@rag_agent.tool
async def query(ctx: RunContext[Deps], sql: str) -> str:
    """Execute a read-only SQL SELECT query against the database.

    Args:
        sql: A SELECT statement to run against the database.

    Returns:
        Query results as a formatted table, or an error message.
    """
    error = validate_sql(sql)
    if error:
        return error

    sql = apply_row_limit(sql)

    try:
        async with ctx.deps.vector_store.pool.acquire() as conn:
            rows = await conn.fetch(sql)
    except asyncpg.PostgresError as e:
        return f"Query error: {e}"
    except Exception:
        logging.exception("Unexpected error in query tool")
        return "Internal error executing query."

    if not rows:
        return "No results found."

    return format_query_results(rows)


@rag_agent.tool
async def risk_score(ctx: RunContext[Deps], cve_ids: list[str]) -> list[RiskScore] | str:
    """Composite 0-100 risk score for specific CVEs, with a per-signal breakdown.

    Blends CVSS severity, EPSS likelihood, KEV listing, SSVC urgency, and CWE
    weakness class into one number. Use this for a handful of NAMED CVEs. For
    ranking, filtering, or counting across the corpus, query the `v_cve_risk` view
    with the `query` tool instead — one ORDER BY beats 25 tool calls.

    Args:
        cve_ids: CVE IDs to score, e.g. ["CVE-2021-44228"]. At most 25 per call;
            they are ranked highest-risk first in the result.

    Returns:
        One entry per CVE with score, band, weighted components, and a rationale;
        an entry with a null score means the CVE is in neither KEV nor NVD.
    """
    try:
        return await score_cves(ctx.deps.vector_store.pool, cve_ids)
    except asyncpg.PostgresError as e:
        return f"Risk score error: {e}"
    except Exception:
        logging.exception("Unexpected error in risk_score tool")
        return "Internal error computing risk scores."


@rag_agent.tool
async def retrieve(ctx: RunContext[Deps], query: str) -> str:
    """Retrieve relevant context from the knowledge base.

    Args:
        query: The search query to find relevant documents.

    Returns:
        Relevant context from the knowledge base.
    """
    query_embedding = await generate_embedding(ctx.deps.openai_client, query)
    results = await ctx.deps.vector_store.search(query_embedding, top_k=settings.top_k)

    if not results:
        return "No relevant context found."

    context = "\n\n---\n\n".join(results)
    return f"Retrieved context:\n\n{context}"
