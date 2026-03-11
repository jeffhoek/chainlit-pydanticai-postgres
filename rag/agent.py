from dataclasses import dataclass

from openai import AsyncOpenAI
from pydantic_ai import Agent, RunContext

from config import settings
from rag.embeddings import generate_embedding
from rag.vector_store import PgVectorStore


@dataclass
class Deps:
    openai_client: AsyncOpenAI
    vector_store: PgVectorStore


rag_agent = Agent(
    settings.llm_model,
    deps_type=Deps,
    system_prompt=settings.system_prompt,
)


MAX_QUERY_ROWS = 100


@rag_agent.tool
async def query(ctx: RunContext[Deps], sql: str) -> str:
    """Execute a read-only SQL SELECT query against the database.

    Args:
        sql: A SELECT statement to run against the database.

    Returns:
        Query results as a formatted table, or an error message.
    """
    if not sql.strip().upper().startswith("SELECT"):
        return "Error: Only SELECT statements are permitted."

    try:
        async with ctx.deps.vector_store.pool.acquire() as conn:
            rows = await conn.fetch(sql)
    except Exception as e:
        return f"Query error: {e}"

    if not rows:
        return "No results found."

    rows = rows[:MAX_QUERY_ROWS]
    headers = list(rows[0].keys())
    lines = [" | ".join(headers)]
    lines.append("-" * len(lines[0]))
    for row in rows:
        lines.append(" | ".join(str(v) for v in row.values()))
    lines.append(f"\n{len(rows)} row(s) returned.")
    return "\n".join(lines)


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
