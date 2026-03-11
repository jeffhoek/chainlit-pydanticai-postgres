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
