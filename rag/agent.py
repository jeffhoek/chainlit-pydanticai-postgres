import logging
from dataclasses import dataclass

import asyncpg
from openai import AsyncOpenAI
from pydantic_ai import Agent, RunContext
from pydantic_ai.models import Model
from pydantic_ai.settings import ModelSettings

from config import settings
from rag.embeddings import generate_embedding
from rag.sql_utils import apply_row_limit, format_query_results, validate_sql
from rag.vector_store import PgVectorStore

# Gemini filters safety categories by default, and this corpus is wall-to-wall exploit,
# ransomware, and privilege-escalation text. DANGEROUS_CONTENT in particular blocks the
# very questions the app exists to answer, returning an empty candidate rather than an
# error. Relax all four explicitly instead of inheriting the defaults.
_GEMINI_SAFETY_SETTINGS = [
    {"category": category, "threshold": "BLOCK_ONLY_HIGH"}
    for category in (
        "HARM_CATEGORY_DANGEROUS_CONTENT",
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
    )
]


@dataclass
class Deps:
    openai_client: AsyncOpenAI
    vector_store: PgVectorStore


def provider_of(model_id: str) -> str:
    """Provider half of a Pydantic AI model id ('anthropic:claude-sonnet-5' -> 'anthropic')."""
    return model_id.split(":", 1)[0] if ":" in model_id else ""


def _capped_effort(effort: str) -> str:
    """Clamp 'max' to 'high' — it is an Anthropic-only level that others reject."""
    return "high" if effort == "max" else effort


def build_model(model_id: str) -> Model | str:
    """Resolve a model id, returning a Model only where one must be built explicitly.

    Pydantic AI infers the provider from the id string for every hosted backend, so the
    string is returned untouched. Local OpenAI-compatible servers are the exception:
    OllamaProvider would otherwise source its base URL from OLLAMA_BASE_URL in
    os.environ, which .env populates only as a side effect of Chainlit's dotenv load.
    Passing ollama_base_url through keeps it a real setting, so ETL scripts and tests
    resolve it the same way the app does.
    """
    if provider_of(model_id) != "ollama":
        return model_id

    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.ollama import OllamaProvider

    _, model_name = model_id.split(":", 1)
    return OpenAIChatModel(model_name, provider=OllamaProvider(base_url=settings.ollama_base_url))


def build_model_settings(model_id: str, effort: str | None, thinking_budget: int | None = None) -> ModelSettings | None:
    """Translate the semantic LLM_EFFORT knob into the active provider's vocabulary.

    Model settings are namespaced per provider (anthropic_*, google_*, openai_*) and each
    model class reads only its own keys, so handing Anthropic's settings to Gemini is
    silently ignored rather than rejected — which is exactly how a provider swap loses its
    latency tuning without anyone noticing. Providers are imported lazily so that adding a
    backend never costs an import for the ones unused.

    Unknown providers return None: any model Pydantic AI supports runs on generic settings,
    and a branch is added here only to reach a provider-specific thinking knob.
    """
    provider = provider_of(model_id)

    if provider == "anthropic":
        if not effort:
            return None
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        return AnthropicModelSettings(anthropic_effort=effort)

    if provider in ("google-gla", "google-vertex"):
        from pydantic_ai.models.google import GoogleModelSettings

        google_settings = GoogleModelSettings(google_safety_settings=_GEMINI_SAFETY_SETTINGS)
        # A numeric budget wins over thinking_level: it is the only way to reach the
        # 2.5-series, which has no thinking_level, and the only way to fully disable
        # thinking (level has no "off").
        if thinking_budget is not None:
            google_settings["google_thinking_config"] = {"thinking_budget": thinking_budget}
        elif effort:
            google_settings["google_thinking_config"] = {"thinking_level": _capped_effort(effort)}
        return google_settings

    if provider == "openai":
        if not effort:
            return None
        from pydantic_ai.models.openai import OpenAIChatModelSettings

        return OpenAIChatModelSettings(openai_reasoning_effort=_capped_effort(effort))

    if provider == "cerebras":
        # Cerebras offers only an on/off switch, and only on its reasoning models
        # (zai-glm-4.6, gpt-oss-120b). Treat "low" as the request to turn it off.
        if effort != "low":
            return None
        from pydantic_ai.models.cerebras import CerebrasModelSettings

        return CerebrasModelSettings(cerebras_disable_reasoning=True)

    # Local backends (ollama:, and LM Studio/vLLM through it) expose no effort knob over
    # the OpenAI-compatible endpoint, so llm_effort is inert rather than an error.
    return None


rag_agent = Agent(
    build_model(settings.llm_model),
    deps_type=Deps,
    system_prompt=settings.system_prompt,
    model_settings=build_model_settings(settings.llm_model, settings.llm_effort, settings.llm_thinking_budget),
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
