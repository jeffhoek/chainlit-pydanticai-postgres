import os

import chainlit as cl
from openai import AsyncOpenAI
from pydantic_ai import Agent

from config import settings
from rag.agent import Deps, rag_agent
from rag.database import init_db
from rag.vector_store import PgVectorStore

if os.getenv("LANGFUSE_PUBLIC_KEY"):
    from langfuse import get_client
    get_client()
    Agent.instrument_all()


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    expected_username = os.getenv("APP_USERNAME", "admin")
    expected_password = os.getenv("APP_PASSWORD")

    if not expected_password:
        return None

    if username == expected_username and password == expected_password:
        return cl.User(identifier=username)

    return None


def _quick_query_actions() -> list[cl.Action]:
    return [
        cl.Action(name="quick_query", label=label, payload={"query": label})
        for label in settings.action_buttons
    ]


@cl.action_callback("quick_query")
async def on_quick_query(action: cl.Action) -> None:
    query = action.payload["query"]
    deps = cl.user_session.get("deps")
    if deps is None:
        await cl.Message(content="Error: Knowledge base not initialized. Please refresh the page.").send()
        return
    result = await rag_agent.run(query, deps=deps)
    await cl.Message(content=result.output, actions=_quick_query_actions()).send()


@cl.on_chat_start
async def on_chat_start() -> None:
    """Initialize the RAG system on chat start."""
    pool = await init_db()
    vector_store = PgVectorStore(pool)
    openai_client = AsyncOpenAI(api_key=settings.openai_api_key)

    deps = Deps(openai_client=openai_client, vector_store=vector_store)
    cl.user_session.set("deps", deps)

    doc_count = await vector_store.get_document_count()
    await cl.Message(
        content=f"Ready! {doc_count} vulnerability records available.",
        actions=_quick_query_actions(),
    ).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    """Handle incoming messages."""
    deps = cl.user_session.get("deps")

    if deps is None:
        await cl.Message(
            content="Error: Knowledge base not initialized. Please refresh the page."
        ).send()
        return

    result = await rag_agent.run(message.content, deps=deps)
    await cl.Message(content=result.output, actions=_quick_query_actions()).send()
