from openai import AsyncOpenAI

from config import settings


async def generate_embedding(client: AsyncOpenAI, text: str) -> list[float]:
    """Generate embedding for a single text."""
    response = await client.embeddings.create(model=settings.embedding_model, input=text)
    return response.data[0].embedding


async def generate_embeddings_batch(
    client: AsyncOpenAI, texts: list[str]
) -> list[list[float]]:
    """Generate embeddings for multiple texts in a single batch."""
    if not texts:
        return []

    response = await client.embeddings.create(model=settings.embedding_model, input=texts)
    return [item.embedding for item in response.data]
