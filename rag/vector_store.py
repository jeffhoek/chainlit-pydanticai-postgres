import asyncpg
import numpy as np


class PgVectorStore:
    """PostgreSQL pgvector-backed vector store with cosine similarity search."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def search(self, query_embedding: list[float], top_k: int = 5) -> list[str]:
        """Find top-k most similar documents across KEV and NVD tables."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT content FROM (
                    SELECT content, embedding <=> $1 AS distance
                    FROM kev_vulnerabilities
                    UNION ALL
                    SELECT content, embedding <=> $1 AS distance
                    FROM nvd_vulnerabilities
                ) combined
                ORDER BY distance
                LIMIT $2
                """,
                np.array(query_embedding, dtype=np.float32),
                top_k,
            )
        return [row["content"] for row in rows]

    async def get_document_count(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                """
                SELECT (SELECT count(*) FROM kev_vulnerabilities)
                     + (SELECT count(*) FROM nvd_vulnerabilities)
                """
            )
