"""Embedding helpers, including the token-aware batching the ETL loaders share.

The embeddings API caps a request at 300k tokens across all inputs, and a single
input at 8191 tokens. Loaders therefore cannot just chunk by item count: a batch
of 500 CVEs is ~96k tokens of ordinary advisory prose but ~305k tokens when the
window is dominated by Linux-kernel CVEs, whose stack traces and symbol names
tokenize far denser than English.

Token counts are estimated from character length rather than measured with a
tokenizer, because the k8s deployment currently runs behind a strict egress
allowlist that does not include tiktoken's BPE download host. That is a
deployment posture, not a hard constraint — if it changes, exact counting is a
drop-in replacement for `estimate_tokens`. Either way the estimate is
deliberately pessimistic and `_embed_request` splits and retries if the server
rejects a batch anyway, so a bad estimate costs an extra request rather than a
failed run.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from openai import AsyncOpenAI, BadRequestError

from config import settings

# The embeddings API's hard cap across all inputs in one request.
API_MAX_TOKENS_PER_REQUEST = 300_000
# Budget to pack a request to, leaving headroom for estimation error.
MAX_TOKENS_PER_REQUEST = 250_000
# The API's hard cap for a single input (text-embedding-3-*).
MAX_TOKENS_PER_INPUT = 8_191
# Upper bound on inputs per request; the token budget usually binds first.
MAX_INPUTS_PER_REQUEST = 500

# Chars per token *floor*, so char_len / this over-estimates tokens rather than
# under-estimating. Measured over 4,160 live NVD records: mean 3.9, worst 2.0
# (kernel CVEs). The previous value of 4 was a mean, not a floor, which is how a
# 214k-token estimate turned into a 305k-token request and a 400.
MIN_CHARS_PER_TOKEN = 2

REQUEST_TIMEOUT = 60
MAX_RETRIES = 3


@asynccontextmanager
async def embedding_client(enabled: bool = True) -> AsyncIterator[AsyncOpenAI | None]:
    """Yield an ``AsyncOpenAI`` client (or None when disabled) and always close it.

    Closing matters more than usual here: `run_etl.py` runs each loader under its
    own `asyncio.run()`, so a client left open outlives the event loop it was
    built on. Its finalizer then schedules `aclose()` against a closed loop, and
    the resulting "Event loop is closed" traceback surfaces whenever the garbage
    collector happens to fire — misattributed to whichever step is running then.
    """
    client = AsyncOpenAI(api_key=settings.openai_api_key) if enabled else None
    try:
        yield client
    finally:
        if client is not None:
            await client.close()


async def generate_embedding(client: AsyncOpenAI, text: str) -> list[float]:
    """Generate embedding for a single text."""
    response = await client.embeddings.create(model=settings.embedding_model, input=text)
    return response.data[0].embedding


def estimate_tokens(text: str) -> int:
    """Upper-bound the token count of ``text`` from its length."""
    return len(text) // MIN_CHARS_PER_TOKEN + 1


def truncate_for_embedding(text: str) -> str:
    """Trim ``text`` to fit the per-input token cap, using the pessimistic ratio."""
    return text[: MAX_TOKENS_PER_INPUT * MIN_CHARS_PER_TOKEN]


def batch_texts_by_tokens(texts: list[str]) -> list[list[str]]:
    """Split ``texts`` into request-sized batches under both the token and item caps.

    Each text is truncated to the per-input cap first. A single text that still
    exceeds the request budget gets its own batch rather than being dropped.
    """
    batches: list[list[str]] = []
    current: list[str] = []
    current_tokens = 0

    for text in texts:
        text = truncate_for_embedding(text)
        tokens = estimate_tokens(text)
        over_budget = current_tokens + tokens > MAX_TOKENS_PER_REQUEST
        if current and (over_budget or len(current) >= MAX_INPUTS_PER_REQUEST):
            batches.append(current)
            current = []
            current_tokens = 0
        current.append(text)
        current_tokens += tokens

    if current:
        batches.append(current)
    return batches


def _is_request_too_large(error: BadRequestError) -> bool:
    """True if the API rejected the request for exceeding the per-request token cap."""
    return "maximum request size" in str(error)


async def _embed_request(client: AsyncOpenAI, batch: list[str]) -> list[list[float]]:
    """Send one embeddings request, halving it if the server says it is too large.

    The split is the backstop for the character-based estimate: if a batch is
    denser than the pessimistic ratio predicted, the run recovers instead of
    failing. Other 400s are deterministic and re-raise immediately.
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = await client.embeddings.create(
                model=settings.embedding_model, input=batch, timeout=REQUEST_TIMEOUT
            )
            return [item.embedding for item in response.data]
        except BadRequestError as e:
            if len(batch) > 1 and _is_request_too_large(e):
                mid = len(batch) // 2
                print(f"  Batch of {len(batch)} rejected as too large, splitting into {mid} + {len(batch) - mid}")
                head = await _embed_request(client, batch[:mid])
                tail = await _embed_request(client, batch[mid:])
                return head + tail
            raise
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            wait = 2**attempt
            print(f"  Embedding API error: {e}, retrying in {wait}s...")
            await asyncio.sleep(wait)

    raise AssertionError("unreachable")  # pragma: no cover


async def generate_embeddings_batch(client: AsyncOpenAI, texts: list[str], label: str = "") -> list[list[float]]:
    """Generate embeddings for ``texts``, splitting across as many requests as needed."""
    if not texts:
        return []

    batches = batch_texts_by_tokens(texts)
    all_embeddings: list[list[float]] = []
    for i, batch in enumerate(batches):
        if label and len(batches) > 1:
            print(f"  {label}: request {i + 1}/{len(batches)} ({len(batch)} texts)")
        all_embeddings.extend(await _embed_request(client, batch))
    return all_embeddings
