from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from openai import BadRequestError

from rag.embeddings import (
    MAX_INPUTS_PER_REQUEST,
    MAX_TOKENS_PER_INPUT,
    MAX_TOKENS_PER_REQUEST,
    MIN_CHARS_PER_TOKEN,
    batch_texts_by_tokens,
    estimate_tokens,
    generate_embedding,
    generate_embeddings_batch,
    truncate_for_embedding,
)

_EMBEDDING = [0.1] * 1536


def _make_openai_mock(embeddings: list[list[float]]) -> AsyncMock:
    client = AsyncMock()
    data = []
    for emb in embeddings:
        item = MagicMock()
        item.embedding = emb
        data.append(item)
    response = MagicMock()
    response.data = data
    client.embeddings.create = AsyncMock(return_value=response)
    return client


def _echo_openai_mock() -> AsyncMock:
    """Client that returns one distinct vector per input, so ordering is checkable."""
    client = AsyncMock()

    async def create(*, model, input, **kwargs):  # noqa: A002 - mirrors the SDK kwarg
        response = MagicMock()
        response.data = [MagicMock(embedding=[float(len(text))]) for text in input]
        return response

    client.embeddings.create = AsyncMock(side_effect=create)
    return client


def _too_large_error() -> BadRequestError:
    return BadRequestError(
        "Error code: 400 - Invalid 'input': maximum request size is 300000 tokens per request.",
        response=httpx.Response(400, request=httpx.Request("POST", "https://api.openai.com/v1/embeddings")),
        body=None,
    )


async def test_generate_embedding_returns_float_list(mock_settings):
    client = _make_openai_mock([_EMBEDDING])
    result = await generate_embedding(client, "test text")
    assert result == _EMBEDDING


async def test_generate_embeddings_batch_calls_api_once_returns_three_vectors(mock_settings):
    embeddings = [[0.1] * 1536, [0.2] * 1536, [0.3] * 1536]
    client = _make_openai_mock(embeddings)
    result = await generate_embeddings_batch(client, ["a", "b", "c"])
    client.embeddings.create.assert_called_once()
    assert len(result) == 3
    assert result[0] == embeddings[0]
    assert result[1] == embeddings[1]
    assert result[2] == embeddings[2]


async def test_generate_embeddings_batch_empty_list_skips_api(mock_settings):
    client = _make_openai_mock([])
    result = await generate_embeddings_batch(client, [])
    client.embeddings.create.assert_not_called()
    assert result == []


# -- Token-aware batching --


def test_estimate_tokens_over_estimates_rather_than_under():
    """A batch that estimates under budget must really be under the API's hard cap."""
    # Densest plausible content is ~2 chars/token; the estimate must not be lower.
    text = "x" * 1000
    assert estimate_tokens(text) >= len(text) / MIN_CHARS_PER_TOKEN


def test_batch_texts_by_tokens_splits_dense_batch_that_old_estimator_kept_whole():
    """Regression: 500 kernel-CVE-sized texts are one batch at 4 chars/token, two at 2."""
    # 1,600 chars each: 400 tokens under the old 4:1 estimate (200k, "safe"),
    # but ~800 real tokens for kernel content — 400k, over the 300k cap.
    texts = ["x" * 1600] * 500
    batches = batch_texts_by_tokens(texts)

    assert len(batches) > 1
    for batch in batches:
        assert sum(estimate_tokens(t) for t in batch) <= MAX_TOKENS_PER_REQUEST
    assert sum(len(b) for b in batches) == 500


def test_batch_texts_by_tokens_respects_item_cap():
    batches = batch_texts_by_tokens(["short"] * (MAX_INPUTS_PER_REQUEST * 2 + 5))
    assert all(len(b) <= MAX_INPUTS_PER_REQUEST for b in batches)
    assert sum(len(b) for b in batches) == MAX_INPUTS_PER_REQUEST * 2 + 5


def test_batch_texts_by_tokens_keeps_small_input_in_one_request():
    texts = ["CVE-2026-1234: a normal advisory description"] * 100
    assert len(batch_texts_by_tokens(texts)) == 1


def test_batch_texts_by_tokens_preserves_order_and_content():
    texts = [f"text-{i}" for i in range(1200)]
    flattened = [t for batch in batch_texts_by_tokens(texts) for t in batch]
    assert flattened == texts


def test_truncate_for_embedding_enforces_per_input_cap():
    truncated = truncate_for_embedding("x" * 100_000)
    assert estimate_tokens(truncated) <= MAX_TOKENS_PER_INPUT + 1


def test_oversized_single_text_gets_its_own_batch():
    """One huge text must not be dropped, and must not drag neighbours over budget."""
    huge = "x" * (MAX_TOKENS_PER_INPUT * MIN_CHARS_PER_TOKEN)
    batches = batch_texts_by_tokens(["small", huge, "small"])
    assert sum(len(b) for b in batches) == 3


async def test_generate_embeddings_batch_splits_on_too_large_400(mock_settings):
    """The server rejecting a batch triggers a halving retry, not a failed run."""
    client = AsyncMock()
    calls: list[int] = []

    async def create(*, model, input, **kwargs):  # noqa: A002 - mirrors the SDK kwarg
        calls.append(len(input))
        if len(input) > 2:
            raise _too_large_error()
        response = MagicMock()
        response.data = [MagicMock(embedding=[float(len(t))]) for t in input]
        return response

    client.embeddings.create = AsyncMock(side_effect=create)

    result = await generate_embeddings_batch(client, ["a", "bb", "ccc", "dddd"])

    assert [v[0] for v in result] == [1.0, 2.0, 3.0, 4.0]
    assert max(calls) == 4 and min(calls) == 2  # tried 4, then split to 2 + 2


async def test_generate_embeddings_batch_reraises_unrelated_400(mock_settings):
    """A deterministic 400 that is not a size problem must not be retried or split."""
    client = AsyncMock()
    error = BadRequestError(
        "Error code: 400 - Invalid 'model'.",
        response=httpx.Response(400, request=httpx.Request("POST", "https://api.openai.com/v1/embeddings")),
        body=None,
    )
    client.embeddings.create = AsyncMock(side_effect=error)

    with pytest.raises(BadRequestError):
        await generate_embeddings_batch(client, ["a", "b"])
    assert client.embeddings.create.await_count == 1


async def test_generate_embeddings_batch_returns_one_vector_per_text_across_requests(mock_settings):
    """Multi-request batches must concatenate in input order."""
    texts = [f"{'x' * (i % 7)}-{i}" for i in range(MAX_INPUTS_PER_REQUEST * 2 + 3)]
    client = _echo_openai_mock()

    result = await generate_embeddings_batch(client, texts)

    assert len(result) == len(texts)
    assert client.embeddings.create.await_count >= 3
    assert [v[0] for v in result] == [float(len(t)) for t in texts]
