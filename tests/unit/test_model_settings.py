"""Tests for the provider dispatch behind LLM_MODEL.

Model settings are namespaced per provider and each model class reads only its own keys,
so passing the wrong provider's settings is silently ignored rather than rejected. That
makes these assertions the only thing standing between a provider swap and a quiet loss of
effort/latency tuning — there is no runtime error to catch it. No network here: the
dispatch is pure, and build_model only constructs a client for local backends.
"""

import pytest

from rag.agent import build_model, build_model_settings, provider_of


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("anthropic:claude-sonnet-5", "anthropic"),
        ("google-gla:gemini-3-flash-preview", "google-gla"),
        ("google-vertex:gemini-3-pro-preview", "google-vertex"),
        ("cerebras:zai-glm-4.6", "cerebras"),
        ("openrouter:z-ai/glm-4.6", "openrouter"),
        ("ollama:qwen3:14b", "ollama"),  # model tags contain colons — split once only
        ("test", ""),  # Pydantic AI's bare TestModel id has no provider
    ],
)
def test_provider_of(model_id, expected):
    assert provider_of(model_id) == expected


def test_anthropic_gets_effort():
    s = build_model_settings("anthropic:claude-sonnet-5", "low")
    assert s == {"anthropic_effort": "low"}


def test_anthropic_keeps_max():
    """The "max" level is Anthropic-only and must survive unclamped."""
    s = build_model_settings("anthropic:claude-opus-4-8", "max")
    assert s == {"anthropic_effort": "max"}


@pytest.mark.parametrize(
    "model_id",
    ["anthropic:claude-haiku-4-5", "openai:gpt-5.1", "cerebras:zai-glm-4.6"],
)
def test_blank_effort_sends_nothing(model_id):
    """Haiku 4.5 rejects the effort parameter outright — blank must omit it, not default it."""
    assert build_model_settings(model_id, None) is None


def test_openai_gets_reasoning_effort():
    s = build_model_settings("openai:gpt-5.1", "low")
    assert s == {"openai_reasoning_effort": "low"}


def test_openai_clamps_max_to_high():
    """OpenAI accepts none|minimal|low|medium|high|xhigh — "max" would be rejected."""
    s = build_model_settings("openai:gpt-5.1", "max")
    assert s == {"openai_reasoning_effort": "high"}


def test_cerebras_disables_reasoning_only_for_low():
    assert build_model_settings("cerebras:zai-glm-4.6", "low") == {"cerebras_disable_reasoning": True}
    assert build_model_settings("cerebras:zai-glm-4.6", "high") is None


@pytest.mark.parametrize("model_id", ["google-gla:gemini-3-flash-preview", "google-vertex:gemini-3-pro-preview"])
def test_gemini_always_relaxes_safety_settings(model_id):
    """The KEV/NVD corpus is exploit text; default DANGEROUS_CONTENT filtering blocks it.

    Must hold for both Google providers and regardless of effort, including when effort is
    blank and no thinking config is attached at all.
    """
    for effort in ("low", None):
        s = build_model_settings(model_id, effort)
        categories = {entry["category"]: entry["threshold"] for entry in s["google_safety_settings"]}
        assert categories["HARM_CATEGORY_DANGEROUS_CONTENT"] == "BLOCK_ONLY_HIGH"
        assert len(categories) == 4


def test_gemini_maps_effort_to_thinking_level():
    s = build_model_settings("google-gla:gemini-3-flash-preview", "low")
    assert s["google_thinking_config"] == {"thinking_level": "low"}


def test_gemini_clamps_max_to_high():
    """thinking_level accepts MINIMAL|LOW|MEDIUM|HIGH — there is no "max"."""
    s = build_model_settings("google-gla:gemini-3-pro-preview", "max")
    assert s["google_thinking_config"] == {"thinking_level": "high"}


def test_gemini_thinking_budget_overrides_effort():
    """The numeric budget is the only route to the 2.5-series and the only way to fully
    disable thinking, so it must win over the effort-derived level."""
    s = build_model_settings("google-gla:gemini-2.5-flash", "low", thinking_budget=0)
    assert s["google_thinking_config"] == {"thinking_budget": 0}


def test_gemini_thinking_budget_applies_without_effort():
    s = build_model_settings("google-gla:gemini-2.5-flash", None, thinking_budget=512)
    assert s["google_thinking_config"] == {"thinking_budget": 512}


def test_gemini_omits_thinking_config_when_unconfigured():
    s = build_model_settings("google-gla:gemini-3-flash-preview", None)
    assert "google_thinking_config" not in s


@pytest.mark.parametrize("model_id", ["ollama:qwen3:14b", "openrouter:z-ai/glm-4.6", "groq:llama-3.3-70b", "test"])
def test_unknown_and_local_providers_get_no_settings(model_id):
    """The None default is the extensibility mechanism: an unhandled provider still runs.

    Local backends have no effort knob over the OpenAI-compatible endpoint, so a set
    llm_effort must be dropped rather than forwarded as an unsupported parameter.
    """
    assert build_model_settings(model_id, "low") is None


@pytest.mark.parametrize(
    "model_id",
    ["anthropic:claude-sonnet-5", "google-gla:gemini-3-flash-preview", "openai:gpt-5.1", "cerebras:zai-glm-4.6"],
)
def test_hosted_models_pass_the_id_through(model_id):
    """Hosted providers must stay string-inferred — building a client here would demand
    credentials at import time for providers the deployment isn't using."""
    assert build_model(model_id) == model_id


def test_ollama_model_is_built_with_the_configured_base_url(monkeypatch):
    """Ollama's base URL comes from Settings, not OLLAMA_BASE_URL in os.environ, so it
    resolves identically in the app, ETL scripts, and tests."""
    from config import settings

    monkeypatch.setattr(settings, "ollama_base_url", "http://localhost:1234/v1")  # LM Studio
    model = build_model("ollama:qwen3:14b")

    assert model.model_name == "qwen3:14b"
    assert str(model.client.base_url).rstrip("/") == "http://localhost:1234/v1"
