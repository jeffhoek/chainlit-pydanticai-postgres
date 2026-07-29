# LLM Provider Fallback Plan

## Overview

Add a configurable backend failover path so the Chainlit RAG assistant keeps
answering when the primary Claude provider is unavailable. The current app has a
single global Pydantic AI agent in `rag/agent.py` backed by `LLM_MODEL`
(`anthropic:claude-sonnet-5` by default). The fallback design should keep that
normal path unchanged, then try one or more backup models only for transient
provider/API failures.

Recommended starting fallback:

```bash
LLM_MODEL=anthropic:claude-sonnet-5
LLM_FALLBACK_MODELS='["openai:gpt-5.1"]'
LLM_OPENAI_REASONING_EFFORT=low
```

Use `openai:gpt-5.1` as the quality-first backup for the RAG agent because this
app uses tool calling and short reasoning over database results. If cost or
latency becomes the main concern, switch the first fallback to
`openai:gpt-5-mini` or add it as the second fallback:

```bash
LLM_FALLBACK_MODELS='["openai:gpt-5.1","openai:gpt-5-mini"]'
```

Keep GPT-4o as a compatibility option, not the default new fallback, unless a
specific deployment target lacks GPT-5 access.

## Goals

- Configure a primary model plus ordered fallback models from environment
  variables.
- Retry fallback only for likely transient provider failures: rate limits,
  provider overload, 5xx responses, network timeouts, and connection errors.
- Preserve existing RAG behavior: same system prompt, same SQL/retrieve tools,
  same Chainlit handlers, same usage tracking.
- Record which model answered each request in logs and, if practical, in traces.
- Keep local testing cheap and deterministic with unit tests that simulate model
  failures.
- Ship Azure App Service support with Key Vault-backed secrets and Bicep app
  settings.

## Non-goals

- Do not fallback when the model returns a valid refusal, content-filter error,
  prompt/tool validation error, SQL tool error, or user rate-limit denial.
- Do not migrate embeddings away from OpenAI; `OPENAI_API_KEY` is already needed
  for embeddings and will also support the OpenAI fallback.
- Do not add UI provider selection for users. Provider routing is an operator
  concern.
- Do not build a separate Azure OpenAI path in the first pass. Add it later only
  if public OpenAI API access is not acceptable for production.

## Current State

- `config.py` defines `llm_model`, `llm_effort`, `openai_api_key`, and
  `anthropic_api_key`.
- `rag/agent.py` creates `rag_agent = Agent(settings.llm_model, ...)` at import
  time and registers `query` / `retrieve` tools on that agent.
- `app.py` calls `rag_agent.run(...)` from both quick-query and normal message
  handlers, then records Pydantic AI usage tokens through `record_usage(result)`.
- `infra/modules/app-service.bicep` already injects `ANTHROPIC_API_KEY` and
  `OPENAI_API_KEY` from Key Vault.
- `docs/deploy-azure-app-service.md` already prompts for both keys and stores
  `openai-api-key`.

## Design

### 1. Configuration

Add these settings to `Settings` in `config.py`:

```python
# LLM failover
llm_fallback_models: JsonStrList = []
llm_request_timeout_seconds: float = 60.0
llm_fallback_status_codes: list[int] = [429, 500, 502, 503, 504, 529]
llm_openai_reasoning_effort: str | None = "low"
llm_max_tokens: int | None = None
```

Notes:

- Default `llm_fallback_models` to `[]` so local and deployed behavior does not
  change until explicitly enabled.
- Use the existing JSON-array env var pattern (`JsonStrList`) for
  `LLM_FALLBACK_MODELS`.
- Add a JSON/int-list parser for `LLM_FALLBACK_STATUS_CODES`, mirroring
  `JsonStrList`, or keep it as a comma-separated string only if tests cover
  Azure's exact value.
- Keep `llm_effort` for Anthropic, but build model settings as a plain combined
  dict so OpenAI fallbacks can receive `openai_reasoning_effort` without using
  an Anthropic-only settings class.

Example `.env`:

```bash
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
LLM_MODEL=anthropic:claude-sonnet-5
LLM_EFFORT=low
LLM_FALLBACK_MODELS='["openai:gpt-5.1"]'
LLM_OPENAI_REASONING_EFFORT=low
LLM_REQUEST_TIMEOUT_SECONDS=60
LLM_FALLBACK_STATUS_CODES='[429,500,502,503,504,529]'
```

### 2. Agent Construction

Refactor `rag/agent.py` so the agent model is assembled by helper functions
instead of hard-coded into the global `Agent(...)` call.

Use Pydantic AI's built-in fallback wrapper:

```python
from pydantic_ai.models.fallback import FallbackModel
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError


def should_fallback(exc: Exception) -> bool:
    if isinstance(exc, ModelHTTPError):
        return exc.status_code in settings.llm_fallback_status_codes
    return isinstance(exc, ModelAPIError)


def build_model():
    if settings.llm_fallback_models:
        return FallbackModel(
            settings.llm_model,
            *settings.llm_fallback_models,
            fallback_on=should_fallback,
        )
    return settings.llm_model
```

Then build settings separately:

```python
def build_model_settings() -> dict:
    model_settings = {"timeout": settings.llm_request_timeout_seconds}
    if settings.llm_max_tokens is not None:
        model_settings["max_tokens"] = settings.llm_max_tokens
    if settings.llm_effort:
        model_settings["anthropic_effort"] = settings.llm_effort
    if settings.llm_openai_reasoning_effort:
        model_settings["openai_reasoning_effort"] = settings.llm_openai_reasoning_effort
    return model_settings
```

The Pydantic AI provider implementations read only their own settings keys, so a
combined dict is simpler than branching between `AnthropicModelSettings` and
`OpenAIModelSettings`.

Construct the global agent with:

```python
rag_agent = Agent(
    build_model(),
    deps_type=Deps,
    system_prompt=settings.system_prompt,
    model_settings=build_model_settings(),
)
```

Keep the existing `@rag_agent.tool` registrations in the first PR. If tests show
that global construction makes monkeypatching awkward, follow up by extracting
`query` and `retrieve` as plain functions and passing them with
`Agent(..., tools=[query, retrieve])`.

### 3. Observability

Add structured logs around each LLM run without leaking prompts or secrets:

- Primary model and configured fallback list at startup.
- Fallback exception class, status code, and provider/model name when failover
  happens.
- Final answering model when Pydantic AI exposes it in result metadata or trace
  span attributes.

If Pydantic AI's `FallbackModel` does not expose "selected model" directly in
`RunResult`, rely on Logfire/OpenTelemetry attributes first and add an app log
only for fallback failures. Avoid parsing model names out of exception strings.

Optional later enhancement: add `llm_provider` / `llm_model` columns to
`user_usage` so `/admin` can show cost by provider. Defer this unless cost
visibility across providers becomes important.

### 4. Failure Policy

Fallback should trigger for:

- `ModelHTTPError` with status code in `LLM_FALLBACK_STATUS_CODES`.
- Other `ModelAPIError` instances that represent provider/network API failures.

Fallback should not trigger for:

- `ContentFilterError`.
- `UsageLimitExceeded`.
- SQL validation errors or Postgres errors returned by the `query` tool.
- User authorization or daily-limit denials in `app.py`.
- 400/401/403/404 responses in normal production config, because these indicate
  bad credentials, bad model names, or missing access and should alert loudly.

For local manual failover testing only, it is acceptable to temporarily include
`401` in `LLM_FALLBACK_STATUS_CODES` and use an invalid Anthropic key. Remove
`401` before committing or deploying.

### 5. Tests

Add focused unit coverage:

- `tests/unit/test_config_lists.py`
  - Parses `LLM_FALLBACK_MODELS='["openai:gpt-5.1"]'`.
  - Parses `LLM_FALLBACK_STATUS_CODES='[429,500,503]'`.
  - Blank fallback model list becomes `[]`.
- `tests/unit/test_llm_fallback.py`
  - `build_model()` returns the primary model when no fallbacks are configured.
  - `build_model()` returns `FallbackModel` when fallbacks are configured.
  - `should_fallback(ModelHTTPError(503, ...))` is true.
  - `should_fallback(ModelHTTPError(401, ...))` is false by default.
  - `should_fallback(ContentFilterError(...))` is false.
  - `build_model_settings()` includes Anthropic effort, OpenAI reasoning effort,
    and timeout without importing provider-specific settings classes.

Add an async smoke test only if it can be done without live provider calls. Do
not make regular unit tests call Anthropic or OpenAI.

### 6. Local Testing

Run deterministic tests first:

```bash
uv run pytest tests/unit/test_config_lists.py tests/unit/test_llm_fallback.py -v
uv run pytest tests/unit -v
```

Run a local end-to-end check against real providers:

```bash
uv run chainlit run app.py
```

Manual checklist:

1. Start with `LLM_FALLBACK_MODELS=[]` or unset; ask a known query such as
   `CVE-2021-44228 (Log4Shell)` and confirm current Claude behavior still works.
2. Set `LLM_FALLBACK_MODELS='["openai:gpt-5.1"]'`; restart; ask the same query
   and confirm no startup/config errors.
3. Temporarily force a primary failure locally:
   - set an invalid `ANTHROPIC_API_KEY`;
   - temporarily set `LLM_FALLBACK_STATUS_CODES='[401,429,500,502,503,504,529]'`;
   - restart and ask the same query;
   - confirm the answer succeeds through OpenAI and logs show the primary
     failure.
4. Restore the real Anthropic key and remove `401` from fallback status codes.
5. Confirm usage accounting still records exactly one query and nonzero token
   totals after fallback.
6. Confirm `retrieve` and `query` tools both work through the fallback model:
   - semantic: `LLM prompt injection vulns`
   - SQL/listing: `List the 10 newest KEV entries by date_added`

### 7. Azure App Service Deployment

#### Bicep changes

In `infra/modules/app-service.bicep`, make LLM failover configurable instead of
hard-coding only `LLM_MODEL`.

Add parameters near the existing app settings inputs:

```bicep
@description('Primary Pydantic AI model name.')
param llmModel string = 'anthropic:claude-sonnet-5'

@description('JSON array of fallback Pydantic AI model names.')
param llmFallbackModels string = '["openai:gpt-5.1"]'

@description('JSON array of HTTP status codes that trigger fallback.')
param llmFallbackStatusCodes string = '[429,500,502,503,504,529]'

@description('OpenAI reasoning effort for fallback models.')
param llmOpenAIReasoningEffort string = 'low'

@description('LLM request timeout in seconds.')
param llmRequestTimeoutSeconds string = '60'
```

Update app settings:

```bicep
{
  name: 'LLM_MODEL'
  value: llmModel
}
{
  name: 'LLM_FALLBACK_MODELS'
  value: llmFallbackModels
}
{
  name: 'LLM_FALLBACK_STATUS_CODES'
  value: llmFallbackStatusCodes
}
{
  name: 'LLM_OPENAI_REASONING_EFFORT'
  value: llmOpenAIReasoningEffort
}
{
  name: 'LLM_REQUEST_TIMEOUT_SECONDS'
  value: llmRequestTimeoutSeconds
}
```

Keep these existing Key Vault references:

```bicep
ANTHROPIC_API_KEY -> anthropic-api-key
OPENAI_API_KEY -> openai-api-key
```

No new secret is needed for public OpenAI fallback because `OPENAI_API_KEY` is
already deployed for embeddings.

#### Parameter file

In `infra/parameters.dev.bicepparam`, explicitly set:

```bicep
param llmModel = 'anthropic:claude-sonnet-5'
param llmFallbackModels = '["openai:gpt-5.1"]'
param llmFallbackStatusCodes = '[429,500,502,503,504,529]'
param llmOpenAIReasoningEffort = 'low'
param llmRequestTimeoutSeconds = '60'
```

#### Docs

Update `docs/deploy-azure-app-service.md`:

- Add the fallback env vars to the configuration table.
- Note that `OPENAI_API_KEY` now powers both embeddings and fallback chat.
- Add a short rollback section:

```bash
az webapp config appsettings set \
  -g rg-vulncopilot-dev \
  -n app-vulncopilot-dev \
  --settings LLM_FALLBACK_MODELS='[]'
```

#### Deploy

Use the existing Azure deployment path for this repo. After the Bicep change is
merged and the image is built, deploy the updated infrastructure/app settings,
then restart the web app if the pipeline does not do so automatically.

Validation commands:

```bash
az webapp config appsettings list \
  -g rg-vulncopilot-dev \
  -n app-vulncopilot-dev \
  --query "[?starts_with(name, 'LLM_')].[name,value]" \
  -o table

az webapp log tail \
  -g rg-vulncopilot-dev \
  -n app-vulncopilot-dev
```

Production smoke checklist:

1. Confirm normal Claude path answers a known query.
2. Confirm app logs show the primary and fallback model configuration at startup.
3. Temporarily set `LLM_FALLBACK_MODELS='[]'` to verify rollback is a single app
   setting change, then restore the configured fallback list.
4. During a real provider incident, confirm user-facing behavior is degraded only
   in latency, not availability.

### 8. Kubernetes Follow-up

This request is Azure-focused, but keep parity with EKS afterward:

- Add `LLM_FALLBACK_MODELS`, `LLM_FALLBACK_STATUS_CODES`,
  `LLM_OPENAI_REASONING_EFFORT`, and `LLM_REQUEST_TIMEOUT_SECONDS` to
  `k8s/configmap.yaml`.
- Update `k8s/secret.yaml.example` comments to mention that `OPENAI_API_KEY`
  powers embeddings and fallback chat.
- Update `docs/eks-runbook.md` only if EKS remains an active deployment target.

## Rollout Sequence

1. Add config fields and unit tests.
2. Refactor `rag/agent.py` to build a `FallbackModel` when fallback models are
   configured.
3. Run local unit tests and live smoke tests.
4. Update README configuration docs.
5. Update Azure Bicep parameters and deployment docs.
6. Deploy to Azure dev with fallback enabled.
7. Smoke test production routes and monitor logs.
8. Leave `LLM_FALLBACK_MODELS='[]'` as the fast rollback lever.

## Open Questions

- Should `/admin` track cost by actual answering model? If yes, add provider/model
  fields to `user_usage` in a later PR.
- Do we want a small circuit breaker that skips the primary for 60-300 seconds
  after repeated provider failures? Pydantic AI fallback handles per-request
  failover, but a circuit breaker would reduce latency during a sustained Claude
  outage.
- Should Azure production use public OpenAI or Azure OpenAI for policy/network
  reasons? The first pass assumes public OpenAI because the app already uses it
  for embeddings.
