# Pluggable model backends (Gemini, GPT, GLM)

Make the generation model swappable by `LLM_MODEL` alone — Anthropic Claude today, plus
Google Gemini, OpenAI GPT, and open-weights GLM (hosted or self-hosted), with no code change
per provider.

## Scope

**In scope:** the generation model only — the Pydantic AI agent in [rag/agent.py](../rag/agent.py).

**Out of scope: embeddings.** `EMBEDDING_MODEL=text-embedding-3-small` produces 1536-dim
vectors and the pgvector column and index are built on that dimension. Switching embedding
providers would require a schema change plus a full re-embed of the KEV + NVD corpus.
`OPENAI_API_KEY` therefore stays a required setting on *every* deployment, whatever
`LLM_MODEL` is set to, and [rag/embeddings.py](../rag/embeddings.py) and
[mcp_server/server.py](../mcp_server/server.py) are untouched. Worth doing eventually; it is
a separate plan.

## Already in place

`pydantic-ai` (not `pydantic-ai-slim`) is the declared dependency, and the full package
pulls every provider extra. `google-genai 1.66.0` is already resolved in `uv.lock`, and
`openai` is already a direct dependency for embeddings. **No dependency changes, no
`uv add`.**

Pydantic AI's `infer_model()` already resolves ~20 provider prefixes from the model string,
including `ollama` and `cerebras`. Most of "make it pluggable" is therefore not ours to
build — it is choosing not to get in its way.

## The one real code blocker

[rag/agent.py:25](../rag/agent.py#L25) hard-codes Anthropic-specific settings:

```python
model_settings=(AnthropicModelSettings(anthropic_effort=settings.llm_effort) if settings.llm_effort else None),
```

Each model class reads only its own prefixed keys, so `anthropic_effort` is silently ignored
by every other provider. A Gemini or GLM run would work but quietly lose the latency/cost
tuning that the comment at [config.py:56-61](../config.py#L56) exists to justify.

## Design: prefix-keyed settings dispatch

One helper in `rag/agent.py`, keyed on the `LLM_MODEL` prefix, translating the single
semantic `LLM_EFFORT` knob into each provider's vocabulary:

| Prefix | Settings |
|---|---|
| `anthropic:` | `AnthropicModelSettings(anthropic_effort=effort)` |
| `google-gla:` / `google-vertex:` | `GoogleModelSettings(google_thinking_config=..., google_safety_settings=...)` |
| `openai:` | `OpenAIChatModelSettings(openai_reasoning_effort=effort)` |
| `cerebras:` | `CerebrasModelSettings(cerebras_disable_reasoning=(effort == "low"))` |
| anything else | `None` |

**The `None` default is the extensibility mechanism.** Any provider Pydantic AI supports
works immediately with generic settings; a branch gets added only when we want that
provider's specific thinking/effort knob. No registry, no plugin system, no abstraction over
`Model` — just don't pass the wrong provider's settings. This is the whole feature.

`LLM_EFFORT` values stay `low|medium|high|max|blank`, since Anthropic and OpenAI already
share that vocabulary. The leaky cases get escape hatches rather than a lossy universal
mapping:

- **Gemini** splits by generation: 3.x uses `thinking_level` (`"low"`/`"high"`), 2.5 uses
  numeric `thinking_budget` (`0` disables, `-1` automatic — **2.5-pro cannot disable
  thinking**, minimum 128). Add an optional `LLM_THINKING_BUDGET` int that, when set, wins
  over `thinking_level`.
- **OpenAI** rejects `low` on some reasoning models and treats `none` as the GPT-5.1+
  default; `openai_supports_reasoning_effort_none` in the model profile gates this.
- **Cerebras** exposes only a boolean `cerebras_disable_reasoning`, and only on reasoning
  models (`zai-glm-4.6`, `gpt-oss-120b`).
- **`max` is Anthropic-only.** Verified against the installed packages, the accepted value
  sets do not line up: Anthropic `low|medium|high|max`, OpenAI
  `none|minimal|low|medium|high|xhigh`, Gemini `thinking_level` `MINIMAL|LOW|MEDIUM|HIGH`.
  `LLM_EFFORT=max` would be rejected by OpenAI and Gemini, so the dispatch clamps `max` →
  `high` outside Anthropic rather than forwarding it blind.
- **Local backends get `None`.** Ollama and LM Studio expose no effort knob over the
  OpenAI-compatible endpoint (GLM's and Qwen's thinking toggles are not reachable through it),
  so `LLM_EFFORT` is simply inert there.

Unit-testable with no network: one table-driven test over prefixes.

## Provider selection stays in the model string

No new "provider" setting. Auth is the only per-provider plumbing:

| `LLM_MODEL` | Auth |
|---|---|
| `anthropic:claude-sonnet-5` | `ANTHROPIC_API_KEY` (today's default) |
| `google-gla:gemini-3-flash-preview` | `GOOGLE_API_KEY` |
| `google-vertex:gemini-3-pro-preview` | ADC / service account + `GOOGLE_CLOUD_PROJECT` |
| `openai:gpt-5.1` | `OPENAI_API_KEY` (already set for embeddings) |
| `cerebras:zai-glm-4.6` | `CEREBRAS_API_KEY` |
| `openrouter:z-ai/glm-4.6` | `OPENROUTER_API_KEY` |
| `ollama:glm-4.5-air` | `OLLAMA_BASE_URL` (no key) |

All provider API keys must be **optional** in `Settings` (as `anthropic_api_key` already is):
ETL scripts never construct the agent, and `google-vertex`/`ollama` have no key at all. Let
the provider raise.

Note the agent is constructed at **import time** ([rag/agent.py:21](../rag/agent.py#L21)),
which resolves the provider and demands its credentials immediately — this is why
[tests/conftest.py:7](../tests/conftest.py#L7) sets an `ANTHROPIC_API_KEY` placeholder. A
missing key is a startup crash, not a first-query error.

**GPT is nearly free.** The `openai` package is already a dependency, `OPENAI_API_KEY` is
already required, and the only new code is one dispatch branch. Include it — it costs a
three-line branch and one test row, and it is the reference implementation for every
OpenAI-compatible endpoint below.

## GLM: hosted beats self-hosted here

Pydantic AI already knows GLM as a first-class model — `cerebras:zai-glm-4.6` and
`cerebras:zai-glm-4.7` are in `KnownModelName`, with `CerebrasModelSettings` for reasoning
control. So **Ollama and LM Studio are not required**; they are one of four routes:

| Route | `LLM_MODEL` | Notes |
|---|---|---|
| Cerebras | `cerebras:zai-glm-4.6` | First-class in Pydantic AI, very high tokens/sec, has an effort knob. Lowest friction. |
| OpenRouter | `openrouter:z-ai/glm-4.6` | Dedicated provider; easy A/B across many models. |
| Z.ai direct | `openai:glm-4.6` + base URL | Their API is OpenAI-compatible. **Conflicts with embeddings** — see below. |
| Local Ollama / LM Studio | `ollama:<any model tag>` | Base URL from settings. Zero code change per model. LM Studio works through the same prefix (`OllamaProvider` is just `OpenAIChatModel` + base URL, and LM Studio is OpenAI-compatible on `:1234/v1`). |

### The `OPENAI_BASE_URL` conflict

`OPENAI_BASE_URL` is read by the OpenAI SDK process-wide, so pointing it at Z.ai (or any
compatible endpoint) also redirects the embedding client in
[app.py:87,204](../app.py#L87) — embeddings would silently go to a server that does not
serve `text-embedding-3-small`. If we take the Z.ai-direct route, the agent must construct
`OpenAIChatModel(name, provider=OpenAIProvider(base_url=..., api_key=...))` explicitly
rather than relying on the env var. **Prefer the `ollama:`/`cerebras:`/`openrouter:`
prefixes, which carry their own base URL and sidestep this entirely.**

### Self-hosting: sizing is a deploy-time decision, not a design-time one

Nothing in the code encodes a model choice. `LLM_MODEL` plus a base URL is the entire
interface, so the model can change per machine with no redeploy of anything but config. What
follows is a sizing rule to apply to whatever hardware is in front of you — not a
recommendation baked into the app.

**Memory budget.** On Apple silicon the GPU gets ~75% of unified memory by default
(`iogpu.wired_limit_mb`, raisable with `sudo sysctl`). This agent needs a large context (next
section), and the KV cache for it competes with the weights. A workable rule:

> **weights budget ≈ 55% of unified RAM** for a comfortable 32k-context run at 4-bit.

Weight size ≈ params × bytes-per-weight: **~0.55 B/param at Q4_K_M**, ~0.7 at Q5, ~1.06 at
Q8, 2.0 at fp16. Inverting the rule gives the largest model that fits:

| Unified RAM | Q4 weights budget | Roughly |
|---|---|---|
| 16GB | ~9GB | up to ~14B dense |
| 24GB | ~13GB | up to ~24B dense |
| 48GB | ~26GB | up to ~45B dense, or a ~30B MoE with room to spare |
| 64GB | ~35GB | up to ~60B dense |
| 128GB | ~70GB | ~106B-class MoE (e.g. GLM-4.5-Air) |
| 512GB | ~280GB | ~355B-class MoE (e.g. GLM-4.6) |

Two consequences worth internalising:

- **The GLM everyone is talking about is a datacenter model.** GLM-4.6 is ~355B params
  (~32B active); GLM-4.5-Air is ~106B (~12B active). Per the table those need ~512GB and
  ~128GB respectively. On any laptop, "GLM" means GLM-4-9B — a 2024-era model that shares the
  name and little else. If the actual GLM-4.6 is the goal, take the Cerebras or OpenRouter
  route; self-hosting is not a substitute.
- **For MoE models, total params set the memory cost but active params set the speed.** A
  30B-A3B model occupies ~18GB yet reads only ~3B params per token, so it generates faster
  than a dense 14B that is half its size. On bandwidth-limited unified memory that trade
  usually favours MoE — prefer the largest MoE that fits the budget over the largest dense
  model.

Quant sizes and model tags move fast; confirm against the current Ollama library rather than
this table.

**Capability bar: tool calling, not SQL.** The agent must choose between `query` and
`retrieve`, emit a well-formed function call, read back a result table, and often call again.
Coder-tuned models are better at raw SQL but weaker in an agentic loop; general instruct
models with solid function-calling support are the right trade. This, not parameter count, is
what decides whether a given local model is usable here.

**Expect a latency regression.** `llm_effort="low"` exists because adaptive thinking ~4x'd
response time ([config.py:56](../config.py#L56)). A local model re-prefills the ~1,800-token
system prompt on each of the 3-4 round trips a single question takes. Local is the right
choice for offline or on-prem-only operation, not for beating a hosted model on speed.

**Ollama's default context window will silently break this app.** Ollama defaults
`num_ctx` to 4096. This agent's system prompt is **~1,800 tokens on its own** (6,473 chars
of SQL schema, SSVC/EPSS guidance, and tool-routing rules), before tool schemas, up to
`MAX_HISTORY_MESSAGES=50` turns of history, and `query` results capped at `MAX_QUERY_ROWS`.
It will blow past 4096 on the first real question, Ollama will silently truncate, the model
will lose the schema, and it will emit garbage SQL — which reads as "GLM is bad at this"
when it is actually a config problem. Worse, `num_ctx` **cannot be set over the
OpenAI-compatible `/v1/chat/completions` endpoint** that Pydantic AI uses; it has to be set
server-side via `OLLAMA_CONTEXT_LENGTH` or baked into the model with a Modelfile
`PARAMETER num_ctx 32768`. Document this in the runbook.

The matching app-side lever already exists: `MAX_HISTORY_MESSAGES` (default 50,
[config.py:53](../config.py#L53)) is what actually determines how much history is replayed
into that window. Lowering it is the cheapest way to fit a smaller-context local model, and
costs only the depth of follow-up references the agent can resolve.

The upside worth naming: a local model means **zero LLM egress**, which simplifies
[k8s/networkpolicy-egress.yaml](../k8s/networkpolicy-egress.yaml) and keeps vulnerability
queries entirely on-prem.

## Per-provider risks

### Gemini safety filters — the project-specific one

Most likely to bite. Gemini applies safety filtering by default, and this corpus is
wall-to-wall "remote code execution", "exploit", "ransomware campaign use", "privilege
escalation". `HARM_CATEGORY_DANGEROUS_CONTENT` can return a blocked candidate with
`finish_reason=SAFETY`, surfacing as an empty answer on exactly the queries the app exists to
answer. Claude has no equivalent failure mode, so nothing in the current code anticipates it.
Set `google_safety_settings` explicitly for all four harm categories at `BLOCK_ONLY_HIGH`
(or `OFF` where permitted). Treat "does a KEV exploit question return non-empty" as a
required acceptance check.

### Tool-calling fidelity — the one that decides whether GLM is usable

The app's entire value is `query`/`retrieve` routing driven by a long system prompt with SQL
schema. GLM-4.5/4.6 are pitched on agentic tool use and should hold up hosted; quantized and
behind Ollama's template handling is where it degrades. [rag/sql_utils.py](../rag/sql_utils.py)
`validate_sql()` is already the safety net against a weaker model emitting non-`SELECT`, so
the failure mode is bad answers, not unsafe ones.

### Cost reporting

`LLM_INPUT_COST_PER_MILLION` / `LLM_OUTPUT_COST_PER_MILLION`
([config.py:222](../config.py#L222)) are already env-configurable — but the defaults are
Sonnet's 3.00/15.00. Any non-Anthropic deployment that does not override them makes the
`/admin` dashboard silently misreport spend. For a local model the honest values are `0`.

Also verify with one live run per provider that reasoning/thinking tokens land in
`usage.output_tokens` and not only in `provider_details` (Gemini stashes
`thoughts_tokens` there — `pydantic_ai/models/google.py:1286`). `record_usage()`
([app.py:159](../app.py#L159)) bills and rate-limits off `input_tokens`/`output_tokens`; if
thinking tokens are excluded, both cost and quota understate real usage.

## Work items

### Phase 1 — code

| File | Change |
|---|---|
| [config.py](../config.py) | Add optional `google_api_key`, `cerebras_api_key`, `openrouter_api_key`, `ollama_base_url`, `llm_thinking_budget: int \| None`. Generalize the `llm_effort` comment beyond Anthropic. |
| [rag/agent.py](../rag/agent.py) | Add prefix-keyed `_model_settings()` (unknown → `None`) incl. Gemini safety settings; replace line 25. |
| [tests/conftest.py](../tests/conftest.py) | Add placeholder keys so import-time agent construction works whichever default `LLM_MODEL` carries. |
| `tests/unit/test_model_settings.py` (new) | Table-driven per prefix; unknown prefix → `None`; effort unset → `None`; `llm_thinking_budget` overrides `thinking_level`. No network. |

### Phase 2 — config plumbing

`.env.example`, [k8s/configmap.yaml:26](../k8s/configmap.yaml#L26),
[k8s/secret.yaml.example](../k8s/secret.yaml.example),
[k8s/external-secret.yaml](../k8s/external-secret.yaml) (new SSM paths),
[infra/modules/app-service.bicep:120,159](../infra/modules/app-service.bicep#L120) (Key
Vault secrets). Anthropic stays the shipped default; the rest are commented alternatives.

### Phase 3 — egress allow-list (EKS only)

Each hosted provider adds a destination to
[k8s/networkpolicy-egress.yaml](../k8s/networkpolicy-egress.yaml),
[scripts/refresh_egress_ips.py](../scripts/refresh_egress_ips.py) (`DNS_RESOLVED` +
template), and [docs/egress-hardening.md](../docs/egress-hardening.md):
`generativelanguage.googleapis.com:443` (or `*-aiplatform.googleapis.com` for Vertex),
`api.cerebras.ai:443`, `openrouter.ai:443`.

**Caveat:** Google's API front end is anycast across a very large address space and rotates
harder than the Cloudflare-fronted entries already flagged as fragile in that doc. Pinning a
resolved `/32` will break — either allow Google's published ranges
(`https://www.gstatic.com/ipranges/goog.json`) or accept a scheduled refresh. Only affects
the EKS deployment. A local Ollama backend needs no rule at all.

### Phase 4 — docs

README `LLM_MODEL` table + "LLM Model Options" (add Gemini/GPT/GLM rows and the
cost-override note), [docs/eks-runbook.md:600,616](../docs/eks-runbook.md#L600),
[docs/deploy-gcp-cloud-run.md:92,113](../docs/deploy-gcp-cloud-run.md#L92),
[docs/deploy-azure-app-service.md:284](../docs/deploy-azure-app-service.md#L284),
[docs/observability.md](../docs/observability.md) (`instrument_openai()` covers embeddings
only; agent calls are traced via `instrument_pydantic_ai()` for every provider). If a local
backend is adopted, add the `num_ctx` warning to the runbook.

## Verification

Unit tests cover the dispatch. What only fails live, per provider:

1. **Tool calling** — run the [ACTION_BUTTONS](../k8s/configmap.yaml) quick-query set end to
   end and diff answers against current Claude output. This is the real gate, especially
   for GLM.
2. **Gemini safety blocks** — confirm exploit/ransomware queries return content.
3. **Token accounting** — one run each; check `input_tokens`/`output_tokens` are non-zero and
   include reasoning tokens.
4. **Latency** — the reason `llm_effort="low"` exists. Compare against Sonnet 5 at low effort.

[plans/eval-framework.md](eval-framework.md) is the right long-term home for 1; this plan
does not depend on it landing. Multi-provider support is, however, the strongest argument
for building it — four backends is where manual spot-checking stops scaling.

## Decisions

- **Local Ollama / LM Studio is the primary route**, with the base URL as a first-class
  setting so the same build serves Ollama, LM Studio, or vLLM. Hosted GLM via
  `cerebras:zai-glm-4.6` remains available through the same dispatch at no extra cost.
- **Phase 1 only for now** — code and unit tests. Config plumbing, egress, and docs follow
  once real models are picked.
- **No model choice or memory budget is encoded in code.** Sizing is deploy-time guidance
  (above), not application behaviour.

## Open questions

1. **Gemini API or Vertex?** Plan assumes `google-gla` first (one API key, mirrors the
   existing pattern); `google-vertex` needs no app code, only credentials, and fits Cloud Run
   better later.
2. **Which Gemini?** `gemini-3-flash-preview` for cost/latency, `gemini-3-pro-preview` for
   SQL-generation quality. Benchmark flash first — the workload is short scoped lookups.
3. **Does Anthropic stay the default?** Plan assumes yes; everything else is opt-in via
   `LLM_MODEL`.
