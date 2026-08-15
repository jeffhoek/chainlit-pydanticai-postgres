# Migrate to Pydantic AI v2

Plan for upgrading this app from `pydantic-ai` v1 (currently `1.107.5`, pinned `>=1.106.0,<2`) to v2 (`2.2.0` as of this writing).

The `<2` cap is deliberate: a lockfile refresh would otherwise pull v2 in as an incidental transitive bump, ahead of the code changes below. Lifting the cap is step one of this migration.

## Context

Pydantic AI v2 (stable since 2026-06-23) is a "harness-first" redesign: many `Agent` constructor arguments move into composable **capabilities**, several accessor methods become properties, and a handful of provider/tool APIs are renamed or removed. Pydantic's own recommended path is to first clear all v1 deprecation warnings on the latest v1 release, then upgrade — that covers most of the diff. What's left is a short list of behavior changes with no v1 equivalent.

This app's usage of `pydantic-ai` is small and concentrated in two files, so the actual code changes are expected to be minor. This plan exists to make sure nothing is missed.

## Current usage inventory

| Location | Usage | Affected in v2? |
|---|---|---|
| `rag/agent.py:20-24` | `Agent(settings.llm_model, deps_type=Deps, system_prompt=settings.system_prompt)` | No — core args, unchanged |
| `rag/agent.py:27,58` | `@rag_agent.tool` decorator, `RunContext[Deps]` | No — unchanged |
| `config.py:55` | `llm_model: str = "anthropic:claude-haiku-4-5-20251001"` | No — only bare `openai:` prefix changes default API |
| `app.py:30` | `Agent.instrument_all()` | Check — instrumentation moved to `capabilities=[Instrumentation(...)]`; confirm `instrument_all()` classmethod still exists in v2 |
| `app.py:158` | `usage = result.usage()` (called as a method) | **Yes** — `usage()` → `usage` (property) in v2 |
| `app.py:163-164` | `usage.input_tokens`, `usage.output_tokens` | No — v2 already uses these names (v1's `request_tokens`/`response_tokens` are the ones being renamed) |
| `app.py:185,226` | `result.all_messages()` | No — unaffected |
| `app.py:186,227` | `result.output` | No — unaffected |
| `docs/mcp-server.md:157-172` | Example: `from pydantic_ai.mcp import MCPServerHTTP`, `Agent(..., mcp_servers=[mcp_server])`, `agent.run_mcp_servers()` | **Yes** — `MCPServerHTTP` removed in favor of unified `MCPToolset`; `mcp_servers=[...]` → `toolsets=[...]` |
| `docs/observability.md:18` | Describes `Agent.instrument_all()` behavior | Update wording if instrumentation API/defaults change |
| `plans/eval-framework.md`, `plans/public-access-plan.md` | Reference `result.usage()`, `result.all_messages()` | Historical planning docs — update `result.usage()` mentions for accuracy, no functional impact |

No test in `tests/` mocks or imports `pydantic_ai` internals (no `TestModel`/`FunctionModel` usage), so the test suite itself shouldn't need rewriting — it should just keep passing once `app.py` and `rag/agent.py` are updated.

`logfire.instrument_pydantic_ai()` (`app.py:14`) comes from the separately-versioned `logfire` package; confirm the installed `logfire` version supports Pydantic AI v2's new instrumentation format (v2 defaults to instrumentation format version 5).

## Non-issues (confirmed not applicable)

- No bare `openai:` model strings are passed to `Agent(...)` — the app's only OpenAI usage is a direct `AsyncOpenAI` client for embeddings, which pydantic-ai's Responses-API default change doesn't touch.
- No `prepare_tools`, `history_processors`, `event_stream_handler`, or `mcp_servers=[...]` args on the app's own `Agent(...)` construction (only the *docs example* uses `mcp_servers`).
- No `ModelProfile` subclassing or attribute access in this codebase.
- No use of `Grok`/`GoogleGLAProvider`/`GeminiModel`/Outlines integration.
- No `sequential=True` tool flag usage.

## Migration steps

1. **Upgrade to latest v1 first.** Bump `pydantic-ai` to the newest `1.x` (v1.107.0+) via `uv add "pydantic-ai>=1.107.0,<2"` and run the app/tests with deprecation warnings enabled (`python -W error::DeprecationWarning` or pytest's default warning capture) to surface anything relevant before jumping to v2.
2. **Fix `result.usage()` → `result.usage`** in `app.py:158`. This is the one confirmed behavior change in this codebase's runtime path.
3. **Verify `Agent.instrument_all()`** still works as expected under v2's instrumentation defaults (format v5, aggregated usage attributes under `gen_ai.aggregated_usage.*`). Update `docs/observability.md` if the described behavior shifts.
4. **Bump `logfire`** to a version compatible with Pydantic AI v2, if needed, and re-check Langfuse (`Agent.instrument_all()` path in `app.py:26-30`) traces still populate correctly.
5. **Bump the dependency pin**: `pydantic-ai>=2.2.0` in `pyproject.toml`, `uv lock`, `uv sync`.
6. **Update `docs/mcp-server.md`** example code: replace `MCPServerHTTP` with `MCPToolset`, `mcp_servers=[...]` with `toolsets=[...]`, and re-verify the snippet still runs against this app's `/mcp` endpoint (see `docs/mcp-server.md` for the live example).
7. **Update planning docs** (`plans/eval-framework.md`, `plans/public-access-plan.md`) that reference `result.usage()` so future readers aren't misled about the current API.
8. **Run full test suite** (`uv run pytest`) plus a manual smoke test: start the app (`uv run chainlit run app.py`), send a chat message that triggers both the `query` and `retrieve` tools, and confirm token-usage rate limiting (`app.py:129-169`) still records correctly against `user_usage`.
9. **Manual regression check on quick-query actions** (`on_quick_query` in `app.py`), since it shares the same `result.usage()` / `result.all_messages()` / `result.output` path as `on_message`.

## Rollback

If v2 introduces an unexpected regression, `pydantic-ai` is a single pinned dependency (`pyproject.toml` + `uv.lock`) — revert the version bump commit and `uv sync` to return to the tested v1.67.0 baseline. No schema or data migrations are involved.

## Open questions

- Should `Agent.instrument_all()` be replaced with the more granular `capabilities=[Instrumentation(...)]` per-agent, now that there's only one agent (`rag_agent`) in the app? Not required for the migration, but worth considering since v2 favors explicit capabilities over global instrumentation.
- Confirm whether `fastmcp` (used in `mcp_server/`) has any coupling to `pydantic-ai`'s MCP classes — it appears to be independent (this app is an MCP *server*, not an MCP client), but worth a quick grep during implementation.
