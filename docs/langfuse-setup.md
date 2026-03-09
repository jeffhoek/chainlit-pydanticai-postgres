# Langfuse Observability

Self-hosted [Langfuse](https://langfuse.com/) stack for local AI telemetry, running alongside the chatbot via Podman Compose.

## How It Works

Langfuse initialization in `app.py` is conditional — it only activates when `LANGFUSE_PUBLIC_KEY` is set. This means:

- **Podman Compose** (local dev): Langfuse env vars are loaded from `.env`, so tracing is enabled automatically.
- **Cloud Run** (production): No Langfuse vars are set, so the app starts cleanly without any telemetry overhead.

When active, `Agent.instrument_all()` enables OpenTelemetry instrumentation on all PydanticAI agents. Traces capture agent runs, tool calls, token counts, and latency.

## Dependencies

The `docker-compose.yaml` at the project root defines a 7-service Langfuse stack (PostgreSQL, ClickHouse, MinIO, Redis, Langfuse server, worker) plus the chatbot service.

The Python dependency `langfuse>=3.0.0` is listed in `pyproject.toml`.

## Setup

1. Add Langfuse keys to your `.env` (see `.env.example` for the template variables).

2. Start all services:

   ```bash
   podman compose up --build -d
   ```

3. Wait ~30s for Langfuse health checks to pass.

4. Open `http://localhost:3000` and log in with `admin@local.dev` / `password`.

5. Open `http://localhost:8080`, log in to the chatbot, and send a message.

6. Back in the Langfuse UI, check the **Traces** page — you should see a trace with the PydanticAI agent run including the `retrieve` tool call, token counts, and latency.
