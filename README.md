# CISA KEV + NVD RAG Chatbot

A retrieval-augmented generation chatbot for vulnerability research, built with Pydantic AI and Chainlit. Indexes the CISA Known Exploited Vulnerabilities (KEV) catalog and NIST National Vulnerability Database (NVD) into PostgreSQL with pgvector, and answers questions using Claude with semantic search and direct SQL.

## Features

- CISA KEV + NVD datasets (~1,500 KEV entries, enriched with CVSS scores from NVD)
- PostgreSQL/pgvector for vector storage and cosine similarity search (HNSW index)
- OpenAI embeddings (text-embedding-3-small)
- Two agent tools: `retrieve` (semantic search) and `query` (direct SQL)
- Claude LLM via Pydantic AI agent
- Chainlit web interface with authentication
- Langfuse observability (optional, self-hosted via Compose)

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- PostgreSQL with pgvector extension — local container or Timescale Cloud

## Installation

1. Clone the repository and navigate to the project directory:

   ```bash
   cd chainlit-pydanticai-postgres
   ```

2. Install dependencies:

   ```bash
   uv sync
   ```

3. Create a `.env` file from the template:

   ```bash
   cp .env.example .env
   ```

4. Fill in your API keys and database connection in `.env`:

   ```env
   ANTHROPIC_API_KEY=your-anthropic-api-key
   OPENAI_API_KEY=your-openai-api-key

   # Option A — Timescale Cloud or any remote pgvector instance:
   DATABASE_URL=postgresql://user:password@hostname.tsdb.cloud.timescale.com:5432/dbname?sslmode=require

   # Option B — local container (defaults, matches docker-compose.yaml pgvector service):
   PG_HOST=localhost
   PG_PORT=5432
   PG_USER=postgresuser
   PG_PASSWORD=postgrespw
   PG_DATABASE=inventory
   ```

   `DATABASE_URL` takes precedence over the individual `PG_*` vars when set.

## Authentication

The app requires username/password login. To set it up:

1. Generate an auth secret:

   ```bash
   uv run chainlit create-secret
   ```

2. Add the following to your `.env`:

   ```env
   APP_USERNAME=admin
   APP_PASSWORD=your-password
   CHAINLIT_AUTH_SECRET=<paste-secret-from-step-1>
   ```

   `APP_USERNAME` defaults to `admin` if not set.

## Quickstart

Choose the database backend that fits your workflow:

### Option A: Timescale Cloud (or any remote pgvector)

No local containers needed. Set `DATABASE_URL` in `.env` and run directly:

```bash
# Load KEV + NVD data (one-time)
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py

# Start the chatbot
uv run chainlit run app.py
```

Open http://localhost:8000.

### Option B: Local pgvector container only

Spin up just the pgvector service, then run the app with `uv`:

```bash
# Start only the pgvector container
podman compose up -d pgvector

# Load KEV + NVD data (one-time)
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py

# Start the chatbot
uv run chainlit run app.py
```

Open http://localhost:8000.

### Option C: Full stack (Langfuse observability + pgvector + chatbot container)

Starts all services: pgvector, the full Langfuse stack (postgres, clickhouse, redis, minio), and the chatbot container itself:

```bash
podman compose up -d
```

- Chatbot: http://localhost:8080
- Langfuse: http://localhost:3000 (admin@local.dev / password)

See [docs/langfuse-setup.md](docs/langfuse-setup.md) for Langfuse configuration details.

> **Note:** The `chatbot` service in Compose builds the image locally and uses fixed DB credentials from the compose environment. Options A and B are better for active development since changes take effect immediately without rebuilding the image.

## Loading Data

The ETL scripts fetch data from public APIs and generate embeddings. Run them once after the database is ready, and re-run to pick up new CISA KEV entries.

```bash
# Fetch CISA KEV catalog and generate embeddings (~1,500 records)
uv run python scripts/load_kev.py

# Fetch NVD enrichment (CVSS scores, severity, affected products)
# Set NVD_API_KEY in .env for a higher rate limit (optional):
# https://nvd.nist.gov/developers/request-an-api-key
uv run python scripts/load_nvd.py
```

## Configuration

Optional settings in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL` | `anthropic:claude-haiku-4-5-20251001` | LLM for generating responses |
| `TOP_K` | `5` | Number of documents to retrieve via semantic search |
| `SYSTEM_PROMPT` | *(KEV/NVD-aware prompt)* | System prompt for the agent |
| `ACTION_BUTTONS` | `[]` | Quick-query buttons shown in the UI (JSON array of strings) |
| `NVD_API_KEY` | *(none)* | Optional — increases NVD API rate limit |

### LLM Model Options

Any [Pydantic AI supported model](https://ai.pydantic.dev/models/) can be used:

| Model | Description |
|-------|-------------|
| `anthropic:claude-haiku-4-5-20251001` | Fast, concise responses (recommended) |
| `anthropic:claude-sonnet-4-20250514` | More capable, slower |

## Docker

Build and run locally with Docker (or Podman):

```bash
docker build -t chainlit-pydanticai-rag .
docker run -p 8080:8080 --env-file .env chainlit-pydanticai-rag:latest
```

Then open http://localhost:8080.

## Deployment

| Guide | Description |
|-------|-------------|
| [docs/deploy-azure-app-service.md](docs/deploy-azure-app-service.md) | Deploy to Azure App Service as a Linux container, using ACR, Key Vault, Timescale Cloud, and Azure Pipelines |
| [docs/deploy-gcp-cloud-run.md](docs/deploy-gcp-cloud-run.md) | Deploy to Google Cloud Run |
| [docs/eks-runbook.md](docs/eks-runbook.md) | Deploy to AWS EKS using GitHub Actions CI/CD |

## Architecture

```
CISA KEV API ─┐
              ├─→ ETL scripts → OpenAI Embeddings → PostgreSQL/pgvector
NVD API ──────┘                                            ↓
                                              ┌─ retrieve (semantic search)
User → Chainlit → Pydantic AI Agent ──────────┤
                         ↓                    └─ query (direct SQL)
                       Claude
```
