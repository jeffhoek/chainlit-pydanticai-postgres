# Vulncopilot

> CISA KEV + NVD RAG chatbot for vulnerability research

**🌐 [vulncopilot.org](https://vulncopilot.org)**

[![Tests](https://github.com/jeffhoek/vulncopilot/actions/workflows/test.yml/badge.svg)](https://github.com/jeffhoek/vulncopilot/actions/workflows/test.yml) [![Claude Code](https://github.com/jeffhoek/vulncopilot/actions/workflows/claude.yml/badge.svg)](https://github.com/jeffhoek/vulncopilot/actions/workflows/claude.yml) [![Deploy to EKS](https://github.com/jeffhoek/vulncopilot/actions/workflows/deploy.yml/badge.svg)](https://github.com/jeffhoek/vulncopilot/actions/workflows/deploy.yml)

A retrieval-augmented generation chatbot for vulnerability research, built with Pydantic AI and Chainlit. Indexes the CISA Known Exploited Vulnerabilities (KEV) catalog and NIST National Vulnerability Database (NVD) into PostgreSQL with pgvector, and answers questions using Claude with semantic search and direct SQL.

![Architecture diagram](docs/chatbot-architecture.drawio.png)

## Use Cases

- **Vulnerability triage** — prioritize patching by querying CVSS scores, ransomware campaign usage, and CISA remediation due dates
- **Compliance reporting** — list KEV vulnerabilities by vendor or product for BOD 22-01 and patch management audits
- **Incident response** — look up CVE details and cross-reference KEV and NVD data without navigating government websites
- **Vendor risk assessment** — identify which vendors have the most known exploited vulnerabilities
- **DevSecOps** — check project dependencies for known exploited vulnerabilities before shipping

## Why this project?

NVD is a record browser with filters. This chatbot is an analyst. A few things it can do that the NVD site cannot:

| Capability | NVD site | This chatbot |
|---|---|---|
| Cross-reference KEV + NVD in one query | No — separate sites | Yes — JOINed in one DB |
| Ransomware campaign filtering | No | Yes (`known_ransomware_campaign_use`) |
| CISA remediation deadline queries | No | Yes (`due_date`, BOD 22-01) |
| Semantic / conceptual search | No — keyword only | Yes — pgvector embeddings |
| Aggregations and trend analytics | No | Yes — arbitrary SQL |
| Temporal calculations (e.g., days from publish → KEV add) | No | Yes |
| Conversational follow-up across multiple questions | No — resets each search | Yes — session history |
| Prioritize by multiple signals at once (CVSS + KEV + ransomware + overdue) | No | Yes |

**Example questions NVD can't answer:**
- *"Which critical Apache vulnerabilities are on the KEV list and linked to ransomware campaigns?"*
- *"How many days on average elapsed between NVD publication and CISA KEV addition in 2024?"*
- *"Rank overdue KEV vulnerabilities by CVSS score for the vendors in my environment."*
- *"Find vulnerabilities conceptually similar to Log4Shell in terms of attack pattern."*

For a broader comparison against commercial platforms, academic projects, and other open-source tools, see [plans/competitive-analysis.md](plans/competitive-analysis.md).

## Beyond the UI — bring the data to your own agent

The chatbot is one way in. The built-in **MCP server** (`/mcp`) exposes the same `retrieve` and `query` tools to any external agent — Claude Desktop, Claude Code, or a custom Pydantic AI agent — so the KEV/NVD data becomes a capability in the analyst's own environment rather than a place they visit:

- **Cross-source correlation** — join KEV/NVD against a local SBOM, asset inventory, or a Jira/GitHub connector in one conversation
- **Deliverable generation** — turn a query result into a ticket, an `.xlsx` risk register, or a CISO briefing deck
- **Agentic workflows** — multi-step triage loops instead of one-shot chat turns
- **Headless automation** — nightly jobs that diff new KEV additions and post to Slack, no browser involved

See [docs/mcp-server.md](docs/mcp-server.md) for setup and worked examples.

## Features

- CISA KEV + NVD datasets (~1,500 KEV entries, enriched with CVSS scores from NVD) + MITRE CWE weakness taxonomy — see [docs/cwe-integration.md](docs/cwe-integration.md)
- FIRST.org EPSS exploitation-likelihood scores (~353k CVEs, refreshed daily) — the leading indicator to KEV's lagging one — see [docs/epss-integration.md](docs/epss-integration.md)
- PostgreSQL/pgvector for vector storage and cosine similarity search (HNSW index)
- OpenAI embeddings (text-embedding-3-small)
- Two agent tools: `retrieve` (semantic search) and `query` (direct SQL)
- Claude LLM via Pydantic AI agent
- Chainlit web interface with authentication
- MCP server at `/mcp` — exposes `retrieve` and `query` to external agents — see [docs/mcp-server.md](docs/mcp-server.md)
- Langfuse observability (optional, self-hosted via Compose) — see [docs/observability.md](docs/observability.md)
- Logfire observability (optional, cloud-hosted tracing) — see [docs/observability.md](docs/observability.md)

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- PostgreSQL with pgvector extension — local container or Supabase

## Installation

1. Clone the repository and navigate to the project directory:

   ```bash
   cd vulncopilot
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

   # Option A — local container (defaults, matches compose pgvector service):
   PG_HOST=localhost
   PG_PORT=5432
   PG_USER=postgresuser
   PG_PASSWORD=postgrespw
   PG_DATABASE=inventory

   # Option B — Supabase or any remote pgvector instance:
   DATABASE_URL=postgresql://user:password@db.<project-ref>.supabase.co:5432/postgres?sslmode=require
   ```

   `DATABASE_URL` takes precedence over the individual `PG_*` vars when set.

## Development

Install pre-commit hooks to enable linting (ruff), formatting, and secrets detection (gitleaks) on each commit:

```bash
uv run pre-commit install
```

To run all checks manually:

```bash
uv run pre-commit run --all-files
```

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

### Option A: Local pgvector container (Podman)

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

### Option B: Supabase (or any remote pgvector)

No local containers needed. Set `DATABASE_URL` in `.env` to your Supabase connection string and run directly:

```bash
# Load KEV + NVD data (one-time)
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py

# Start the chatbot
uv run chainlit run app.py
```

Open http://localhost:8000. See [plans/migrate-to-supabase.md](plans/migrate-to-supabase.md) for Supabase setup details.

### Option C: Full stack (Langfuse observability + pgvector + chatbot container)

Starts all services: pgvector, the full Langfuse stack (postgres, clickhouse, redis, minio), and the chatbot container itself:

```bash
podman compose up -d
```

- Chatbot: http://localhost:8080
- Langfuse: http://localhost:3000 (admin@local.dev / password)

See [docs/observability.md](docs/observability.md) for Langfuse configuration details, including the managed **Logfire** integration as an alternative to self-hosted Langfuse.

> **Note:** The `chatbot` service in Compose builds the image locally and uses fixed DB credentials from the compose environment. Options A and B are better for active development since changes take effect immediately without rebuilding the image.

## Loading Data

The ETL scripts fetch data from public APIs and generate embeddings. Run them once after the database is ready, and re-run to pick up new entries.

```bash
# Fetch CISA KEV catalog and generate embeddings (~1,500 records)
uv run python scripts/load_kev.py

# Fetch NVD enrichment for KEV CVEs (CVSS scores, severity, affected products)
uv run python scripts/load_nvd.py

# Or load the full NVD database (~280k CVEs) — optional, requires more storage and can take several hours
uv run python scripts/load_nvd_full.py

# Load MITRE CWE weakness definitions — enables CWE name resolution in queries
uv run python scripts/load_cwe.py

# Load FIRST.org EPSS daily scores (~353k) — exploitation likelihood for prioritization
uv run python scripts/load_epss.py
```

Set `NVD_API_KEY` in `.env` for a higher NVD API rate limit (optional). See [docs/data-loading.md](docs/data-loading.md) for the full guide, including incremental sync, checkpoint/resume, and embedding backfill options. For storage sizing and PostgreSQL hosting options when loading the full NVD dataset, see [plans/postgres-hosting-options.md](plans/postgres-hosting-options.md). For the database schema and example queries, see [docs/nvd-integration.md](docs/nvd-integration.md).

## Configuration

Optional settings in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL` | `anthropic:claude-sonnet-5` | LLM for generating responses |
| `TOP_K` | `5` | Number of documents to retrieve via semantic search |
| `SYSTEM_PROMPT` | *(KEV/NVD-aware prompt)* | System prompt for the agent |
| `ACTION_BUTTONS` | `[]` | Quick-query buttons shown in the UI (JSON array of strings) — see [docs/action-buttons.md](docs/action-buttons.md) |
| `NVD_API_KEY` | *(none)* | Optional — increases NVD API rate limit |

### LLM Model Options

Any [Pydantic AI supported model](https://ai.pydantic.dev/models/) can be used:

| Model | Description |
|-------|-------------|
| `anthropic:claude-haiku-4-5` | Fast, concise responses |
| `anthropic:claude-sonnet-5` | Near-Opus quality on coding/reasoning at Sonnet cost (recommended default) |
| `anthropic:claude-opus-4-8` | Most capable, highest latency and cost |

## Docker

Build and run locally with Docker (or Podman):

```bash
docker build -t vulncopilot .
docker run -p 8080:8080 --env-file .env vulncopilot:latest
```

Then open http://localhost:8080.

## Deployment

| Guide | Description |
|-------|-------------|
| [docs/deploy-azure-app-service.md](docs/deploy-azure-app-service.md) | Deploy to Azure App Service as a Linux container, using ACR, Key Vault, Timescale Cloud, and Azure Pipelines — includes MCP server setup |
| [docs/deploy-gcp-cloud-run.md](docs/deploy-gcp-cloud-run.md) | Deploy to Google Cloud Run |
| [docs/eks-runbook.md](docs/eks-runbook.md) | Deploy to AWS EKS using GitHub Actions CI/CD |

## Further Reading

See [docs/](docs/README.md) for the full documentation index, including deployment guides (Azure, GCP, EKS), observability setup, and [future enhancements](plans/future-enhancements.md).
