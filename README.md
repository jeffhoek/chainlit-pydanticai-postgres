# Chainlit Pydantic AI RAG Chatbot

A retrieval-augmented generation chatbot built with Pydantic AI and Chainlit. Stores documents in PostgreSQL with pgvector, generates embeddings, and answers questions using Claude.

## Features

- PostgreSQL with pgvector for vector storage and cosine similarity search
- HNSW indexing for fast approximate nearest-neighbor retrieval
- OpenAI embeddings (text-embedding-3-small)
- Claude LLM via Pydantic AI agent
- Chainlit web interface

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- PostgreSQL with pgvector extension (or use the included Compose setup)

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

4. Fill in your credentials in `.env`:

   ```
   ANTHROPIC_API_KEY=your-anthropic-api-key
   OPENAI_API_KEY=your-openai-api-key
   PG_HOST=localhost
   PG_PORT=5432
   PG_USER=postgresuser
   PG_PASSWORD=postgrespw
   PG_DATABASE=inventory
   ```

## Authentication

The app requires username/password login. To set it up:

1. Generate an auth secret:

   ```bash
   uv run chainlit create-secret
   ```

2. Add the following to your `.env`:

   ```
   APP_USERNAME=admin
   APP_PASSWORD=your-password
   CHAINLIT_AUTH_SECRET=<paste-secret-from-step-1>
   ```

   `APP_USERNAME` defaults to `admin` if not set.

## Quickstart

1. Start the database and supporting services:

   ```bash
   podman compose up -d
   ```

2. Start the chatbot:

   ```bash
   uv run chainlit run app.py
   ```

3. Open your browser to http://localhost:8000

## Configuration

Optional settings can be adjusted in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL` | anthropic:claude-haiku-4-5-20251001 | LLM for generating responses |
| `TOP_K` | 5 | Number of documents to retrieve |
| `SYSTEM_PROMPT` | *(see .env.example)* | System prompt for the RAG agent |

### LLM Model Options

Any [Pydantic AI supported model](https://ai.pydantic.dev/models/) can be used:

| Model | Description |
|-------|-------------|
| `anthropic:claude-haiku-4-5-20251001` | Fast, concise responses (recommended) |
| `anthropic:claude-sonnet-4-20250514` | More capable, slower |

## Docker

Build and run locally with Docker (or Podman):

```bash
docker build -t chainlit-pydanticai .
```
```
docker run -p 8080:8080 --env-file .env chainlit-pydanticai:latest
```

Then open http://localhost:8080.

## Deployment

| Guide | Description |
|-------|-------------|
| [docs/deploy-gcp-cloud-run.md](docs/deploy-gcp-cloud-run.md) | Deploy to Google Cloud Run |
| [docs/deploy-azure-app-service.md](docs/deploy-azure-app-service.md) | Deploy to Azure App Service as a Linux container, using ACR, Key Vault, and Azure Pipelines |
| [docs/eks-runbook.md](docs/eks-runbook.md) | Deploy to AWS EKS using GitHub Actions CI/CD |

Helper scripts in `scripts/`:

| Script | Purpose |
|--------|---------|
| `create-gcp-secrets.sh` | Interactively create GCP Secret Manager secrets and grant access |
| `env2yaml.sh` | Convert a `.env` file to YAML format for Cloud Run |

## Observability

See [docs/langfuse-setup.md](docs/langfuse-setup.md) for self-hosted Langfuse tracing via Podman Compose.

## Architecture

```
PostgreSQL/pgvector ← Document Ingestion → OpenAI Embeddings
         ↓
User Query → Chainlit → Pydantic AI Agent → Retrieve Tool → Claude Response
```
