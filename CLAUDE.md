# CLAUDE.md

A RAG chatbot built with Pydantic AI and Chainlit that indexes CISA KEV and NIST NVD vulnerability data into PostgreSQL with pgvector embeddings, enabling natural language queries about security vulnerabilities via semantic search and direct SQL tools.

## Docs

- [Public access setup (OAuth)](docs/public-access-setup.md)
- [Data loading (ETL)](docs/data-loading.md)
- [NVD integration](docs/nvd-integration.md)
- [CWE integration](docs/cwe-integration.md)
- [EPSS integration](docs/epss-integration.md)
- [Pluggable model backends (Gemini, GPT, GLM)](plans/pluggable-model-backends.md)
- [Supabase migration](plans/migrate-to-supabase.md)
- [Pydantic AI v2 migration](plans/pydantic-ai-v2-migration.md)
- [Deployment: Azure](docs/deploy-azure-app-service.md), [GCP](docs/deploy-gcp-cloud-run.md), [EKS](docs/eks-runbook.md)
- [Azure blue/green cutover run log (rename)](docs/rename-cutover-runlog.md)
- [Container hardening pen test](docs/container-hardening.md)
- [NetworkPolicy pen test](docs/network-hardening.md), [egress](docs/egress-hardening.md)
- [Observability (Langfuse + Logfire)](docs/observability.md)
- [Supabase RBAC](docs/supabase-readonly-role.md)
- [MCP server](docs/mcp-server.md)
- [Competitive analysis](plans/competitive-analysis.md)
- [Future enhancements](plans/future-enhancements.md)

## Development Commands

```bash
# Start the chatbot
uv run chainlit run app.py

# Add a dependency
uv add <package-name>

# Sync dependencies
uv sync
```

## Requirements

- Python 3.12+
- uv package manager
