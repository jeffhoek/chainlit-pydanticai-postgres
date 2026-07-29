# Documentation

## Guides

| Document | Description |
|---|---|
| [data-loading.md](data-loading.md) | ETL guide for populating the database with CISA KEV and NVD data (KEV-scoped and full NVD) |
| [nvd-integration.md](nvd-integration.md) | NVD & CISA KEV dataset integration, schema, and cross-reference query examples |
| [cwe-integration.md](cwe-integration.md) | MITRE CWE weakness taxonomy integration — `cwe_definitions` lookup table, ETL script, and example JOIN queries |
| [epss-integration.md](epss-integration.md) | FIRST.org EPSS exploitation-likelihood scores — `epss_scores` table, daily feed ETL, and prioritization query examples |
| [mcp-server.md](mcp-server.md) | MCP server setup — exposes `retrieve` and `query` tools at `/mcp` for external agents |
| [action-buttons.md](action-buttons.md) | Configure Chainlit action buttons on the welcome message for quick-access suggested questions |
| [observability.md](observability.md) | Observability integrations — self-hosted Langfuse (Compose) and cloud-hosted Logfire |
| [supabase-readonly-role.md](supabase-readonly-role.md) | Role-based access control in Supabase — `app_readonly` (SELECT only) for the live app, `app_etl` for ETL scripts |
| [deploy-azure-app-service.md](deploy-azure-app-service.md) | Deploy to Azure App Service as a Linux container, using ACR, Key Vault, and Azure Pipelines with Workload Identity Federation — includes MCP server setup |
| [deploy-gcp-cloud-run.md](deploy-gcp-cloud-run.md) | Deploy to Google Cloud Run |
| [eks-runbook.md](eks-runbook.md) | Deploy to AWS EKS using GitHub Actions CI/CD |
