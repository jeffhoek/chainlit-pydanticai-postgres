# Documentation

## Guides

| Document | Description |
|---|---|
| [deploy-azure-app-service.md](deploy-azure-app-service.md) | Deploy to Azure App Service as a Linux container, using ACR, Key Vault, Blob Storage, and Azure Pipelines with Workload Identity Federation |
| [deploy-gcp-cloud-run.md](deploy-gcp-cloud-run.md) | Deploy to Google Cloud Run |
| [eks-runbook.md](eks-runbook.md) | Deploy to AWS EKS using GitHub Actions CI/CD |
| [langfuse-setup.md](langfuse-setup.md) | Set up self-hosted Langfuse observability alongside the chatbot via Podman Compose |
| [action-buttons.md](action-buttons.md) | Configure Chainlit action buttons on the welcome message for quick-access suggested questions |

---

## Cloud Service Mapping

Equivalent services across AWS, GCP, and Azure for each layer of the stack:

| Service Type | AWS | GCP | Azure | Notes |
|---|---|---|---|---|
| Container Registry | ECR | Artifact Registry | Container Registry (ACR) | ACR admin disabled; image pull via Managed Identity |
| App Runtime | EKS | Cloud Run | App Service (Linux container) | All three require sticky sessions for WebSocket support |
| Secrets Management | Secrets Manager / SSM Parameter Store | Secret Manager | Key Vault | Azure uses RBAC model with Key Vault references in app settings |
| Object Storage | S3 | Cloud Storage | Blob Storage | App loads knowledge base from storage on startup |
| Workload Identity | EKS Pod Identity | Workload Identity (Service Account) | User-Assigned Managed Identity | Binds a cloud IAM role to the app runtime; no static credentials |
| CI/CD | GitHub Actions + OIDC | Cloud Build + Workload Identity | Azure Pipelines + Workload Identity Federation | OIDC/WIF eliminates stored access keys in all three |
| IaC | CloudFormation/Terraform | Cloud Deployment Manager | Bicep / ARM | Azure uses `.bicepparam` parameter files |
| Policy Enforcement | AWS Organizations / Config | Organization Policy | Azure Policy | Enforces guardrails (HTTPS-only, required tags) |
| Access Control | AWS IAM | Cloud IAM | Azure RBAC | Minimal-privilege role assignments throughout |
