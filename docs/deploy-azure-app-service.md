# Deploying to Azure App Service

This guide walks through deploying the CISA KEV + NVD RAG chatbot to Azure App Service as a Linux container, using Azure Container Registry for images, Azure Key Vault for secrets, and Timescale Cloud (hosted pgvector) as the database. CI/CD runs via Azure Pipelines with Workload Identity Federation — no static credentials.

Two requirements shape the infrastructure design:
- **WebSocket support** (Chainlit) → ARR sticky sessions (`clientAffinityEnabled: true`)
- **120s+ startup time** (pgvector schema init) → `WEBSITE_CONTAINER_START_TIME_LIMIT: 230`

---

## Architecture

```
GitHub (source) → Azure Pipelines → ACR (images)
                                        ↓
                              App Service (Linux container)
                                ↓              ↓
                           Key Vault    Timescale Cloud
                                ↑         (pgvector)
                     User-Assigned Managed Identity (RBAC)

Azure Policy  → governs resource group
Azure Bicep   → provisions all infrastructure (Resource Manager)
```

---

## Resource Names

Pattern: `{type}-chainlit-rag-{env}` (globally unique resources drop hyphens)

| Resource | Dev |
|---|---|
| Resource Group | `rg-chainlit-rag-dev` |
| Managed Identity | `id-chainlit-rag-dev` |
| Container Registry | `acrchainlitragdev` |
| App Service Plan | `asp-chainlit-rag-dev` |
| App Service | `app-chainlit-rag-dev` |
| Key Vault | `kv-chainlit-rag-dev` |

> Storage Account and Blob Container have been removed. RAG data lives in Timescale Cloud (pgvector).

---

## Prerequisites

- Azure CLI (`az`) authenticated to the target subscription
- Azure DevOps project created (e.g., `chainlit-rag`)
- Contributor access on the target resource group (or subscription for first deploy)
- `az bicep upgrade` run at least once (Bicep CLI 0.18+ required for `.bicepparam`)
- Timescale Cloud service provisioned with pgvector extension enabled

---

## Step 1: Create the Resource Group (one-time)

```bash
az group create \
  --name rg-chainlit-rag-dev \
  --location eastus \
  --tags environment=dev application=chainlit-rag
```

---

## Step 2: Azure DevOps Setup (one-time)

Two portals are used here: **Azure DevOps** (dev.azure.com) for pipelines/service connections/environments, and **Azure Portal** (portal.azure.com) for Azure resources and Entra ID.

### 2.0 Connect Azure DevOps to your Entra ID tenant (new organizations only)

In **Azure DevOps** → **Organization Settings** → **Microsoft Entra** → **Connect directory** → select your tenant → confirm.

### 2.1 Create service connections

In **Azure DevOps** → your project → **Project Settings** → **Pipelines** → **Service connections** → **New service connection**:

**GitHub** (`github-chainlit-rag`):
- Type: **GitHub**, auth: **Grant authorization**, OAuth: **AzurePipelines**
- Click **Authorize**, name it `github-chainlit-rag`, check **Grant access permission to all pipelines** → **Save**

**Azure Resource Manager** (`azure-chainlit-rag`):
- Type: **Azure Resource Manager**, identity: **App registration (automatic)**, credential: **Workload identity federation**
- Scope: **Subscription**, resource group: `rg-chainlit-rag-dev`
- Name it `azure-chainlit-rag`, check **Grant access permission to all pipelines** → **Save**

> If the resource group dropdown shows "Loading..." indefinitely, complete step 2.0 first.

### 2.2 Create the Pipeline

In **Azure DevOps** → **Pipelines** → **New pipeline** → **GitHub** → select `chainlit-pydanticai-rag` → **Existing Azure Pipelines YAML file** → branch `main`, path `/azure-pipelines.yml` → **Continue** → **Save** (do not run yet).

### 2.3 Add the pipeline service principal Object ID to the pipeline

Saving the ARM service connection creates an **Enterprise Application** in Entra ID. You need its Object ID — this is different from the App Registration's Object ID shown in the Azure DevOps service connection details.

In **Azure Portal** → **Microsoft Entra ID** → **Enterprise applications** → search for the auto-generated name matching your org and project (e.g. `jeffreyscotthoekman0908-chainlit-pg-<guid>`) → **Overview** → copy the **Object ID**.

Set it as a pipeline UI variable (no YAML edit needed):

In **Azure DevOps** → **Pipelines** → select the pipeline → **Edit** → **Variables** (top-right) → **New variable** → name: `PIPELINE_SP_OBJECT_ID`, value: `<object-id>`, uncheck **Keep this value secret** → **Save**.

### 2.4 Create the Deployment Environment

In **Azure DevOps** → **Pipelines** → **Environments** → **New environment** → name: `chainlit-rag-dev`, resource: **None** → **Create**.

### 2.5 Grant the pipeline service principal Owner on the resource group

The Bicep `rbac` module creates role assignments, which requires `Owner` (not `Contributor`) for the first run. After the first successful deploy, Bicep downgrades the pipeline SP to the minimal roles it needs (ACR Push, Website Contributor).

```bash
az role assignment create \
  --role "Owner" \
  --assignee-object-id <PIPELINE_SP_OBJECT_ID> \
  --assignee-principal-type ServicePrincipal \
  --scope /subscriptions/<subscription-id>/resourceGroups/rg-chainlit-rag-dev
```

---

## Step 3: Deploy Infrastructure (Bicep)

The pipeline does this automatically on every push to `main`. To deploy manually:

### Set env
```
PIPELINE_SP_OBJECT_ID=<pipeline-sp-object-id>
```

### Dry run — shows what will change
```bash
az deployment group what-if \
  --resource-group rg-chainlit-rag-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=$PIPELINE_SP_OBJECT_ID
```

### Apply
```bash
az deployment group create \
  --resource-group rg-chainlit-rag-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=$PIPELINE_SP_OBJECT_ID \
  --mode Incremental
```

**Module deployment order** (enforced by `dependsOn` in `main.bicep`):

1. `identity` — User-Assigned Managed Identity (outputs feed everything else)
2. `acr` — Container Registry (admin disabled; Managed Identity pull only)
3. `keyVault` — Key Vault (RBAC authorization model, soft delete 7 days)
4. `appService` — App Service Plan (B2) + Web App with all app settings and KV references
5. `rbac` — All role assignments (must complete before App Service resolves KV refs)
6. `policy` — Azure Policy assignments (HTTPS-only, require `environment`/`application` tags)

---

## Step 4: Provision Key Vault Secrets (one-time)

Secrets are not created by Bicep. Run these after the first successful infrastructure deploy.

### 4.0 Grant yourself write access to Key Vault (one-time)

The Key Vault uses the RBAC authorization model — no one has access by default, including the person who deployed it. The Bicep `rbac` module only grants the App Service's managed identity read access. You must explicitly grant yourself write access before you can set secrets.

```bash
USER_OID=$(az ad signed-in-user show --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee-object-id $USER_OID \
  --assignee-principal-type User \
  --scope $(az keyvault show \
      --name kv-chainlit-rag-dev \
      --resource-group rg-chainlit-rag-dev \
      --query id -o tsv)
```

### 4.1 Set the secrets

Use the bash `for` loop with `read` shell built-in to securely enter the env vars:
```bash
for var in ANTHROPIC_API_KEY OPENAI_API_KEY APP_PASSWORD CHAINLIT_AUTH_SECRET DATABASE_URL; do
  echo "$var" && read -rs $var
done
```

> For `DATABASE_URL`, enter the full Timescale Cloud connection string:
> `postgresql://user:password@hostname.tsdb.cloud.timescale.com:5432/dbname?sslmode=require`

Create the Azure Key Vault secrets:
```bash
az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name anthropic-api-key \
  --value "$ANTHROPIC_API_KEY"

az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name openai-api-key \
  --value "$OPENAI_API_KEY"

az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name app-password \
  --value "$APP_PASSWORD"

az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name chainlit-auth-secret \
  --value "$CHAINLIT_AUTH_SECRET"

az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name database-url \
  --value "$DATABASE_URL"
```

Restart the App Service to re-resolve the Key Vault references:

```bash
az webapp restart \
  --name app-chainlit-rag-dev \
  --resource-group rg-chainlit-rag-dev
```

---

## Step 5: Load KEV and NVD Data (one-time)

Data is loaded directly into Timescale Cloud from your local machine. Run these steps once after the database is reachable. Set `DATABASE_URL` in your `.env` pointing to Timescale Cloud before running.

### 5.0 Verify pgvector is enabled on Timescale Cloud

Connect to your Timescale Cloud instance and confirm:
```bash
psql "$DATABASE_URL" -c "SELECT extname FROM pg_extension WHERE extname = 'vector';"
```

If not present, enable it:
```bash
psql "$DATABASE_URL" -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

### 5.1 Create the schema

Schema creation runs automatically on app startup. To run manually:
```bash
uv run python -c "from rag.database import create_schema; import asyncio; asyncio.run(create_schema())"
```

### 5.2 Load CISA KEV data (~1,500 records)

Fetches the CISA KEV catalog and generates OpenAI embeddings:
```bash
uv run python scripts/load_kev.py
```

### 5.3 Load NVD enrichment data

Fetches CVSS scores, severity, and affected products from NIST NVD. Rate-limited — set `NVD_API_KEY` in `.env` to increase the rate limit ([request a key](https://nvd.nist.gov/developers/request-an-api-key)):
```bash
uv run python scripts/load_nvd.py
```

### 5.4 Verify record counts

```bash
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM kev_vulnerabilities;"
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM nvd_vulnerabilities;"
```

---

## Step 6: Trigger the Pipeline

Push to `main` to trigger all three stages automatically:

```
Build       → docker build + push to ACR (tags: <git-sha-short>, latest)
DeployInfra → Bicep what-if + incremental deploy
DeployApp   → az webapp config container set + restart + /healthz poll (240s)
```

To trigger manually without a code change:

```bash
az pipelines run --name chainlit-pydanticai-rag
```

---

## Verification

```bash
# 1. All resources provisioned
az resource list --resource-group rg-chainlit-rag-dev -o table

# 2. KV references resolved (look for "Resolved" in the value column, not "Failed")
az webapp config appsettings list \
  --name app-chainlit-rag-dev \
  --resource-group rg-chainlit-rag-dev \
  --query "[?contains(value, '@Microsoft.KeyVault')]" -o table

# 3. Image present in ACR
az acr repository show-tags \
  --name acrchainlitragdev \
  --repository chainlit-pydanticai-rag \
  -o table

# 4. Health check responds 200
curl -v https://app-chainlit-rag-dev.azurewebsites.net/healthz

# 5. App logs confirm successful DB connection
az webapp log tail \
  --name app-chainlit-rag-dev \
  --resource-group rg-chainlit-rag-dev
# Expected: successful startup with no DB connection errors
# Test query: "What vulnerabilities affect Apache?"

# 6. WebSocket: open app in browser → DevTools → Network → WS tab → active connection

# 7. Sticky sessions: check browser cookies for ARRAffinity cookie after login
```

---

## Redeploying

**New code:** push to `main` — pipeline handles everything.

**Updated secret value:**

```bash
az keyvault secret set \
  --vault-name kv-chainlit-rag-dev \
  --name <secret-name> \
  --value "<new-value>"

az webapp restart \
  --name app-chainlit-rag-dev \
  --resource-group rg-chainlit-rag-dev
```

**Reload KEV/NVD data** (e.g., after CISA publishes new entries):

```bash
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py
# No app restart needed — data is queried live from Timescale Cloud
```

---

## Troubleshooting

**KV reference not resolving (App Service shows "Failed")**
- Confirm the managed identity has `Key Vault Secrets User` on the vault: `az role assignment list --scope <kv-resource-id>`
- Confirm `AZURE_CLIENT_ID` app setting matches the MI's **client ID** (not object/principal ID)
- Re-run the Bicep `rbac` module, then restart the app

**Container pull failing (App Service can't pull from ACR)**
- Both `acrUseManagedIdentityCreds: true` AND `acrUserManagedIdentityID` must be set together — missing `acrUserManagedIdentityID` causes App Service to try the system-assigned MI (not enabled)
- Confirm the MI has `AcrPull` on the registry: `az role assignment list --scope <acr-resource-id>`

**`DefaultAzureCredential` picks wrong identity**
- `AZURE_CLIENT_ID` must be set to the user-assigned MI's **client ID** (not object/principal ID)
- Without it, the SDK falls through to system-assigned MI and fails

**Container startup timeout**
- `WEBSITE_CONTAINER_START_TIME_LIMIT: 230` allows 230s; if startup still times out, check logs for DB connection errors
- The B2 plan has `alwaysOn: true`, so cold starts only happen after a restart or deploy

**Database connection fails on startup**
- Confirm `DATABASE_URL` KV secret is set and the reference resolved (`az webapp config appsettings list`)
- Confirm the Timescale Cloud connection string includes `?sslmode=require`
- Timescale Cloud requires SSL — connections without it will be refused
- Check Timescale Cloud connection limits and allowed IP ranges if the app is blocked

**Bicep deploy fails with `.bicepparam` syntax error**
- Run `az bicep upgrade` to ensure Bicep CLI 0.18+
- The pipeline's DeployInfra stage runs `az bicep upgrade` automatically before deploying

**Policy assignment fails with authorization error**
- `Microsoft.Authorization/policyAssignments` requires `Resource Policy Contributor` on the resource group
- Run the `policy` module manually the first time with a higher-privileged identity, or grant the pipeline SP that role temporarily
