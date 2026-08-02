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

Pattern: `{type}-vulncopilot-{env}` (globally unique resources drop hyphens)

| Resource | Dev |
|---|---|
| Resource Group | `rg-vulncopilot-dev` |
| Managed Identity | `id-vulncopilot-dev` |
| Container Registry | `acrvulncopilotdev` |
| App Service Plan | `asp-vulncopilot-dev` |
| App Service | `app-vulncopilot-dev` |
| Key Vault | `kv-vulncopilot-dev` |

> Storage Account and Blob Container have been removed. RAG data lives in Timescale Cloud (pgvector).

---

## Prerequisites

- Azure CLI (`az`) authenticated to the target subscription
- Azure DevOps project created (e.g., `vulncopilot`)
- Contributor access on the target resource group (or subscription for first deploy)
- `az bicep upgrade` run at least once (Bicep CLI 0.18+ required for `.bicepparam`)
- Timescale Cloud service provisioned with pgvector extension enabled

---

## Step 1: Create the Resource Group (one-time)

```bash
az group create \
  --name rg-vulncopilot-dev \
  --location eastus \
  --tags environment=dev application=vulncopilot
```

### 1.1 Register resource providers (one-time, subscription-scoped)

The infrastructure uses three resource provider namespaces that may not be
registered on a fresh subscription. Bicep can't register them for you — an
unregistered namespace fails the deploy with `MissingSubscriptionRegistration`.

| Namespace | Needed for |
|---|---|
| `Microsoft.App` | Container Apps Environment + scheduled ETL job |
| `Microsoft.OperationalInsights` | Log Analytics workspace (backs the Container Apps env) |
| `Microsoft.Communication` | Azure Communication Services + Email (ETL results email) |

Register them once (idempotent; `--wait` blocks until `Registered`, ~1–5 min each):

```bash
az account set --subscription <subscription-id>
for ns in Microsoft.App Microsoft.OperationalInsights Microsoft.Communication; do
  az provider register --namespace "$ns" --wait
done

# Verify
for ns in Microsoft.App Microsoft.OperationalInsights Microsoft.Communication; do
  echo "$ns: $(az provider show -n $ns --query registrationState -o tsv)"
done
```

> Provider registration requires `*/register/action` at **subscription** scope
> (Owner/Contributor have it). The pipeline's resource-group-scoped service principal
> does not, so do this once with a subscription-privileged login. The pipeline's
> "Register resource providers" step only *attempts* registration for namespaces that
> aren't already `Registered`, so it won't fail on permissions once this is done.

---

## Step 2: Azure DevOps Setup (one-time)

Two portals are used here: **Azure DevOps** (dev.azure.com) for pipelines/service connections/environments, and **Azure Portal** (portal.azure.com) for Azure resources and Entra ID.

### 2.0 Connect Azure DevOps to your Entra ID tenant (new organizations only)

In **Azure DevOps** → **Organization Settings** → **Microsoft Entra** → **Connect directory** → select your tenant → confirm.

### 2.1 Create service connections

In **Azure DevOps** → your project → **Project Settings** → **Pipelines** → **Service connections** → **New service connection**:

**GitHub** (`github-vulncopilot`):
- Type: **GitHub**, auth: **Grant authorization**, OAuth: **AzurePipelines**
- Click **Authorize**, name it `github-vulncopilot`, check **Grant access permission to all pipelines** → **Save**

**Azure Resource Manager** (`azure-vulncopilot`):
- Type: **Azure Resource Manager**, identity: **App registration (automatic)**, credential: **Workload identity federation**
- Scope: **Subscription**, resource group: `rg-vulncopilot-dev`
- Name it `azure-vulncopilot`, check **Grant access permission to all pipelines** → **Save**

> If the resource group dropdown shows "Loading..." indefinitely, complete step 2.0 first.

### 2.2 Create the Pipeline

In **Azure DevOps** → **Pipelines** → **New pipeline** → **GitHub** → select `vulncopilot` → **Existing Azure Pipelines YAML file** → branch `main`, path `/azure-pipelines.yml` → **Continue** → **Save** (do not run yet).

### 2.3 Add the pipeline service principal Object ID to the pipeline

Saving the ARM service connection creates an **Enterprise Application** in Entra ID. You need its Object ID — this is different from the App Registration's Object ID shown in the Azure DevOps service connection details.

In **Azure Portal** → **Microsoft Entra ID** → **Enterprise applications** → search for the auto-generated name matching your org and project (e.g. `jeffreyscotthoekman0908-chainlit-pg-<guid>`) → **Overview** → copy the **Object ID**.

Set it as a pipeline UI variable (no YAML edit needed):

In **Azure DevOps** → **Pipelines** → select the pipeline → **Edit** → **Variables** (top-right) → **New variable** → name: `PIPELINE_SP_OBJECT_ID`, value: `<object-id>`, uncheck **Keep this value secret** → **Save**.

### 2.3.1 Personal / environment-specific deploy variables

The bicep keeps personal and environment-specific values **out of git** — they are
injected at deploy time from pipeline variables (the same mechanism as
`PIPELINE_SP_OBJECT_ID` above), not hardcoded in `parameters.dev.bicepparam`. Add
these the same way (Pipelines → Edit → Variables → New variable):

| Variable | Example value | Used for |
|---|---|---|
| `ETL_EMAIL_TO` | `you@example.com` | Recipient(s) of the ETL results email (comma-separated). Empty = no email. |
| `ADMIN_USER_IDENTIFIERS` | `["github:12345678"]` | GitHub identifiers granted the elevated rate-limit cap. **Must be valid JSON** (`[]` for none). |

> These are optional and supplied **only** as UI variables — they are deliberately
> *not* declared in `azure-pipelines.yml`'s `variables:` block. **A variable defined
> at the YAML root overrides a UI variable of the same name** (a notorious Azure
> DevOps gotcha), so a YAML default would permanently shadow your UI value — e.g.
> `ETL_EMAIL_TO` would always deploy empty and the ETL email would never send, no
> matter what you set in the UI. The safe default for the *unset* case is instead
> applied in the deploy step's inline script, which coerces an undefined variable's
> literal `$(NAME)` expansion to `''` / `[]`. For `ADMIN_USER_IDENTIFIERS`, set valid
> JSON (`[]` for none) — the deploy reads the value from the variable's **environment
> variable** (quoted), not a `$(...)` macro, because a macro is substituted as literal
> text and bash strips the JSON's own double-quotes. The app also treats a blank value
> as `[]` rather than crashing, so an empty variable is tolerated — but a non-empty
> *invalid* value (e.g. `[github:1]` with the quotes lost) still fails fast at startup.

> ⚠️ **These variables only take effect on an infra deploy.** They are baked into
> the resources (the Container Apps Job's env, the app's settings) by the
> **DeployInfra** stage's bicep — they are *not* read at runtime. Adding or changing
> a variable in the ADO UI does **nothing** to already-deployed resources until
> DeployInfra runs again and re-applies the bicep. So if you set `ETL_EMAIL_TO`
> after the job was last deployed, the live job keeps its old (empty) value and the
> ETL run logs `Email not configured … skipping` even though the variable is set.
> Confirm what the **live job** actually has — this is ground truth, not the pipeline:
>
> ```bash
> az containerapp job show -n job-vulncopilot-etl-dev -g rg-vulncopilot-dev \
>   --query "properties.template.containers[0].env[?name=='ETL_EMAIL_TO']" -o json
> ```
>
> **Watch out for the path filters:** `azure-pipelines.yml`'s trigger excludes
> `docs/**`, `*.md`, `k8s/**`, and `.github/**`, so a docs- or EKS-only commit will
> **not** fire the pipeline and your new variable will never reach the job. After
> changing one of these variables, force a deploy: **Run pipeline** manually on
> `main` (path filters apply only to automatic CI triggers, not manual runs), or
> push a change that touches a non-excluded path.

### 2.4 Create the Deployment Environment

In **Azure DevOps** → **Pipelines** → **Environments** → **New environment** → name: `vulncopilot-dev`, resource: **None** → **Create**.

### 2.5 Grant the pipeline service principal Owner on the resource group

The Bicep `rbac` module creates role assignments, which requires `Owner` (not `Contributor`) for the first run. After the first successful deploy, Bicep downgrades the pipeline SP to the minimal roles it needs (ACR Push, Website Contributor).

```bash
az role assignment create \
  --role "Owner" \
  --assignee-object-id <PIPELINE_SP_OBJECT_ID> \
  --assignee-principal-type ServicePrincipal \
  --scope /subscriptions/<subscription-id>/resourceGroups/rg-vulncopilot-dev
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
  --resource-group rg-vulncopilot-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=$PIPELINE_SP_OBJECT_ID
```

### Apply
```bash
az deployment group create \
  --resource-group rg-vulncopilot-dev \
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
7. `email` — Azure Communication Services + Email service (Azure-managed sender domain) for the results email
8. `etlJob` — Container Apps Environment + scheduled ETL job (depends on `rbac` for ACR pull / KV read)

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
      --name kv-vulncopilot-dev \
      --resource-group rg-vulncopilot-dev \
      --query id -o tsv)
```

### 4.1 Set the secrets

> **Create the GitHub OAuth App first.** The app authenticates users with GitHub
> OAuth (see [docs/public-access-setup.md](public-access-setup.md)). Register an
> OAuth App at github.com/settings/developers with the **Authorization callback
> URL** set to your App Service URL plus Chainlit's fixed callback path:
> `https://app-vulncopilot-dev.azurewebsites.net/auth/oauth/github/callback`.
> Use its Client ID / Client Secret for `OAUTH_GITHUB_CLIENT_ID` /
> `OAUTH_GITHUB_CLIENT_SECRET` below. Authorization is locked to `ALLOWED_LOGINS`
> (default `["jeffhoek"]`, set in `parameters.dev.bicepparam`); the App Service is
> already HTTPS-only (`httpsOnly: true`), which OAuth requires.
>
> **Proxy gotcha — `CHAINLIT_URL` is required.** App Service terminates TLS at the
> front end and forwards plain HTTP to the container, so Chainlit otherwise builds
> the OAuth `redirect_uri` as `http://…` and GitHub rejects it with *"The
> redirect_uri is not associated with this application."* The bicep sets
> `CHAINLIT_URL=https://<appServiceName>.azurewebsites.net` to fix this. If you see
> that error, confirm the setting is present:
> `az webapp config appsettings list -g rg-vulncopilot-dev -n app-vulncopilot-dev --query "[?name=='CHAINLIT_URL']"`.
>
> **Same setting, different symptom — a 404 after the GitHub consent screen.** If
> `CHAINLIT_URL` points at a host that no longer serves this app (e.g. a custom
> domain that has since been repointed elsewhere), GitHub accepts the
> `redirect_uri` and sends the browser to that host's
> `/auth/oauth/github/callback`, where nothing answers. The fix is the same
> command with the host you are actually browsing, plus a matching callback URL on
> the OAuth App. `CHAINLIT_URL` comes from the `publicUrl` bicep param, so update
> `parameters.<env>.bicepparam` too or the next deployment resets it — see
> [Reverting off the apex](../plans/custom-domain-cloudflare.md#reverting-off-the-apex).

Use the bash `for` loop with `read` shell built-in to securely enter the env vars:
```bash
for var in ANTHROPIC_API_KEY OPENAI_API_KEY OAUTH_GITHUB_CLIENT_ID OAUTH_GITHUB_CLIENT_SECRET CHAINLIT_AUTH_SECRET PG_DATABASE_URL PG_DATABASE_URL_READONLY MCP_API_KEY LOGFIRE_TOKEN NVD_API_KEY; do
  echo "$var" && read -rs $var
done
```

> **Two database URLs, two roles** (see [docs/supabase-readonly-role.md](supabase-readonly-role.md)):
> - `PG_DATABASE_URL` → **write/admin** role (`app_etl`/`postgres`) → stored as `database-url`, used by the **ETL job**. Needs DDL since the loaders create tables/indexes.
> - `PG_DATABASE_URL_READONLY` → **read-only** role (`app_readonly`) → stored as `database-url-readonly`, used by the **live app**. The app runs with `DB_INIT_SCHEMA=false` so it never attempts schema DDL.
>
> Create the schema once with the admin connection (or let the ETL job's first run
> create it) **before** the read-only app serves traffic.

Create the Azure Key Vault secrets:
```bash
az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name anthropic-api-key \
  --value "$ANTHROPIC_API_KEY"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name openai-api-key \
  --value "$OPENAI_API_KEY"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name oauth-github-client-id \
  --value "$OAUTH_GITHUB_CLIENT_ID"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name oauth-github-client-secret \
  --value "$OAUTH_GITHUB_CLIENT_SECRET"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name chainlit-auth-secret \
  --value "$CHAINLIT_AUTH_SECRET"

# HTTP Basic password for the /admin dashboard. Required — the app refuses to
# start (and crash-loops on 503) if ADMIN_SECRET is empty. /admin is HTTPS-only
# but has no rate limiting, so the value must not be guessable. Use a strong
# value you'll actually type: a 4+ ordinary-word passphrase (e.g.
# "purple-canoe-rainy-otter", ~44+ bits) is easy to enter and well beyond online
# brute force. For a copy-paste manager, `openssl rand -base64 18` (~24 chars) works.
read -rs ADMIN_SECRET   # paste/type your chosen passphrase, then Enter
az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name admin-secret \
  --value "$ADMIN_SECRET"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name database-url \
  --value "$PG_DATABASE_URL"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name database-url-readonly \
  --value "$PG_DATABASE_URL_READONLY"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name mcp-api-key \
  --value "$MCP_API_KEY"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name logfire-token \
  --value "$LOGFIRE_TOKEN"

az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name nvd-api-key \
  --value "$NVD_API_KEY"
```

> `database-url-readonly` must exist before the pipeline runs — the App Service
> resolves it as its `PG_DATABASE_URL`. If absent, the KV reference fails and the
> app can't connect. (The ETL job uses the separate `database-url` write/admin secret.)

> `mcp-api-key` must exist before the pipeline runs — if absent, the App Service
> will start with a warning and the `/mcp` route will reject all requests with 401.

> `logfire-token` must exist before the pipeline runs — if absent, the App Service
> will fail to resolve the KV reference and Logfire tracing will not start.
> Retrieve the token from your Logfire project settings under **API Tokens**.
> `LOGFIRE_ENABLED` is controlled by `logfireEnabled` in `infra/parameters.dev.bicepparam`
> (defaults to `false` in the Bicep module; set to `true` in the param file to enable).

> `nvd-api-key` is consumed by the scheduled ETL job (see [Scheduled ETL Refresh](#scheduled-etl-refresh-container-apps-job)),
> not the App Service. The job still runs without it, but NVD throttles unauthenticated
> callers to 5 req/30s (vs 50 with a key), so a multi-week backfill will be far slower.
> Request a free key at <https://nvd.nist.gov/developers/request-an-api-key>.

Restart the App Service to re-resolve the Key Vault references:

```bash
az webapp restart \
  --name app-vulncopilot-dev \
  --resource-group rg-vulncopilot-dev
```

---

## Step 5: Load KEV and NVD Data (one-time)

Set `DATABASE_URL` in your `.env` pointing to Timescale Cloud, then follow the [Data Loading guide](data-loading.md) to populate the database.

> **Timescale Cloud note:** The connection string must include `?sslmode=require` — connections without SSL will be refused.

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
az pipelines run --name vulncopilot
```

---

## Verification

```bash
# 1. All resources provisioned
az resource list --resource-group rg-vulncopilot-dev -o table

# 2. KV references resolved (look for "Resolved" in the value column, not "Failed")
az webapp config appsettings list \
  --name app-vulncopilot-dev \
  --resource-group rg-vulncopilot-dev \
  --query "[?contains(value, '@Microsoft.KeyVault')]" -o table

# 3. Image present in ACR
az acr repository show-tags \
  --name acrvulncopilotdev \
  --repository vulncopilot \
  -o table

# 4. Health check responds 200
curl -v https://app-vulncopilot-dev.azurewebsites.net/healthz

# 5. App logs confirm successful DB connection
az webapp log tail \
  --name app-vulncopilot-dev \
  --resource-group rg-vulncopilot-dev
# Expected: successful startup with no DB connection errors
# Test query: "What vulnerabilities affect Apache?"

# 6. WebSocket: open app in browser → DevTools → Network → WS tab → active connection

# 7. Sticky sessions: check browser cookies for ARRAffinity cookie after login

# 8. Logfire KV reference resolved and tracing active
az webapp config appsettings list \
  --name app-vulncopilot-dev \
  --resource-group rg-vulncopilot-dev \
  --query "[?name=='LOGFIRE_TOKEN']" -o table
# Expected: value shows "@Microsoft.KeyVault(...)" — if "Failed", check KV permissions
# Then send a message in the app and confirm traces appear at https://logfire.pydantic.dev
```

---

## Redeploying

**New code:** push to `main` — pipeline handles everything.

**Updated secret value:**

```bash
az keyvault secret set \
  --vault-name kv-vulncopilot-dev \
  --name <secret-name> \
  --value "<new-value>"

az webapp restart \
  --name app-vulncopilot-dev \
  --resource-group rg-vulncopilot-dev
```

**Reload KEV/NVD data** (e.g., after CISA publishes new entries):

```bash
uv run python scripts/load_kev.py
uv run python scripts/load_nvd.py
# No app restart needed — data is queried live from Timescale Cloud
```

For an automated weekly refresh instead of running these by hand, see
[Scheduled ETL Refresh](#scheduled-etl-refresh-container-apps-job) below.

---

## Scheduled ETL Refresh (Container Apps Job)

The KEV and NVD datasets need periodic refreshes. Rather than running the loaders
by hand, a **Container Apps Job** (`job-vulncopilot-etl-<env>`) runs them on a cron
schedule, set by `etlCronExpression` in `infra/parameters.dev.bicepparam`. It reuses
the web app's container image, managed identity, ACR, and Key Vault, and scales to
zero between runs (you pay only for the few minutes each run takes).

Provisioned by `infra/modules/etl-job.bicep` and wired into `main.bicep` as Step 7.

### Why a Container Apps Job (not Functions / WebJobs)

- **No timeout ceiling that matters** — `replicaTimeout` is set to 2h; a multi-week
  catch-up backfill won't be killed mid-run. Azure Functions on the Consumption plan
  caps at 10 minutes, which is too short for a large Phase 2 modified-CVE sweep.
- **Reuses the existing stack** — same image in ACR, same user-assigned identity
  (already has `AcrPull` + `Key Vault Secrets User` from the `rbac` module), same
  Key Vault secrets. No new auth model, no new role assignments.
- **Serverless billing** — the job has no idle replicas between Mondays.

### What it runs

The job's entrypoint is `scripts/run_etl.py`, which runs the loaders, captures
each step's output and timing, and emails a results summary:

```
load_nvd_full.py --incremental   # full NVD incremental -> nvd_vulnerabilities
load_kev.py                      # KEV catalog          -> kev_vulnerabilities
```

The two loaders write different tables and are independent, so `run_etl.py` runs
both regardless of whether either fails — a KEV outage won't skip the NVD refresh,
and vice versa. It exits non-zero if any loader fails (so the platform records the
run as failed), and a failed email never masks a successful sync.

> **Why no KEV-scoped NVD enrichment step?** An earlier pipeline ran
> `load_nvd.py` to enrich KEV CVEs with CVSS/CWE data, but `load_nvd_full.py`
> already loads the full NVD corpus (every KEV CVE included) into the same columns,
> so it was redundant. Dropping it also removed the ordering constraint its recent
> `last_modified` writes used to impose on the incremental's high-water mark.

### Results email (Azure Communication Services)

After each run the job emails a summary — overall `SUCCESS`/`FAILED`, per-step
status, duration, and the key output lines (`Done! Synced N CVEs`, errors). It uses
**Azure Communication Services Email** with an **Azure-managed sender domain**
(`donotreply@<guid>.azurecomm.net`) — no DNS/domain verification needed — and
authenticates with the job's **managed identity** (no SMTP keys or secrets).

Provisioned by `infra/modules/email.bicep` (Step 7). The recipient is set by
`etlEmailTo` in `parameters.dev.bicepparam`; the sender address is auto-derived and
surfaced as the `etlEmailSender` deployment output.

> The managed identity is granted **Contributor scoped to the ACS resource only**
> (ACS has no fine-grained email-send role). If the first run logs an auth error
> sending email, that role assignment is the thing to check.

> **Gmail/Outlook spam:** mail from the Azure-managed `azurecomm.net` domain may land
> in spam initially. Check the spam folder on the first run and mark as “not spam.”

### Secrets and environment

Secrets come from Key Vault via the managed identity (Container Apps secret refs,
not App Service `@Microsoft.KeyVault(...)` references):

| Env var | Key Vault secret | Notes |
|---|---|---|
| `OPENAI_API_KEY` | `openai-api-key` | embeddings (shared with the web app) |
| `PG_DATABASE_URL` | `database-url` | target database (shared with the web app) |
| `NVD_API_KEY` | `nvd-api-key` | NVD rate limit 50/30s vs 5/30s — add in Step 4.1 |

Plus these non-secret env vars, set from Bicep (no Key Vault needed):

| Env var | Source | Purpose |
|---|---|---|
| `AZURE_CLIENT_ID` | identity client ID | selects the managed identity for ACS auth |
| `ACS_ENDPOINT` | `email` module output | ACS endpoint for sending mail |
| `ACS_SENDER` | `email` module output | verified `donotreply@…` sender address |
| `ETL_EMAIL_TO` | `etlEmailTo` param | recipient(s), comma-separated |

### Adjusting the schedule

Set `etlCronExpression` (UTC) in `parameters.dev.bicepparam`. Start frequent while
validating, then dial back as you gain confidence:

| Cron | Cadence | When |
|---|---|---|
| `0 6,18 * * *` | Twice daily (06:00 + 18:00 UTC) | Bootstrap — watching it work |
| `0 6 * * *` | Daily (06:00 UTC) | Early steady state |
| `0 6 * * 1` | Weekly (Mondays 06:00 UTC) | Steady state — index overhead is lowest |

Each change is a one-line param edit; redeploy the `etlJob` module (or the whole
template) to apply. More frequent runs mean smaller per-run incremental windows and
lower HNSW index churn, at the cost of more (cheap) job executions.

### Operating the job

```bash
# Trigger an immediate run (e.g. to catch up after a missed window)
az containerapp job start \
  --name job-vulncopilot-etl-dev \
  --resource-group rg-vulncopilot-dev

# List recent executions and their status
az containerapp job execution list \
  --name job-vulncopilot-etl-dev \
  --resource-group rg-vulncopilot-dev \
  --query "[].{name:name, status:properties.status, start:properties.startTime}" -o table

# Stream logs for a RUNNING execution (live replica only — see "Viewing logs" below)
az containerapp job logs show \
  --name job-vulncopilot-etl-dev \
  --resource-group rg-vulncopilot-dev \
  --container etl --execution <execution-name> --follow
```

> **Recovering from a long gap.** A weekly schedule keeps the watermark current, so
> each run only syncs ~7 days. If runs were paused for weeks, the incremental's
> auto-derived start may be too recent (especially if KEV loaders ran in between) —
> identify the last full-sync date from the per-day `last_modified` counts and pass
> `--since <date>` for a one-off manual catch-up before relying on the schedule again.
> See the [Data Loading guide](data-loading.md) for the `--since` workflow.

### Viewing logs

The job writes two kinds of logs to the `log-vulncopilot-dev` Log Analytics workspace:

| Table | Contents |
|---|---|
| `ContainerAppConsoleLogs_CL` | container **stdout/stderr** — the loader output, CVE counts, and (after the email branch) the `SUCCESS`/`FAILED` summary and `Email sent` line |
| `ContainerAppSystemLogs_CL` | platform events — image pull, container created/started, execution scheduled/completed |

> **`az containerapp job logs show` only works for a *running* execution.** Container
> Apps garbage-collects the replica (pod) once a job execution completes, so for a
> finished run the command returns `No replicas found for execution`. Use it with
> `--follow` right after `az containerapp job start` to watch a live run; for past
> runs, query Log Analytics (below), where the console output is persisted.

**From the CLI** (`az monitor log-analytics query`):

```bash
WS=$(az monitor log-analytics workspace show \
  -g rg-vulncopilot-dev -n log-vulncopilot-dev --query customerId -o tsv)

# Full console output from the last 2 days
az monitor log-analytics query --workspace "$WS" -o table \
  --analytics-query "ContainerAppConsoleLogs_CL | where TimeGenerated > ago(2d) | where ContainerName_s == 'etl' | order by TimeGenerated asc | project TimeGenerated, Log_s"

# Just the run summary + email outcome
az monitor log-analytics query --workspace "$WS" -o table \
  --analytics-query "ContainerAppConsoleLogs_CL | where TimeGenerated > ago(2d) | where Log_s has_any ('SUCCESS','FAILED','Synced','Done!','Email sent','failed to send') | order by TimeGenerated asc | project TimeGenerated, Log_s"
```

> Requires `Log Analytics Reader` on the workspace and the `log-analytics` CLI
> extension (auto-installs on first use).

**In the portal** (Log Analytics workspace → **Logs**; close the *Queries hub* overlay
and toggle off "Always show Queries hub" to reach the KQL editor), run the same KQL:

```kql
// All console output for the ETL container
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(2d)
| where ContainerName_s == "etl"
| order by TimeGenerated asc
| project TimeGenerated, Log_s

// Scope to one execution (replica name carries the execution id, e.g. ...-yahqcyx-xxxxx)
ContainerAppConsoleLogs_CL
| where ContainerGroupName_s has "<execution-id>"
| order by TimeGenerated asc
| project TimeGenerated, Log_s

// Platform events (image pull, start/complete) for the job
ContainerAppSystemLogs_CL
| where JobName_s == "job-vulncopilot-etl-dev"
| order by TimeGenerated desc
| project TimeGenerated, Log_s
```

> Console logs have a 2–10 min ingestion lag into Log Analytics — empty results right
> after a run usually mean "not ingested yet," not "no logs."

---

## MCP Server

The `/mcp` endpoint is co-hosted on the same App Service container as the Chainlit UI. No additional Azure resources are required.

### Architecture

```
Azure App Service (existing container)
├── / → Chainlit WebSocket UI           (unchanged)
├── /healthz → health check             (unchanged)
└── /mcp → FastMCP Streamable HTTP      (new)
      ├── tool: retrieve                (semantic search)
      └── tool: query                   (direct SQL)
```

All traffic uses the same HTTPS endpoint, same managed identity, same Key Vault references, and the same asyncpg connection pool.

### Transport

Streamable HTTP is used instead of SSE — it is stateless per-request and avoids Azure App Service idle timeout issues with long-lived SSE connections. Requires MCP spec 2025-03-26+ clients (Claude Desktop, etc.).

### Authentication

The `/mcp` route requires an `X-API-Key` header. The key is stored in Key Vault as `mcp-api-key` and injected via the Key Vault reference pattern (see Step 4.1 above). Generate a key with:

```bash
openssl rand -hex 32
```

See [docs/mcp-server.md](mcp-server.md) for the full MCP server operational guide, including tool reference and client connection examples.

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

**App crash-loops on 503 right after deploy (`:( Application Error`)**
- The app fails fast at startup if `ADMIN_SECRET` is empty (the `/admin` dashboard guard). Confirm the `admin-secret` Key Vault secret exists and the reference resolved: `az webapp config appsettings list -g rg-vulncopilot-dev -n app-vulncopilot-dev --query "[?name=='ADMIN_SECRET']"` (an empty `value` means the KV secret is missing — create it per Step 4.1, then restart).
- Also check the JSON-array app settings (`ADMIN_USER_IDENTIFIERS`, `ALLOWED_LOGINS`, …) hold valid JSON — a malformed value (e.g. quotes stripped to `[github:1]`) aborts startup. A *blank* value is tolerated as `[]`.

**Database connection fails on startup**
- Confirm `PG_DATABASE_URL` app setting is set and the KV reference resolved (`az webapp config appsettings list`)
- Confirm the Timescale Cloud connection string includes `?sslmode=require`
- Timescale Cloud requires SSL — connections without it will be refused
- Check Timescale Cloud connection limits and allowed IP ranges if the app is blocked

**Bicep deploy fails with `.bicepparam` syntax error**
- Run `az bicep upgrade` to ensure Bicep CLI 0.18+
- The pipeline's DeployInfra stage runs `az bicep upgrade` automatically before deploying

**Policy assignment fails with authorization error**
- `Microsoft.Authorization/policyAssignments` requires `Resource Policy Contributor` on the resource group
- Run the `policy` module manually the first time with a higher-privileged identity, or grant the pipeline SP that role temporarily

**ETL job only syncs the last day (misses weeks of CVEs)**
- The KEV loaders ran before the full incremental and advanced the high-water mark — confirm the job runs `load_nvd_full.py --incremental` *first* (it does in `etl-job.bicep`)
- For a one-off catch-up, run the job's loader manually with `--since <last-full-sync-date>`; find that date from the per-day `last_modified` counts (see [Data Loading guide](data-loading.md))

**ETL job fails pulling the image or reading secrets**
- The job uses the *same* managed identity as the App Service — confirm `AcrPull` and `Key Vault Secrets User` role assignments exist (they're created by the `rbac` module at resource-group scope)
- Confirm `nvd-api-key`, `openai-api-key`, and `database-url` all exist in Key Vault (`az keyvault secret list --vault-name kv-vulncopilot-dev -o table`)

**ETL job run terminated before completing**
- A large backfill may exceed `replicaTimeout` (default 7200s/2h) — raise it in `etl-job.bicep`, or split the catch-up into smaller `--since` windows run manually
