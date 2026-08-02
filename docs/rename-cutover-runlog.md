# Azure blue/green cutover — run log (rename to vulncopilot)

A record of the **as-run** blue/green cutover of the Azure App Service **dev** stack
during the `chainlit-rag` → `vulncopilot` rename: the exact `az` commands, the two
deployment failures and their fixes, and how the custom-domain certificates were
issued and bound. Companion to the forward runbook in
[plans/rename-to-vulncopilot.md](../plans/rename-to-vulncopilot.md) step 9 — that
file says *what to do*; this one says *what actually happened and how it was verified*.

Kept so the exercise doesn't have to be reverse-engineered later — especially the
custom-domain/cert mechanics, which are the least obvious part.

> **Historical as of 2026-08-01.** vulncopilot.org has since been repointed to the
> GCP/Mastra deployment, and this Azure app is back on
> `app-vulncopilot-dev.azurewebsites.net` (`publicUrl`/`customDomain` empty, certs
> off). The `CHAINLIT_URL = https://vulncopilot.org` readings below are the values
> *at cutover time*, not current. See
> [Reverting off the apex](../plans/custom-domain-cloudflare.md#reverting-off-the-apex).

## Ground rules that made this safe

- **Blue/green, not in-place.** RGs, ACR, and the App Service hostname can't be
  renamed in place, so a fresh `vulncopilot` stack was stood up alongside the old
  `chainlit-rag` stack; the old one stayed as a rollback until the very end.
- **The database was never in scope.** It's external (Supabase); the bicep only
  *references* `database-url` / `database-url-readonly` from Key Vault. Nothing here
  touched KEV/NVD/pgvector data, so no ETL reload.
- **No secrets are printed** in any command below (values piped to variables / `>/dev/null`).

Resource name map:

| | Old | New |
|---|---|---|
| Resource group | `rg-chainlit-rag-dev` | `rg-vulncopilot-dev` |
| Container registry / image | `acrchainlitragdev` / `chainlit-pydanticai-rag:latest` | `acrvulncopilotdev` / `vulncopilot:latest` |
| App Service | `app-chainlit-rag-dev` | `app-vulncopilot-dev` |
| Key Vault | `kv-chainlit-rag-dev` | `kv-vulncopilot-dev` |
| ADO ARM connection / SP | `azure-chainlit-rag` | `azure-vulncopilot` (SP objectId `c22817f0-…`) |

---

## Phase 1 — provision the new stack (plan 9.1–9.3)

### 1a. Prerequisites

```bash
# Confirm subscription/identity
az account show --query "{sub:name, id:id, user:user.name}" -o json

# Empty RG first — the ADO ARM service connection is RG-scoped, so the RG must exist
az group create -n rg-vulncopilot-dev -l eastus \
  --tags environment=dev application=vulncopilot
```

Then, in ADO, the `azure-vulncopilot` ARM service connection was created (automatic SP,
scope = `rg-vulncopilot-dev`) — this auto-granted the SP **Contributor**. Its objectId
was read back from the RG (no need to copy it out of ADO):

```bash
az role assignment list -g rg-vulncopilot-dev \
  --query "[?principalType=='ServicePrincipal'].{role:roleDefinitionName, principalId:principalId}" -o table
# → Contributor  c22817f0-fcc8-4df9-ab37-6a04eeda42b7

# Sanity-check which ADO project's SP this is
az ad sp show --id c22817f0-fcc8-4df9-ab37-6a04eeda42b7 --query displayName -o tsv
# → jeffreyscotthoekman0908-chainlit-pg-…   (the reused ADO project)
```

### 1b. Validate, then deploy — and the FIRST failure

```bash
# Fast dry-run catches param/template errors before committing to a long deploy
az deployment group validate \
  --resource-group rg-vulncopilot-dev \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=c22817f0-… \
               deployCustomDomainCerts=false publicUrl=''
# → state: Succeeded
```

> **Green-field overrides.** `deployCustomDomainCerts=false` + `publicUrl=''` are the
> two overrides that keep the new app *off* the shared domain during blue/green. Without
> them the managed cert for `vulncopilot.org` fails to issue (domain still points at the
> old app) and the OAuth redirect would point at the old app. `publicUrl=''` falls back to
> `https://app-vulncopilot-dev.azurewebsites.net` (`app-service.bicep:226`).

```bash
az deployment group create --resource-group rg-vulncopilot-dev --name vulncopilot-91 \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=c22817f0-… \
               deployCustomDomainCerts=false publicUrl=''
```

**❌ FAILED** — everything provisioned except the ETL Container Apps job:

```
InvalidParameterValueInContainerTemplate: Unable to get value using Managed identity
id-vulncopilot-dev for secret openai-api-key / database-url / nvd-api-key
```

**Why:** the Container Apps **Job** (`job-vulncopilot-etl-dev`, part of `main.bicep`)
resolves its Key Vault secret references **at create time**, and secrets weren't seeded
yet. (The App Service uses lazy `@Microsoft.KeyVault(...)` references that resolve at
*runtime*, so it deployed fine — only the job hard-failed.)

### 1c. Fix 1 — seed Key Vault (plan 9.3, but must come first)

Both vaults are RBAC-mode; **subscription Owner does not grant data-plane access**, so a
role had to be granted before secrets could be written:

```bash
az keyvault show -n kv-vulncopilot-dev --query "properties.enableRbacAuthorization" -o tsv   # → true

az role assignment create --role "Key Vault Secrets Officer" \
  --assignee-object-id $(az ad signed-in-user show --query id -o tsv) \
  --assignee-principal-type User \
  --scope $(az keyvault show -n kv-vulncopilot-dev --query id -o tsv)

# Copy EVERY secret old → new (12 of them; values never printed)
OLD_KV=kv-chainlit-rag-dev; NEW_KV=kv-vulncopilot-dev
for s in $(az keyvault secret list --vault-name "$OLD_KV" --query "[].name" -o tsv); do
  v=$(az keyvault secret show --vault-name "$OLD_KV" --name "$s" --query value -o tsv)
  az keyvault secret set --vault-name "$NEW_KV" --name "$s" --value "$v" >/dev/null
  echo "copied: $s"
done
```

The full set was: `admin-secret anthropic-api-key app-password chainlit-auth-secret
database-url database-url-readonly logfire-token mcp-api-key nvd-api-key
oauth-github-client-id oauth-github-client-secret openai-api-key` — copy the *whole*
vault, not a hand-picked subset.

Re-deployed (`vulncopilot-91b`) → **❌ FAILED again**, new error:

```
template.containers.etl.image invalid: "acrvulncopilotdev.azurecr.io/vulncopilot:latest":
MANIFEST_UNKNOWN: manifest tagged by "latest" is not found
```

Same lesson: the ETL job also validates its **image** at create time, and the new ACR was empty.

### 1d. Fix 2 — seed the registry (plan 9.2, also must come first)

```bash
az acr repository show-tags --name acrchainlitragdev --repository chainlit-pydanticai-rag  # confirm source
az acr import --name acrvulncopilotdev \
  --source acrchainlitragdev.azurecr.io/chainlit-pydanticai-rag:latest \
  --image vulncopilot:latest
```

Re-deployed (`vulncopilot-91c`) → **✅ Succeeded** (2m12s).

> **The ordering lesson (now fixed in the plan):** seed the **registry** and **Key Vault**
> *before* the stack deploy. The ETL Container Apps job validates both its image and its
> secrets at create time; the App Service does not.

### 1e. Post-provision validation

```bash
az resource list -g rg-vulncopilot-dev --query "[].name" -o table        # 11 resources incl. job-vulncopilot-etl-dev
az containerapp job show -n job-vulncopilot-etl-dev -g rg-vulncopilot-dev \
  --query "{image:properties.template.containers[0].image, state:properties.provisioningState}" -o json
az webapp config appsettings list -n app-vulncopilot-dev -g rg-vulncopilot-dev \
  --query "[?name=='CHAINLIT_URL']|[0].value" -o tsv                      # → https://app-vulncopilot-dev.azurewebsites.net
curl -s -o /dev/null -w "%{http_code}\n" https://app-vulncopilot-dev.azurewebsites.net/healthz   # → 200
```

---

## Phase 2 — CI/CD pipeline (plan 9.5)

### 2a. The pipeline SP needs Owner

The pipeline runs the *full bicep*, whose `rbac`/`policy` modules create role and policy
assignments (`Microsoft.Authorization/*/write`) — which **Contributor cannot do**. The old
pipeline SPs had **Owner**; the new one only had Contributor:

```bash
az role assignment list --assignee c22817f0-… -g rg-vulncopilot-dev --query "[].roleDefinitionName" -o tsv
# → Contributor, Website Contributor, AcrPush   (no Owner)

az role assignment create --role Owner \
  --assignee-object-id c22817f0-… --assignee-principal-type ServicePrincipal \
  --scope $(az group show -n rg-vulncopilot-dev --query id -o tsv)
```

### 2b. Keep the pipeline off the domain

The pipeline redeploys `parameters.dev.bicepparam` *without* CLI overrides, so the
green-field values had to be **committed to the branch** param file (else a run would
re-enable the cert and break OAuth): `deployCustomDomainCerts=false`, `publicUrl=''`
(commit `4ae3aac`). **This toggle is reverted at cutover (Phase 3f).**

The pipeline run itself was done in ADO (variable `PIPELINE_SP_OBJECT_ID=c22817f0-…`,
branch `rename-to-vulncopilot`, path `azure-pipelines.yml`). Post-run validation:

```bash
az webapp config show -n app-vulncopilot-dev -g rg-vulncopilot-dev --query linuxFxVersion -o tsv
# → DOCKER|acrvulncopilotdev.azurecr.io/vulncopilot:4ae3aac   (pipeline-built image, not the imported :latest)
az acr repository show-tags --name acrvulncopilotdev --repository vulncopilot --orderby time_desc -o tsv  # → 4ae3aac, latest
curl -s -o /dev/null -w "%{http_code}\n" https://app-vulncopilot-dev.azurewebsites.net/healthz   # → 200
```

---

## Phase 3 — domain cutover + certificates (plan 9.6)

This is the part that's least obvious, so read the "How custom domains + certs work"
section below alongside it.

### 3a. The asuid TXT does NOT change

```bash
az webapp show -n app-chainlit-rag-dev -g rg-chainlit-rag-dev --query customDomainVerificationId -o tsv
az webapp show -n app-vulncopilot-dev  -g rg-vulncopilot-dev  --query customDomainVerificationId -o tsv
# → IDENTICAL (8AF55B95…) — the verification ID is per-SUBSCRIPTION, not per-app
```

So the Cloudflare `asuid.vulncopilot.org` TXT record is left alone; only the two CNAMEs move.

### 3b–d. DNS + hostname rebinding (done manually)

1. **Cloudflare:** repoint the apex `@` and `www` CNAMEs from `app-chainlit-rag-dev…`
   to `app-vulncopilot-dev.azurewebsites.net`, **DNS-only (grey cloud)** — orange-cloud
   proxying breaks App Service cert validation + SNI.
2. **Release from old app** (a hostname can bind to only ONE app at a time):
   ```bash
   az webapp config hostname delete -g rg-chainlit-rag-dev --webapp-name app-chainlit-rag-dev --hostname vulncopilot.org
   az webapp config hostname delete -g rg-chainlit-rag-dev --webapp-name app-chainlit-rag-dev --hostname www.vulncopilot.org
   ```
3. **Bind to new app:**
   ```bash
   az webapp config hostname add -g rg-vulncopilot-dev --webapp-name app-vulncopilot-dev --hostname vulncopilot.org
   az webapp config hostname add -g rg-vulncopilot-dev --webapp-name app-vulncopilot-dev --hostname www.vulncopilot.org
   ```

Verification:

```bash
az webapp config hostname list --webapp-name app-vulncopilot-dev -g rg-vulncopilot-dev --query "[].name" -o tsv
# → app-vulncopilot-dev.azurewebsites.net, vulncopilot.org, www.vulncopilot.org
dig +short vulncopilot.org            # apex → A record (Cloudflare CNAME flattening), e.g. 20.119.8.60
dig +short www.vulncopilot.org CNAME  # → app-vulncopilot-dev.azurewebsites.net.
```

### 3e. Issue the managed certs (publicUrl held empty)

Certs are issued by re-deploying with `deployCustomDomainCerts=true` **but `publicUrl`
still `''`** — deliberately holding the OAuth redirect on the azurewebsites host until the
certs actually serve, so login isn't broken mid-flow.

```bash
az deployment group create --resource-group rg-vulncopilot-dev --name vulncopilot-certs \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=c22817f0-… \
               deployCustomDomainCerts=true publicUrl=''
# → Succeeded (4m29s)
```

The bicep only *creates* the certs (`app-service.bicep` `apexCert`/`wwwCert`, gated on
`deployCustomDomainCerts && !empty(customDomain)`) — it does **not** bind them. Confirm
issuance and grab thumbprints:

```bash
# NOTE: `az webapp config ssl list` showed EMPTY here (a quirk before binding) —
# inspect the raw cert resources instead:
az resource list -g rg-vulncopilot-dev --resource-type Microsoft.Web/certificates --query "[].name" -o table
az resource show -g rg-vulncopilot-dev --resource-type Microsoft.Web/certificates --name cert-vulncopilot-org \
  --query "{thumbprint:properties.thumbprint, subject:properties.subjectName, issue:properties.issueDate, expiry:properties.expirationDate}" -o json
# apex → 1DDB8B5DBEBDACE6482C3F27AD7DF2CC331B3461 (CN=vulncopilot.org, DigiCert/GeoTrust)
# www  → E7F956CFBE9B743639A874D0380125C637132444
```

### 3f. SNI-bind the certs

```bash
az webapp config ssl bind -g rg-vulncopilot-dev --name app-vulncopilot-dev \
  --certificate-thumbprint 1DDB8B5DBEBDACE6482C3F27AD7DF2CC331B3461 --ssl-type SNI
az webapp config ssl bind -g rg-vulncopilot-dev --name app-vulncopilot-dev \
  --certificate-thumbprint E7F956CFBE9B743639A874D0380125C637132444 --ssl-type SNI

az webapp show -n app-vulncopilot-dev -g rg-vulncopilot-dev \
  --query "hostNameSslStates[?sslState!='Disabled'].{host:name, sslState:sslState, thumb:thumbprint}" -o table
# → vulncopilot.org / www.vulncopilot.org both SniEnabled
```

Verify HTTPS (the first probe returned `HTTP 000` — frontend propagation, ~1–2 min — then 200):

```bash
curl -s -o /dev/null -w "%{http_code} ssl_verify=%{ssl_verify_result}\n" https://vulncopilot.org/healthz       # → 200 ssl_verify=0
curl -s -o /dev/null -w "%{http_code} ssl_verify=%{ssl_verify_result}\n" https://www.vulncopilot.org/healthz   # → 200 ssl_verify=0

echo | openssl s_client -connect vulncopilot.org:443 -servername vulncopilot.org 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
# subject=CN=vulncopilot.org ; issuer=DigiCert/GeoTrust ; valid Jul 11 2026 → Jan 11 2027
```

### 3g. Final flip — publicUrl → vulncopilot.org

Revert the blue/green toggle in the branch param file (commit `07a6f72`:
`deployCustomDomainCerts=true`, `publicUrl='https://vulncopilot.org'`) and redeploy so the
app's canonical URL + OAuth `redirect_uri` move onto the domain:

```bash
az deployment group create --resource-group rg-vulncopilot-dev --name vulncopilot-flip \
  --template-file infra/main.bicep \
  --parameters infra/parameters.dev.bicepparam \
  --parameters pipelineServicePrincipalObjectId=c22817f0-…
# → Succeeded

az webapp config appsettings list -n app-vulncopilot-dev -g rg-vulncopilot-dev \
  --query "[?name=='CHAINLIT_URL']|[0].value" -o tsv    # → https://vulncopilot.org
```

Then, in GitHub, the OAuth App's single **Authorization callback URL** was moved to
`https://vulncopilot.org/auth/oauth/github/callback`, and login was verified end-to-end
through the domain (private window, to avoid cached sessions).

### 3h. `/admin` sanity check

`/admin` is **HTTP Basic Auth**, separate from GitHub OAuth — the entered *password* is
compared to `ADMIN_SECRET` (`admin/dashboard.py`, `secrets.compare_digest`; username
ignored). Confirmed working on the new app:

```bash
curl -s -D - -o /dev/null https://vulncopilot.org/admin | grep -iE "^HTTP|WWW-Authenticate"
# → HTTP/1.1 401 Unauthorized ; WWW-Authenticate: Basic

s=$(az keyvault secret show --vault-name kv-vulncopilot-dev --name admin-secret --query value -o tsv)
curl -s -o /dev/null -w "%{http_code}\n" -u "admin:$s" https://vulncopilot.org/admin   # → 200
```

---

## How custom domains + certs actually work on App Service

The single most confusing part. There are **three independent systems** that all have to
line up, and the bicep only owns one of them:

1. **DNS (Cloudflare)** — makes `vulncopilot.org` *resolve*. Two CNAMEs (apex + www),
   grey-cloud. Plus a one-time `asuid.<domain>` TXT for ownership proof (per-subscription,
   so it didn't change in this migration).
2. **Hostname binding (App Service)** — makes the app *accept and route* requests for that
   `Host` header. DNS alone isn't enough: App Service's shared frontend routes by Host and
   only to the app that has claimed the hostname. `az webapp config hostname add`. A
   hostname binds to exactly **one** app, so cutover = delete-from-old then add-to-new.
3. **TLS certificate** — a **managed cert** (`Microsoft.Web/certificates`, free, DigiCert-
   issued via `cname-delegation` validation) that must then be **SNI-bound** to the
   hostname. Issuance requires #1 and #2 to already be in place — which is why the bicep
   gates it behind `deployCustomDomainCerts` and the param comment says "keep false until
   DNS + hostname binding exist."

**Order that works:** DNS → hostname binding → issue cert (redeploy) → `ssl bind` (SNI) →
*then* flip `publicUrl` so OAuth moves onto the now-serving domain. The bicep creates the
cert but not the binding or the SNI bind (its comment: *"the hostname-binding/cert ordering
doesn't express cleanly in a single ARM pass"*), so those two are manual `az` steps.

## Gotchas, condensed

- **ETL job validates image + secrets at create time** → seed ACR and Key Vault *before* the deploy.
- **RBAC vaults:** Owner ≠ data-plane access → grant yourself `Key Vault Secrets Officer` to seed.
- **Pipeline SP needs Owner** (not just Contributor) for the bicep `rbac`/`policy` modules.
- **`deployCustomDomainCerts`/`publicUrl`** must be off during blue/green and flipped back at cutover — and `publicUrl` should flip *after* the cert serves, not with it.
- **asuid TXT is per-subscription** — unchanged across a same-subscription app move.
- **`az webapp config ssl list` can show empty** before binding — inspect `Microsoft.Web/certificates` resources directly.
- **First HTTPS probe after `ssl bind` may be `HTTP 000`** — frontend propagation; retry after a minute.
- **Custom-domain verification ID / object IDs are identifiers, not secrets** — safe to record; actual Key Vault secret *values* never are.
