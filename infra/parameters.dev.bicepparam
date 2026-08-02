using './main.bicep'

param environment = 'dev'
param acrName = 'acrvulncopilotdev'
param keyVaultName = 'kv-vulncopilot-dev'
param appServicePlanSku = 'B2'

param logfireEnabled = true

// GitHub OAuth authorization. Locked to a single login until rate limiting (PR 2)
// lands — flip openRegistration to true only for a short OAuth smoke test.
// Set oauth-github-client-id / oauth-github-client-secret in Key Vault (see
// docs/deploy-azure-app-service.md and docs/public-access-setup.md).
param openRegistration = false
param allowedLogins = '["jeffhoek"]'

// Custom domain (see plans/custom-domain-cloudflare.md). vulncopilot.org now
// resolves to the GCP deployment, so the apex is no longer this app's public
// host: empty publicUrl puts CHAINLIT_URL (the OAuth redirect_uri host) and
// MCP_ALLOWED_HOSTS back on app-vulncopilot-dev.azurewebsites.net, and the cert
// params are off because managed-certificate issuance/renewal validates DNS,
// which would now fail. Restore all three together if the apex ever points back.
param publicUrl = ''
param customDomain = ''
param deployCustomDomainCerts = false

// ETL refresh schedule (UTC cron). Start frequent while validating, then dial back:
//   '0 6,18 * * *' — twice daily, 06:00 + 18:00 UTC (bootstrap / watching it work)
//   '0 6 * * *'    — daily, 06:00 UTC
//   '0 6 * * 1'    — weekly, Mondays 06:00 UTC (steady state)
param etlCronExpression = '0 6,18 * * *'

// Personal / environment-specific values are NOT committed here — they are injected
// at deploy time from Azure DevOps pipeline variables (Pipelines → Edit → Variables),
// so nothing identifying lives in git. See azure-pipelines.yml:
//   --parameters etlEmailTo=$(ETL_EMAIL_TO)
//   --parameters adminUserIdentifiers=$(ADMIN_USER_IDENTIFIERS)
//   --parameters pipelineServicePrincipalObjectId=$(PIPELINE_SP_OBJECT_ID)
// Each falls back to a safe default (empty recipient = no email; empty admin list =
// everyone gets the standard rate limit) if the variable is unset.
param pipelineServicePrincipalObjectId = ''
