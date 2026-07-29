param location string
param appServicePlanName string
param appServiceName string
param appServicePlanSku string
param identityId string
param identityClientId string
param acrLoginServer string
param keyVaultName string
param logfireEnabled bool = false
// Authorization for GitHub OAuth login (see docs/public-access-setup.md).
// Keep locked to your own login until rate limiting (PR 2) lands.
param openRegistration bool = false
param allowedLogins string = '[]' // JSON array, e.g. '["jeffhoek"]'
// Elevated rate-limit cap for admin/trusted users, keyed by stable GitHub
// identifier. Personal/env-specific — injected at deploy time from a pipeline
// variable, not committed to the param file. JSON array, e.g. '["github:123"]'.
param adminUserIdentifiers string = '[]'
param tags object = {}

// Custom domain (see plans/custom-domain-cloudflare.md).
// Canonical public URL. When a custom domain is live, set this to it so
// Chainlit builds the OAuth redirect_uri on the right host (App Service
// terminates TLS at the front end and forwards plain HTTP, so it can't infer
// this). Empty falls back to the default azurewebsites.net host.
param publicUrl string = ''
// Apex custom domain, e.g. 'vulncopilot.org'. Empty = no custom-domain certs.
param customDomain string = ''
// Gate for managed-certificate issuance. Keep false on a green-field deploy:
// issuance requires the DNS records (CNAME + asuid TXT) to already exist AND
// the hostname to be bound to the app (`az webapp config hostname add`). Flip
// to true only once DNS is live for the environment.
param deployCustomDomainCerts bool = false

var imageRef = '${acrLoginServer}/vulncopilot:latest'

var systemPrompt = concat(
  'You are a security analyst assistant with access to the ',
  'CISA Known Exploited Vulnerabilities (KEV) database ',
  'and NIST National Vulnerability Database (NVD).\n\n',
  '## Database Schema\n\n',
  'TABLE: kev_vulnerabilities (\n',
  '  cve_id VARCHAR(20),\n',
  '  vendor_project TEXT,\n',
  '  product TEXT,\n',
  '  vulnerability_name TEXT,\n',
  '  short_description TEXT,\n',
  '  required_action TEXT,\n',
  '  notes TEXT,\n',
  '  date_added DATE,\n',
  '  due_date DATE,\n',
  '  known_ransomware_campaign_use VARCHAR(20),\n',
  '  cwes TEXT[]\n',
  ')\n\n',
  'TABLE: nvd_vulnerabilities (\n',
  '  cve_id VARCHAR(20),\n',
  '  description TEXT,\n',
  '  cvss_v31_score NUMERIC(3,1),\n',
  '  cvss_v31_severity VARCHAR(10),\n',
  '  cvss_v31_vector TEXT,\n',
  '  cvss_v2_score NUMERIC(3,1),\n',
  '  cvss_v2_severity VARCHAR(10),\n',
  '  cwes TEXT[],\n',
  '  affected_products TEXT[],\n',
  '  reference_urls TEXT[],\n',
  '  published DATE,\n',
  '  last_modified DATE,\n',
  '  raw_json JSONB -- full NVD API response, query with -> and ->> operators\n',
  ')\n\n',
  'TABLE: cwe_definitions (\n',
  '  cwe_id VARCHAR(20),       -- e.g., \'CWE-79\'\n',
  '  name TEXT,                -- human-readable weakness name\n',
  '  abstraction VARCHAR(20),  -- Pillar, Class, Base, Variant, Compound\n',
  '  description TEXT,\n',
  '  url TEXT\n',
  ')\n\n',
  'JOIN tables on cve_id to cross-reference KEV and NVD data.\n',
  'JOIN cwe_definitions using: cwe_id = ANY(nvd_vulnerabilities.cwes) ',
  'or cwe_id = ANY(kev_vulnerabilities.cwes) to resolve CWE IDs to names.\n\n',
  '## Tools\n\n',
  '- **retrieve**: semantic search across both datasets. ',
  'Use for conceptual questions (e.g. \'tell me about Log4j\').\n',
  '- **query**: execute SQL. Use for counts, top-N, date filters, grouping, listing, and JOINs across tables.\n\n',
  'Answer concisely. If the answer is not in the data, say so. ',
  'When the user asks a follow-up question, use the conversation history to resolve references ',
  '(e.g., \'it\', \'that CVE\', \'the one you just described\') before querying the database.'
)

var actionButtons = join([
  'List the 10 newest KEV entries by date_added'
  'List KEV entries with known ransomware use'
  'CVE-2021-44228 (Log4Shell)'
  'CVE-2017-0144 (EternalBlue)'
  'CVE-2023-34362 (MOVEit Transfer)'
  'Reference URLs for CVE-2025-53770 (SharePoint ToolShell)'
  'Top 10 AI-related CVEs in 2026 by CVSS score'
  'LLM prompt injection vulns'
  'typo squatting'
  'Anthropic Claude vulns'
  'VPN and remote access vulns'
  'Top vendors in KEV'
  'Which weakness types appear most in KEV?'
  'Top actively-exploited, automatable, total-impact CVEs'
  'How many CVEs are in each SSVC exploitation state?'
  'CVSS 10.0 CVEs not yet exploited (SSVC none)'
], '","')

// FastMCP 3.x enables DNS-rebinding Host validation by default and only allows
// localhost, so every authenticated /mcp request to a public host returns 421
// Misdirected Request unless the host is allow-listed (see docs/mcp-server.md).
// Bare host (scheme/path stripped) of publicUrl, plus its www. variant.
var publicHost = replace(replace(publicUrl, 'https://', ''), 'http://', '')
var mcpAllowedHosts = empty(publicUrl)
  ? '["${appServiceName}.azurewebsites.net"]'
  : '["${appServiceName}.azurewebsites.net","${publicHost}","www.${publicHost}"]'

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: appServicePlanSku
  }
  properties: {
    reserved: true
  }
}

resource appService 'Microsoft.Web/sites@2023-12-01' = {
  name: appServiceName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlan.id
    keyVaultReferenceIdentity: identityId
    httpsOnly: true
    clientAffinityEnabled: true
    siteConfig: {
      linuxFxVersion: 'DOCKER|${imageRef}'
      webSocketsEnabled: true
      alwaysOn: true
      healthCheckPath: '/healthz'
      acrUseManagedIdentityCreds: true
      acrUserManagedIdentityID: identityClientId
      appSettings: [
        {
          name: 'AZURE_CLIENT_ID'
          value: identityClientId
        }
        {
          name: 'OPEN_REGISTRATION'
          value: string(openRegistration)
        }
        {
          name: 'ALLOWED_LOGINS'
          value: allowedLogins
        }
        {
          name: 'ADMIN_USER_IDENTIFIERS'
          value: adminUserIdentifiers
        }
        {
          name: 'LLM_MODEL'
          value: 'anthropic:claude-sonnet-5'
        }
        {
          name: 'TOP_K'
          value: '5'
        }
        {
          name: 'SYSTEM_PROMPT'
          value: systemPrompt
        }
        {
          name: 'ACTION_BUTTONS'
          value: '["${actionButtons}"]'
        }
        {
          // Read-only role for the live app (see docs/supabase-readonly-role.md).
          // The ETL job uses the separate write/admin 'database-url' secret.
          name: 'PG_DATABASE_URL'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=database-url-readonly)'
        }
        {
          // Read-only role can't run schema DDL; admin/ETL connection owns the schema.
          name: 'DB_INIT_SCHEMA'
          value: 'false'
        }
        {
          name: 'WEBSITES_PORT'
          value: '8080'
        }
        {
          name: 'WEBSITE_CONTAINER_START_TIME_LIMIT'
          value: '230'
        }
        {
          name: 'ANTHROPIC_API_KEY'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=anthropic-api-key)'
        }
        {
          name: 'OPENAI_API_KEY'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=openai-api-key)'
        }
        {
          // GitHub OAuth App client ID. Not strictly secret (it appears in the
          // redirect URL), but kept in Key Vault to keep the deploy flow uniform.
          name: 'OAUTH_GITHUB_CLIENT_ID'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=oauth-github-client-id)'
        }
        {
          name: 'OAUTH_GITHUB_CLIENT_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=oauth-github-client-secret)'
        }
        {
          name: 'CHAINLIT_AUTH_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=chainlit-auth-secret)'
        }
        {
          // HTTP Basic password for the /admin dashboard. app.py fails fast at
          // startup if this is empty, so the admin-secret Key Vault secret must
          // exist before this reference deploys or the app crash-loops (503).
          name: 'ADMIN_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=admin-secret)'
        }
        {
          // Canonical public URL. App Service terminates TLS at the front end and
          // forwards plain HTTP to the container, so without this Chainlit builds
          // the OAuth redirect_uri as http://… and GitHub rejects the mismatch.
          // Set publicUrl to a custom domain once live (plans/custom-domain-cloudflare.md).
          name: 'CHAINLIT_URL'
          value: empty(publicUrl) ? 'https://${appServiceName}.azurewebsites.net' : publicUrl
        }
        {
          name: 'MCP_API_KEY'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=mcp-api-key)'
        }
        {
          // Allow-list the public hostname(s) for FastMCP's Host guard; without
          // this, authenticated /mcp requests return 421 (see mcpAllowedHosts above).
          name: 'FASTMCP_HTTP_ALLOWED_HOSTS'
          value: mcpAllowedHosts
        }
        {
          name: 'LOGFIRE_ENABLED'
          value: string(logfireEnabled)
        }
        {
          name: 'LOGFIRE_TOKEN'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=logfire-token)'
        }
      ]
    }
  }
}

// Free App Service Managed Certificates for the custom domain + www.
// Declared here (rather than `az webapp config ssl create`) so the required
// environment/application tags are applied — the resource group tag policy
// denies untagged Microsoft.Web/certificates. Issuance requires the hostname to
// already be bound to the app and DNS (CNAME + asuid TXT, grey-cloud) to
// resolve, so this is gated behind deployCustomDomainCerts. Bind with SNI via
// `az webapp config ssl bind` after issuance — the hostname-binding/cert
// ordering doesn't express cleanly in a single ARM pass.
resource apexCert 'Microsoft.Web/certificates@2023-12-01' = if (deployCustomDomainCerts && !empty(customDomain)) {
  name: 'cert-${replace(customDomain, '.', '-')}'
  location: location
  tags: tags
  properties: {
    serverFarmId: appServicePlan.id
    canonicalName: customDomain
    domainValidationMethod: 'cname-delegation'
  }
}

resource wwwCert 'Microsoft.Web/certificates@2023-12-01' = if (deployCustomDomainCerts && !empty(customDomain)) {
  name: 'cert-www-${replace(customDomain, '.', '-')}'
  location: location
  tags: tags
  properties: {
    serverFarmId: appServicePlan.id
    canonicalName: 'www.${customDomain}'
    domainValidationMethod: 'cname-delegation'
  }
}

output appServiceId string = appService.id
output defaultHostName string = appService.properties.defaultHostName
