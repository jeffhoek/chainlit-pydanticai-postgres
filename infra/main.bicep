targetScope = 'resourceGroup'

@description('Deployment environment (dev, prod)')
param environment string

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Azure Container Registry name (globally unique, no hyphens)')
param acrName string

@description('Key Vault name (globally unique, 3-24 chars)')
param keyVaultName string

@description('App Service Plan SKU (B2 for dev, P1v3 for prod)')
param appServicePlanSku string

@description('Object ID of the pipeline service principal for RBAC assignments')
param pipelineServicePrincipalObjectId string

@description('Enable Logfire observability (requires logfire-token in Key Vault)')
param logfireEnabled bool = false

@description('Allow any GitHub account to log in. Keep false in prod until rate limiting (PR 2) lands.')
param openRegistration bool = false

@description('JSON array of allowed GitHub usernames, e.g. \'["jeffhoek"]\'.')
param allowedLogins string = '[]'

@description('JSON array of GitHub identifiers with the elevated rate-limit cap, e.g. \'["github:12345678"]\'. Inject from a pipeline variable; do not commit a real value.')
param adminUserIdentifiers string = '[]'

@description('Cron schedule (UTC) for the ETL refresh job. Default: Mondays 06:00 UTC.')
param etlCronExpression string = '0 6 * * 1'

@description('Recipient address(es) for the ETL results email (comma-separated). Inject from a pipeline variable; empty disables the email. Do not commit a real address.')
param etlEmailTo string = ''

@description('Max seconds the ad-hoc catch-up job may run before termination. Default 10h — large one-off backfills are long.')
param etlCatchupReplicaTimeout int = 36000

@description('Canonical public URL. Set to the custom domain once live (e.g. \'https://vulncopilot.org\'); empty falls back to the azurewebsites.net host. See plans/custom-domain-cloudflare.md.')
param publicUrl string = ''

@description('Apex custom domain for managed certs, e.g. \'vulncopilot.org\'. Empty = no custom-domain certs.')
param customDomain string = ''

@description('Issue managed certificates for the custom domain. Keep false until DNS + hostname binding exist for the environment.')
param deployCustomDomainCerts bool = false

var appName = 'vulncopilot'
var tags = {
  environment: environment
  application: appName
}

var identityName = 'id-${appName}-${environment}'
var appServicePlanName = 'asp-${appName}-${environment}'
var appServiceName = 'app-${appName}-${environment}'
var logAnalyticsName = 'log-${appName}-${environment}'
var managedEnvironmentName = 'cae-${appName}-${environment}'
var etlJobName = 'job-${appName}-etl-${environment}'
var etlCatchupJobName = 'job-${appName}-etl-catchup-${environment}'
var communicationServiceName = 'acs-${appName}-${environment}'
var emailServiceName = 'email-${appName}-${environment}'

// Step 1: User-Assigned Managed Identity (must run first)
module identity 'modules/identity.bicep' = {
  name: 'identity'
  params: {
    location: location
    name: identityName
    tags: tags
  }
}

// Step 2: Container Registry
module acr 'modules/acr.bicep' = {
  name: 'acr'
  params: {
    location: location
    name: acrName
    tags: tags
  }
}

// Step 3: Key Vault
module keyVault 'modules/key-vault.bicep' = {
  name: 'keyVault'
  params: {
    location: location
    name: keyVaultName
    tags: tags
  }
}

// Step 4: App Service Plan + Web App
module appService 'modules/app-service.bicep' = {
  name: 'appService'
  params: {
    location: location
    appServicePlanName: appServicePlanName
    appServiceName: appServiceName
    appServicePlanSku: appServicePlanSku
    identityId: identity.outputs.identityId
    identityClientId: identity.outputs.clientId
    acrLoginServer: acr.outputs.loginServer
    keyVaultName: keyVaultName
    logfireEnabled: logfireEnabled
    openRegistration: openRegistration
    allowedLogins: allowedLogins
    adminUserIdentifiers: adminUserIdentifiers
    publicUrl: publicUrl
    customDomain: customDomain
    deployCustomDomainCerts: deployCustomDomainCerts
    tags: tags
  }
}

// Step 5: RBAC — all role assignments (depends on all resources above)
module rbac 'modules/rbac.bicep' = {
  name: 'rbac'
  dependsOn: [
    appService
  ]
  params: {
    managedIdentityPrincipalId: identity.outputs.principalId
    pipelinePrincipalId: pipelineServicePrincipalObjectId
    keyVaultId: keyVault.outputs.keyVaultId
    acrId: acr.outputs.acrId
  }
}

// Step 6: Azure Policy assignments
module policy 'modules/policy.bicep' = {
  name: 'policy'
}

// Step 7: Azure Communication Services Email — sends the ETL results summary.
module email 'modules/email.bicep' = {
  name: 'email'
  params: {
    communicationServiceName: communicationServiceName
    emailServiceName: emailServiceName
    managedIdentityPrincipalId: identity.outputs.principalId
    tags: tags
  }
}

// Step 8: Scheduled ETL job (Container Apps Job) — KEV + NVD refresh + results email.
// Depends on rbac so the identity can pull from ACR and read Key Vault secrets.
module etlJob 'modules/etl-job.bicep' = {
  name: 'etlJob'
  dependsOn: [
    rbac
  ]
  params: {
    location: location
    logAnalyticsName: logAnalyticsName
    managedEnvironmentName: managedEnvironmentName
    jobName: etlJobName
    identityId: identity.outputs.identityId
    identityClientId: identity.outputs.clientId
    acrLoginServer: acr.outputs.loginServer
    keyVaultName: keyVaultName
    cronExpression: etlCronExpression
    acsEndpoint: email.outputs.acsEndpoint
    acsSender: email.outputs.senderAddress
    emailTo: etlEmailTo
    tags: tags
  }
}

// Step 9: Ad-hoc ETL catch-up job (Manual-trigger Container Apps Job) — started
// on demand by azure-pipelines-etl.yml for large one-off backlogs. Reuses the
// managed environment stood up by the scheduled job, so it depends on it.
module etlCatchupJob 'modules/etl-catchup-job.bicep' = {
  name: 'etlCatchupJob'
  params: {
    location: location
    managedEnvironmentId: etlJob.outputs.managedEnvironmentId
    jobName: etlCatchupJobName
    identityId: identity.outputs.identityId
    identityClientId: identity.outputs.clientId
    acrLoginServer: acr.outputs.loginServer
    keyVaultName: keyVaultName
    replicaTimeout: etlCatchupReplicaTimeout
    acsEndpoint: email.outputs.acsEndpoint
    acsSender: email.outputs.senderAddress
    emailTo: etlEmailTo
    tags: tags
  }
}

output appServiceUrl string = 'https://${appService.outputs.defaultHostName}'
output acrLoginServer string = acr.outputs.loginServer
output keyVaultUri string = keyVault.outputs.keyVaultUri
output etlJobName string = etlJob.outputs.jobName
output etlCatchupJobName string = etlCatchupJob.outputs.jobName
output etlEmailSender string = email.outputs.senderAddress
