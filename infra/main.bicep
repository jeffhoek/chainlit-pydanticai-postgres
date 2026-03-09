targetScope = 'resourceGroup'

@description('Deployment environment (dev, prod)')
param environment string

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Azure Container Registry name (globally unique, no hyphens)')
param acrName string

@description('Key Vault name (globally unique, 3-24 chars)')
param keyVaultName string

@description('Storage account name (globally unique, lowercase alphanumeric)')
param storageAccountName string

@description('Blob container name for RAG content')
param blobContainerName string = 'rag-content'

@description('App Service Plan SKU (B2 for dev, P1v3 for prod)')
param appServicePlanSku string

@description('Object ID of the pipeline service principal for RBAC assignments')
param pipelineServicePrincipalObjectId string

var appName = 'chainlit-rag'
var tags = {
  environment: environment
  application: appName
}

var identityName = 'id-${appName}-${environment}'
var appServicePlanName = 'asp-${appName}-${environment}'
var appServiceName = 'app-${appName}-${environment}'

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

// Step 4: Storage Account + Blob Container
module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    storageAccountName: storageAccountName
    blobContainerName: blobContainerName
    tags: tags
  }
}

// Step 5: App Service Plan + Web App
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
    storageAccountName: storageAccountName
    tags: tags
  }
}

// Step 6: RBAC — all role assignments (depends on all resources above)
module rbac 'modules/rbac.bicep' = {
  name: 'rbac'
  dependsOn: [
    appService
  ]
  params: {
    managedIdentityPrincipalId: identity.outputs.principalId
    pipelinePrincipalId: pipelineServicePrincipalObjectId
    keyVaultId: keyVault.outputs.keyVaultId
    storageAccountId: storage.outputs.storageAccountId
    acrId: acr.outputs.acrId
  }
}

// Step 7: Azure Policy assignments
module policy 'modules/policy.bicep' = {
  name: 'policy'
}

output appServiceUrl string = 'https://${appService.outputs.defaultHostName}'
output acrLoginServer string = acr.outputs.loginServer
output keyVaultUri string = keyVault.outputs.keyVaultUri
output storageAccountName string = storage.outputs.storageAccountName
