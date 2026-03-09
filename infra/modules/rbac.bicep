param managedIdentityPrincipalId string
param pipelinePrincipalId string
param keyVaultId string
param storageAccountId string
param acrId string

// Built-in role definition IDs
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
var storageBlobDataReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var acrPushRoleId = '8311e382-0749-4cb8-b61a-304f252e45ec'
var websiteContributorRoleId = 'de139f84-1756-47ae-9be6-808fbbe84772'

// Managed Identity → Key Vault Secrets User
resource kvSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultId, managedIdentityPrincipalId, 'kv-secrets-user')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Allow managed identity to read Key Vault secrets'
  }
}

// Managed Identity → Storage Blob Data Reader
resource storageBlobReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccountId, managedIdentityPrincipalId, 'storage-blob-reader')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataReaderRoleId)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Allow managed identity to read blobs from storage'
  }
}

// Managed Identity → ACR Pull
resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acrId, managedIdentityPrincipalId, 'acr-pull')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
    description: 'Allow managed identity to pull images from ACR'
  }
}

// Pipeline SP → ACR Push
resource acrPushAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acrId, pipelinePrincipalId, 'acr-push')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPushRoleId)
    principalId: pipelinePrincipalId
    principalType: 'ServicePrincipal'
    description: 'Allow pipeline service principal to push images to ACR'
  }
}

// Pipeline SP → Website Contributor (App Service)
resource websiteContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, pipelinePrincipalId, 'website-contributor')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', websiteContributorRoleId)
    principalId: pipelinePrincipalId
    principalType: 'ServicePrincipal'
    description: 'Allow pipeline service principal to deploy to App Service'
  }
}
