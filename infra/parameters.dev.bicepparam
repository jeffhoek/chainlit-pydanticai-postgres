using './main.bicep'

param environment = 'dev'
param acrName = 'acrchainlitragdev'
param keyVaultName = 'kv-chainlit-rag-dev'
param storageAccountName = 'stchainlitragdev'
param blobContainerName = 'rag-content'
param appServicePlanSku = 'B2'

// pipelineServicePrincipalObjectId is passed as a pipeline variable at deploy time:
//   --parameters pipelineServicePrincipalObjectId=$(PIPELINE_SP_OBJECT_ID)
param pipelineServicePrincipalObjectId = ''
