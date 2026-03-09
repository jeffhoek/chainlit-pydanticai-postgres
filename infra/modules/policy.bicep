// Built-in policy definitions live at tenant scope — use tenantResourceId(), not subscriptionResourceId()

// Policy: Require HTTPS on App Service
// Built-in: "App Service apps should only be accessible over HTTPS"
resource httpsOnlyPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'enforce-https-app-service'
  properties: {
    displayName: 'App Service apps should only be accessible over HTTPS'
    policyDefinitionId: tenantResourceId(
      'Microsoft.Authorization/policyDefinitions',
      'a4af4a39-4135-47fb-b175-47fbdf85311d'
    )
    enforcementMode: 'Default'
  }
}

// Policy: Require 'environment' tag on resources
// Built-in: "Require a tag on resources"
resource requireEnvironmentTagPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'require-tag-environment'
  properties: {
    displayName: 'Require environment tag on resources'
    policyDefinitionId: tenantResourceId(
      'Microsoft.Authorization/policyDefinitions',
      '871b6d14-10aa-478d-b590-94f262ecfa99'
    )
    enforcementMode: 'Default'
    parameters: {
      tagName: {
        value: 'environment'
      }
    }
  }
}

// Policy: Require 'application' tag on resources
resource requireApplicationTagPolicy 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'require-tag-application'
  properties: {
    displayName: 'Require application tag on resources'
    policyDefinitionId: tenantResourceId(
      'Microsoft.Authorization/policyDefinitions',
      '871b6d14-10aa-478d-b590-94f262ecfa99'
    )
    enforcementMode: 'Default'
    parameters: {
      tagName: {
        value: 'application'
      }
    }
  }
}
