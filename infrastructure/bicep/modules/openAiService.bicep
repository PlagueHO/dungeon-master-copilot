param location string
param openAiServiceName string
param openAiModeldeployments array
param logAnalyticsWorkspaceId string
param logAnalyticsWorkspaceName string

resource openAiService 'Microsoft.CognitiveServices/accounts@2022-12-01' = {
  name: openAiServiceName
  location: location
  sku: {
    name: 'S0'
  }
  kind: 'OpenAI'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    customSubDomainName: openAiServiceName
  }

  // Loop through the list of models and create a deployment for each
  resource openAiServiceDeployment 'deployments@2022-12-01' = [for (model, i) in openAiModeldeployments: {
    name: model.name
    properties: {
      model: {
        format: 'OpenAI'
        name: model.modelName
        version: model.modelVersion
      }
      scaleSettings: {
        scaleType: model.scaleType
      }
    }
  }]
}

// Add the diagnostic settings to send logs and metrics to Log Analytics
resource openAiServiceDiagnosticSetting 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-${logAnalyticsWorkspaceName}'
  scope: openAiService
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'Audit'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: false 
        }
      }
      {
        category: 'allLogs'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: false 
        }
      }
    ]
    metrics:[
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}

output openAiServiceEndpoint string = openAiService.properties.endpoint
