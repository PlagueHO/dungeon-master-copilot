param location string
param cosmosDbAccountName string

resource cosmosDbAccount 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {
  name: cosmosDbAccountName
  location: location
  kind: 'GlobalDocumentDB'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    databaseAccountOfferType: 'Standard'
    locations: [
      {
        locationName: location
        failoverPriority: 0
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
      maxIntervalInSeconds: 5
      maxStalenessPrefix: 100
    }
    enableAutomaticFailover: false
    enableMultipleWriteLocations: false
    isVirtualNetworkFilterEnabled: false
    enableAnalyticalStorage: false
    enableFreeTier: false
    publicNetworkAccess: 'Enabled'
  }
}


resource cosmosDbDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2023-04-15' = {
  name: 'dmcopilot'
  parent: cosmosDbAccount
  properties: {
    resource: {
      id: 'dmcopilot'
    }
    options: {
      autoscaleSettings: {
        maxThroughput: 1000
      }
    }
  }
}

resource cosmosDbAccountsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: 'accounts'
  parent: cosmosDbDatabase
  properties: {
    resource: {
      id: 'accounts'
      partitionKey: {
        paths: [
          '/id'
        ]
        kind: 'Hash'
      }
    }
  }
}

resource cosmosDbTenantsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: 'tenants'
  parent: cosmosDbDatabase
  properties: {
    resource: {
      id: 'tenants'
      partitionKey: {
        paths: [
          '/id'
        ]
        kind: 'Hash'
      }
    }
  }
}

resource cosmosDbWorldsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: 'worlds'
  parent: cosmosDbDatabase
  properties: {
    resource: {
      id: 'worlds'
      partitionKey: {
        paths: [
          '/tenantid'
          '/id'
        ]
        kind: 'MultiHash'
        version: 2
      }
    }
  }
}

resource cosmosDbCampaignsContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: 'campaigns'
  parent: cosmosDbDatabase
  properties: {
    resource: {
      id: 'campaigns'
      partitionKey: {
        paths: [
          '/tenantid'
          '/worldid'
          '/id'
        ]
        kind: 'MultiHash'
        version: 2
      }
    }
  }
}

resource cosmosDbCharactersContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-04-15' = {
  name: 'characters'
  parent: cosmosDbDatabase
  properties: {
    resource: {
      id: 'characters'
      partitionKey: {
        paths: [
          '/tenantid'
          '/campaignid'
          '/id'
        ]
        kind: 'MultiHash'
        version: 2
      }
    }
  }
}

output cosmosDbAccountName string = cosmosDbAccount.name
output cosmosDbAccountId string = cosmosDbAccount.id
