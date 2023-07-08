using DMCopilot.Shared.Models;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Logging;
using Microsoft.Graph.Models;

namespace DMCopilot.Shared.Data
{
    public class TenantRepository : ITenantRepository
    {
        private readonly Container _container;
        private readonly ILogger<TenantRepository> _logger;

        public TenantRepository(CosmosClient client, String databaseName, String containerName, ILogger<TenantRepository> logger)
        {
            _container = client.GetContainer(databaseName, containerName);
            _logger = logger;
            _logger.LogInformation($"Initialized {nameof(TenantRepository)} using container '{containerName}'.");
        }

        public async Task<Tenant> GetTenantAsync(Guid id)
        {
            try
            {
                var response = await _container.ReadItemAsync<Tenant>(id.ToString(), new PartitionKey(id.ToString()));
                return response.Resource;
            }
            catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new TenantNotFoundException(id.ToString());
            }
        }

        private async Task<Tenant> GetTenantByQueryAsync(QueryDefinition queryDefinition)
        {
            var query = _container.GetItemQueryIterator<Tenant>(queryDefinition);
            if (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                if (response != null && response.Count > 0)
                {
                    return response.FirstOrDefault();
                }
            }
            return null;
        }

        public async Task<Tenant> GetTenantByNameAsync(String name)
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c WHERE c.Name = @name")
                .WithParameter("@name", name);
            return await GetTenantByQueryAsync(queryDefinition);
        }

        public async Task<Tenant> GetTenantByOwnerEmailAsync(EmailAddress ownerEmail)
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c WHERE c.OwnerEmail = @ownerEmail")
                .WithParameter("@ownerEmail", ownerEmail.Address);
            return await GetTenantByQueryAsync(queryDefinition);
        }

        private async Task<IEnumerable<Tenant>> GetTenantsByQueryAsync(QueryDefinition queryDefinition)
        {
            var query = _container.GetItemQueryIterator<Tenant>(queryDefinition);
            var results = new List<Tenant>();
            while (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                results.AddRange(response.ToList());
            }
            return results;
        }

        public async Task<IEnumerable<Tenant>> GetTenantsAsync()
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c");
            return await GetTenantsByQueryAsync(queryDefinition);
        }

        public async Task<IEnumerable<Tenant>> GetTenantsByOwnerEmailAsync(EmailAddress ownerEmail)
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c WHERE c.OwnerEmail = @ownerEmail")
                .WithParameter("@ownerEmail", ownerEmail.Address);
            return await GetTenantsByQueryAsync(queryDefinition);
        }

        public async Task<Tenant> CreateTenantAsync(Tenant tenant)
        {
            var response = await _container.CreateItemAsync(tenant);
            return response.Resource;
        }

        public async Task<Tenant> UpdateTenantAsync(Guid id, Tenant tenant)
        {
            tenant.Id = id;
            var response = await _container.UpsertItemAsync(tenant, new PartitionKey(tenant.Id.ToString()));
            return response.Resource;
        }

        public async Task<Boolean> DeleteTenantAsync(Guid id)
        {
            try
            {
                await _container.DeleteItemAsync<Tenant>(id.ToString(), new PartitionKey(id.ToString()));
                return true;
            }
            catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return false;
            }
        }
    }
}