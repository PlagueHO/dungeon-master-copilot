using DMCopilot.Shared.Models;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Logging;

namespace DMCopilot.Shared.Data
{
    public class WorldRepository : IWorldRepository
    {
        private readonly Container _container;
        private readonly ILogger<WorldRepository> _logger;

        public WorldRepository(CosmosClient client, String databaseName, String containerName, ILogger<WorldRepository> logger)
        {
            _container = client.GetContainer(databaseName, containerName);
            _logger = logger;
            _logger.LogInformation($"Initialized {nameof(WorldRepository)} using container '{containerName}'.");
        }

        public async Task<World> GetWorldAsync(Guid id, Guid tenantId)
        {
            try
            {
                var response = await _container.ReadItemAsync<World>(id.ToString(), new PartitionKey(id.ToString()));
                return response.Resource;
            }
            catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new TenantNotFoundException(id.ToString());
            }
        }

        private async Task<World> GetWorldByQueryAsync(QueryDefinition queryDefinition)
        {
            var query = _container.GetItemQueryIterator<World>(queryDefinition);
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

        public async Task<World> GetWorldByNameAsync(Guid tenantId, string name)
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c WHERE c.Name = @name")
                .WithParameter("@name", name);
            return await GetWorldByQueryAsync(queryDefinition);
        }

        private async Task<IEnumerable<World>> GetWorldsByQueryAsync(QueryDefinition queryDefinition)
        {
            var query = _container.GetItemQueryIterator<World>(queryDefinition);
            var results = new List<World>();
            while (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                results.AddRange(response.ToList());
            }
            return results;
        }

        public async Task<IEnumerable<World>> GetWorldsByTenantAsync(Guid tenantId)
        {
            var queryDefinition = new QueryDefinition("SELECT * FROM c");
            return await GetWorldsByQueryAsync(queryDefinition);
        }

        public async Task<World> CreateWorldAsync(World world)
        {
            var response = await _container.CreateItemAsync(world);
            return response.Resource;
        }

        public async Task<World> UpdateWorldAsync(Guid id, World world)
        {
            world.Id = id;
            var response = await _container.UpsertItemAsync(world, new PartitionKey(world.Id.ToString()));
            return response.Resource;
        }

        public async Task<Boolean> DeleteWorldAsync(Guid id)
        {
            try
            {
                await _container.DeleteItemAsync<World>(id.ToString(), new PartitionKey(id.ToString()));
                return true;
            }
            catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return false;
            }
        }
    }
}