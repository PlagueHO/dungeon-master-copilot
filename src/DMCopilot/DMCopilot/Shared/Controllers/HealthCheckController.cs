using DMCopilot.Shared.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace DMCopilot.Shared.Controllers
{
    [ApiController]
    [Route("healthcheck")]
    public class HealthCheckController : ControllerBase
    {
        private readonly CosmosClient _cosmosClient;
        private readonly ILogger<HealthCheckController> _logger;

        public HealthCheckController(CosmosClient cosmosClient, ILogger<HealthCheckController> logger)
        {
            _cosmosClient = cosmosClient;
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            Boolean healthy = true;

            // Check the Cosmos DB connection
            var databases = await _cosmosClient.GetDatabaseQueryIterator<DatabaseProperties>().ReadNextAsync();
            healthy = databases.Any() && healthy;

            // Perform other health checks here

            // Return the health check status
            if (healthy)
            {
                _logger.LogInformation("Healthcheck OK");
                return Ok();
            }
            else
            {
                _logger.LogWarning("Healthcheck failed");
                return StatusCode(500);
            }
        }
    }

}
