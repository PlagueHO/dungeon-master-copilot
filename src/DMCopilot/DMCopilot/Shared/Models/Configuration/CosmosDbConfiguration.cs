namespace DMCopilot.Shared.Models.Configuration
{
    public class CosmosDbConfiguration
    {
        public Uri? EndpointUri { get; set; }
        public string DatabaseName { get; set; } = "dmcopilot";
    }
}
