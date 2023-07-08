using Azure.Identity;
using DMCopilot.Shared.Models.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Orchestration;
using Microsoft.SemanticKernel.SkillDefinition;
using System.Configuration;

namespace DMCopilot.Shared.Services
{
    public class SemanticKernelService : ISemanticKernelService
    {
        private readonly IKernel _semanticKernel;
        private readonly SemanticKernelConfiguration _semanticKernelConfiguration;
        private readonly DefaultAzureCredential _azureCredential;
        private readonly string _pluginsDirectory;
        private readonly ILogger<SemanticKernelService> _logger;
        private IDictionary<string, IDictionary<string, Microsoft.SemanticKernel.SkillDefinition.ISKFunction>> _functions;

        public SemanticKernelService(DefaultAzureCredential azureCredential, SemanticKernelConfiguration semanticKernelConfiguration, ILogger<SemanticKernelService> logger)
        {
            _azureCredential = azureCredential;
            _semanticKernelConfiguration = semanticKernelConfiguration;
            _logger = logger;

            _logger.LogInformation("Creating Semantic Kernel");

            var semanticKernelBuilder = new KernelBuilder();

            // Load the generative AI services that will be available to Semantic Kernel
            LoadAzureOpenAiTextCompletionServices(semanticKernelBuilder);
            LoadAzureOpenAiChatCompletionServices(semanticKernelBuilder);
            LoadAzureOpenAiTextEmbeddingGenerationServices(semanticKernelBuilder);

            _semanticKernel = semanticKernelBuilder.Build();

            // Set the class-level private field _skillDirectory to a value that 
            // corresponds to the value retrieved from the configuration or the default 
            // value specified in the code block, which is "\Plugins".
            var pluginsDirectory = semanticKernelConfiguration.PluginsDirectory;
            if (pluginsDirectory == null)
            {
                _pluginsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Plugins");
            }
            else
            {
                _pluginsDirectory = Path.IsPathRooted(pluginsDirectory) ? pluginsDirectory : Path.Combine(Directory.GetCurrentDirectory(), pluginsDirectory);
            }

            _functions = new Dictionary<string, IDictionary<string, Microsoft.SemanticKernel.SkillDefinition.ISKFunction>>();
        }

        public void LoadAzureOpenAiTextCompletionServices(KernelBuilder semanticKernelBuilder)
        {
            if (_semanticKernelConfiguration.AzureOpenAiTextCompletionServices == null)
                throw new ConfigurationErrorsException("No Azure OpenAI Text Completion services configured");

            foreach (SemanticKernelAzureOpenAiTextCompletionServices service in _semanticKernelConfiguration.AzureOpenAiTextCompletionServices)
            {
                if (service.Deployment == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Text Completion service is empty");

                if (service.Endpoint == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Text Completion service is empty");

                _logger.LogInformation($"Adding Azure OpenAI Text Completion service '{service.Id}' using deployment '{service.Deployment}' on endpoint '{service.Endpoint}' to Semantic Kernel");

                semanticKernelBuilder.WithAzureTextCompletionService(
                   deploymentName: service.Deployment,
                   endpoint: service.Endpoint,
                   credentials: _azureCredential,
                   serviceId: service.Id,
                   setAsDefault: service.SetAsDefault);
            }
        }

        public void LoadAzureOpenAiChatCompletionServices(KernelBuilder semanticKernelBuilder)
        {
            if (_semanticKernelConfiguration.AzureOpenAiChatCompletionServices == null)
                throw new ConfigurationErrorsException("No Azure OpenAI Chat Completion services configured");

            foreach (SemanticKernelAzureOpenAiChatCompletionServices service in _semanticKernelConfiguration.AzureOpenAiChatCompletionServices)
            {
                if (service.Deployment == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Chat Completion service is empty");

                if (service.Endpoint == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Chat Completion service is empty");

                _logger.LogInformation($"Adding Azure OpenAI Chat Completion service '{service.Id}' using deployment '{service.Deployment}' on endpoint '{service.Endpoint}' to Semantic Kernel");

                semanticKernelBuilder.WithAzureChatCompletionService(
                   deploymentName: service.Deployment,
                   endpoint: service.Endpoint,
                   credentials: _azureCredential,
                   serviceId: service.Id,
                   setAsDefault: service.SetAsDefault,
                   alsoAsTextCompletion: service.AlsoAsTextCompletion);
            }
        }

        public void LoadAzureOpenAiTextEmbeddingGenerationServices(KernelBuilder semanticKernelBuilder)
        {
            if (_semanticKernelConfiguration.AzureOpenAiTextEmbeddingGenerationServices == null)
                throw new ConfigurationErrorsException("No Azure OpenAI Text Embedding Generation services configured");

            foreach (SemanticKernelAzureOpenAiTextEmbeddingGenerationServices service in _semanticKernelConfiguration.AzureOpenAiTextEmbeddingGenerationServices)
            {
                if (service.Deployment == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Text Embedding Generation service is empty");

                if (service.Endpoint == null)
                    throw new ConfigurationErrorsException("Deployment setting for Azure OpenAI Text Embedding Generation service is empty");

                _logger.LogInformation($"Adding Azure OpenAI Text Embedding Generation service '{service.Id}' using deployment '{service.Deployment}' on endpoint '{service.Endpoint}' to Semantic Kernel");

                semanticKernelBuilder.WithAzureTextEmbeddingGenerationService(
                   deploymentName: service.Deployment,
                   endpoint: service.Endpoint,
                   credential: _azureCredential,
                   serviceId: service.Id,
                   setAsDefault: service.SetAsDefault);
            }
        }

        public void LoadPlugin(string name)
        {
            if (! _functions.ContainsKey(name))
            {
                // Import a Semantic Skill from the specified directory and output a console message to confirm it.
                _functions.Add(name, _semanticKernel.ImportSemanticSkillFromDirectory(_pluginsDirectory, name));
                _logger.LogInformation($"Imported {_functions.Count()} from plugin '{name} in the '{_pluginsDirectory}' directory.");
            } 
        }

        public async Task<SKContext> InvokeFunctionAsync(string plugin, string function, string input)
        {
            LoadPlugin(plugin);
            var context = _semanticKernel.CreateNewContext();
            context["input"] = input;
            var result = await _functions[plugin][function].InvokeAsync(context);
            return result;
        }
    }
}
