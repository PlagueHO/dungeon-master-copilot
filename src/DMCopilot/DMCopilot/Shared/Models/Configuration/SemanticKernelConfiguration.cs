namespace DMCopilot.Shared.Models.Configuration;

public class SemanticKernelConfiguration
{
    public String? PluginsDirectory { get; set; }
    public List<SemanticKernelAzureOpenAiTextCompletionServices>? AzureOpenAiTextCompletionServices { get; set; }
    public List<SemanticKernelAzureOpenAiChatCompletionServices>? AzureOpenAiChatCompletionServices { get; set; }
    public List<SemanticKernelAzureOpenAiTextEmbeddingGenerationServices>? AzureOpenAiTextEmbeddingGenerationServices { get; set; }
}

public class SemanticKernelAzureOpenAiTextCompletionServices
{
    public String? Id { get; set; }    
    public String? Deployment { get; set; }
    public String? Endpoint { get; set; }
    public Boolean SetAsDefault { get; set; } = false;
}

public class SemanticKernelAzureOpenAiChatCompletionServices
{
    public String? Id { get; set; }
    public String? Deployment { get; set; }
    public String? Endpoint { get; set; }
    public Boolean AlsoAsTextCompletion { get; set; } = false;
    public Boolean SetAsDefault { get; set; } = false;
}

public class SemanticKernelAzureOpenAiTextEmbeddingGenerationServices
{
    public String? Id { get; set; }
    public String? Deployment { get; set; }
    public String? Endpoint { get; set; }
    public Boolean SetAsDefault { get; set; } = false;
}
