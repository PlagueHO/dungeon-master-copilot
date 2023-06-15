using Azure.Identity;
using dungeon_master_copilot_server.Data;
using dungeon_master_copilot_server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.SemanticKernel;
using System.Text.Json;

internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var initialScopes = builder.Configuration["DownstreamApi:Scopes"]?.Split(' ') ?? builder.Configuration["MicrosoftGraph:Scopes"]?.Split(' ');

        // Add services to the container.
        builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
                .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
        .AddMicrosoftGraph(builder.Configuration.GetSection("MicrosoftGraph"))
                    .AddInMemoryTokenCaches();
        builder.Services.AddControllersWithViews()
            .AddMicrosoftIdentityUI();

        builder.Services.AddAuthorization(options =>
        {
            // By default, all incoming requests will be authorized according to the default policy
            options.FallbackPolicy = options.DefaultPolicy;
        });

        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor()
            .AddMicrosoftIdentityConsentHandler();

        // Create the Semantic Kernel and add it as a singleton service
        var semanticKernelBuilder = CreateSemanticKernel(builder);

        builder.Services.AddSingleton<ISemanticKernelService>((svc) =>
        {
            return new SemanticKernelService(semanticKernelBuilder,builder.Configuration["SemanticKernel:SkillDirectory"]);
        });

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllers();
        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");

        app.Run();
    }

    private static IKernel CreateSemanticKernel(WebApplicationBuilder builder)
    {
        Console.WriteLine("Creating Semantic Kernel");

        // Get an Azure AD token for the application to use to authenticate to services in Azure
        var azureCredential = new DefaultAzureCredential();

        var semanticKernel = new KernelBuilder();

        // Get the Semantic Kernel configuration from appsettings.json
        var semanticKernelConfiguration = builder.Configuration
            .GetSection("SemanticKernel")
            .Get<SemanticKernelConfiguration>();
        if (semanticKernelConfiguration == null)
        {
            throw new Exception("Semantic Kernel configuration is null");
        }

        var serviceActions = new Dictionary<SemanticKernelConfigurationServiceType, Action<SemanticKernelConfigurationService>>()
        {
            { SemanticKernelConfigurationServiceType.AzureOpenAIServiceTextCompletion, (service) => semanticKernel.WithAzureTextCompletionService(service.Deployment,
                                                                                                                                service.Endpoint,
                                                                                                                                azureCredential,
                                                                                                                                service.Id) },
            { SemanticKernelConfigurationServiceType.AzureOpenAIServiceChatCompletion, (service) => semanticKernel.WithAzureTextCompletionService(service.Deployment,
                                                                                                                                service.Endpoint,
                                                                                                                                azureCredential,
                                                                                                                                service.Id) },
            { SemanticKernelConfigurationServiceType.AzureOpenAIServiceEmbedding, (service) => semanticKernel.WithAzureTextEmbeddingGenerationService(service.Deployment,
                                                                                                                                     service.Endpoint,
                                                                                                                                     azureCredential,
                                                                                                                                     service.Id) }
        };

        if (semanticKernelConfiguration.Services == null)
        {
            throw new Exception("Semantic Kernel configuration services are null");
        }

        foreach (var service in semanticKernelConfiguration.Services)
        {
            Console.WriteLine($"Adding service {service.Id} using deployment {service.Deployment} on endpoint {service.Endpoint} to Semantic Kernel");


            if (serviceActions.TryGetValue(service.Type, out var action))
            {
                action(service);
            }
            else
            {
                throw new ArgumentException("Invalid Semantic Kernel service type");
            }
        }

        return semanticKernel.Build();
    }
}