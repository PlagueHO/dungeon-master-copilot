using Azure.Identity;
using DMCopilot.Backend.Data;
using DMCopilot.Backend.Data.Configuration;
using DMCopilot.Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Azure.Cosmos;
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

        // Add Application Insights services into service collection
        builder.Services.AddApplicationInsightsTelemetry();

        // Add Logging services into service collection
        builder.Services.AddLogging();

        builder.Services.AddAuthorization(options =>
        {
            // By default, all incoming requests will be authorized according to the default policy
            options.FallbackPolicy = options.DefaultPolicy;
        });

        // Get an Azure AD token for the application to use to authenticate to services in Azure
        var azureCredential = new DefaultAzureCredential();

        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor()
            .AddMicrosoftIdentityConsentHandler();
        
        // Add the Cosmos DB client as a singleton service
        builder.Services.AddSingleton<CosmosClient>(sp =>
            {
                var cosmosDbEndpointUri = builder.Configuration["cosmosDbEndpointUri"];
                if (string.IsNullOrEmpty(cosmosDbEndpointUri))
                {
                    throw new ArgumentNullException("cosmosDbEndpointUri");
                }
                return new CosmosClient(cosmosDbEndpointUri, azureCredential);
            });

        // Add the Tenant repository as a scoped service
        builder.Services.AddScoped<ITenantRepository>(sp =>
            {
                var cosmosClient = sp.GetService<CosmosClient>();
                return new TenantRepository(cosmosClient, "dungeon-master-copilot", "Tenants");
            });

        // Add the Character repository as a scoped service
        builder.Services.AddScoped<ICharacterRepository>(sp =>
            {
                var cosmosClient = sp.GetService<CosmosClient>();
                return new CharacterRepository(cosmosClient, "dungeon-master-copilot", "Characters");
            });

        // Add the Semantic Kernel service
        builder.Services.AddSingleton<ISemanticKernelService>((svc) =>
        {
            // Get the Semantic Kernel configuration from appsettings.json
            var semanticKernelConfiguration = builder.Configuration
                .GetSection("SemanticKernel")
                .Get<SemanticKernelConfiguration>() ?? throw new Exception("Semantic Kernel configuration is null");
            return new SemanticKernelService(azureCredential, semanticKernelConfiguration);
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
}