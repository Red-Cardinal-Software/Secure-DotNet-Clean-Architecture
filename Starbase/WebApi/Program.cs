//#if (UseAzure)
using Azure.Identity;
using Microsoft.ApplicationInsights.Extensibility;
using Serilog.Events;
//#endif
//#if (UseAWS)
using Amazon;
using Kralizek.Extensions.Configuration;
using AWS.Logger.SeriLog;
using AWS.Logger;
//#endif
//#if (UseGCP)
using Google.Cloud.SecretManager.V1;
using Serilog.Sinks.GoogleCloudLogging;
//#endif
using DependencyInjectionConfiguration;
using Elastic.CommonSchema.Serilog;
using Infrastructure.Logging;
using Infrastructure.Persistence;
using Infrastructure.Web.Middleware;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// SECURITY: Disable the 'Server' header to prevent fingerprinting
// CMMC SI.L2-3.14.1 - Hide system information
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;

    // SECURITY: Limit request body size to prevent DoS attacks with oversized payloads
    // Default is ~28.6MB, we limit to 1MB which is generous for JSON API requests
    serverOptions.Limits.MaxRequestBodySize = 1 * 1024 * 1024; // 1MB
});

//#if (UseAzure)
// Azure Key Vault Configuration
// Requires: Azure.Identity and Azure.Extensions.AspNetCore.Configuration.Secrets packages
// Set KeyVaultName in appsettings.json or as environment variable
if (!builder.Environment.IsDevelopment())
{
    var keyVaultName = builder.Configuration["KeyVaultName"];
    if (!string.IsNullOrEmpty(keyVaultName))
    {
        var keyVaultUri = new Uri($"https://{keyVaultName}.vault.azure.net/");
        builder.Configuration.AddAzureKeyVault(keyVaultUri, new DefaultAzureCredential());
    }
}
//#endif

//#if (UseAWS)
// AWS Secrets Manager Configuration
// Requires: AWSSDK.SecretsManager and Kralizek.Extensions.Configuration.AWSSecretsManager packages
// Set AWS:SecretsManager:SecretName in appsettings.json or as environment variable
// AWS credentials are loaded from environment, IAM role, or ~/.aws/credentials
if (!builder.Environment.IsDevelopment())
{
    var secretName = builder.Configuration["AWS:SecretsManager:SecretName"];
    if (!string.IsNullOrEmpty(secretName))
    {
        var region = builder.Configuration["AWS:SecretsManager:Region"] ?? "us-east-1";
        builder.Configuration.AddSecretsManager(region: RegionEndpoint.GetBySystemName(region), configurator: options =>
        {
            options.SecretFilter = entry => entry.Name == secretName;
        });
    }
}
//#endif

//#if (UseGCP)
// Google Cloud Secret Manager Configuration
// Requires: Google.Cloud.SecretManager.V1 package
// Set GCP:SecretManager:ProjectId and GCP:SecretManager:SecretId in appsettings.json
// GCP credentials are loaded from GOOGLE_APPLICATION_CREDENTIALS environment variable
if (!builder.Environment.IsDevelopment())
{
    var projectId = builder.Configuration["GCP:SecretManager:ProjectId"];
    var secretId = builder.Configuration["GCP:SecretManager:SecretId"];
    if (!string.IsNullOrEmpty(projectId) && !string.IsNullOrEmpty(secretId))
    {
        var client = SecretManagerServiceClient.Create();
        var secretVersionName = new SecretVersionName(projectId, secretId, "latest");
        var response = client.AccessSecretVersion(secretVersionName);
        var secretPayload = response.Payload.Data.ToStringUtf8();

        // Parse the secret as JSON and add to configuration
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(secretPayload));
        builder.Configuration.AddJsonStream(stream);
    }
}
//#endif

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
// SECURITY: Only add Swagger services in development to prevent API surface information disclosure
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
        {
            Title = "Starbase Template .NET API",
            Version = "v1",
            Description = "A secure .NET API with comprehensive MFA and security features"
        });

        // Add JWT Bearer Authentication
        c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Description = "JWT Authorization header using the Bearer scheme. Enter your JWT token in the text input below (without 'Bearer' prefix).",
            Name = "Authorization",
            In = Microsoft.OpenApi.Models.ParameterLocation.Header,
            Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT"
        });

        c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
        {
            {
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Reference = new Microsoft.OpenApi.Models.OpenApiReference
                    {
                        Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        });
    });
}

var loggerConfig = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.With<EmailMaskingEnricher>()
    .Enrich.WithMachineName()
    .Enrich.WithProcessId()
    .Enrich.WithProcessName()
    .Enrich.WithEnvironmentName()
    .Destructure.With<SensitiveDataDestructuringPolicy>();
    

// Only write to console in development - production should use configured sinks
// Use ECS (Elastic Common Schema) format for SIEM compatibility
if (builder.Environment.IsDevelopment())
{
    // Development: Human-readable console + ECS JSON file for testing SIEM integration
    loggerConfig.WriteTo.Console();
    loggerConfig.WriteTo.File(
        new EcsTextFormatter(),
        "logs/ecs-.json",
        rollingInterval: RollingInterval.Day);
}
else
{
    //#if (UseAzure)
    // Azure Application Insights logging
    // Set ApplicationInsights:ConnectionString in appsettings.json or secrets
    var appInsightsConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"];
    if (!string.IsNullOrEmpty(appInsightsConnectionString))
    {
        var telemetryConfig = TelemetryConfiguration.CreateDefault();
        telemetryConfig.ConnectionString = appInsightsConnectionString;
        loggerConfig.WriteTo.ApplicationInsights(telemetryConfig, TelemetryConverter.Traces);
        builder.Services.AddApplicationInsightsTelemetry(options =>
        {
            options.ConnectionString = appInsightsConnectionString;
        });
    }
    //#endif
    //#if (UseAWS)
    // AWS CloudWatch logging
    // Set AWS:CloudWatch:LogGroup in appsettings.json
    // AWS credentials are loaded from environment, IAM role, or ~/.aws/credentials
    var logGroup = builder.Configuration["AWS:CloudWatch:LogGroup"];
    var region = builder.Configuration["AWS:CloudWatch:Region"] ?? "us-east-1";
    if (!string.IsNullOrEmpty(logGroup))
    {
        var awsLoggerConfig = new AWSLoggerConfig(logGroup)
        {
            Region = region
        };
        loggerConfig.WriteTo.AWSSeriLog(awsLoggerConfig);
    }
    //#endif
    //#if (UseGCP)
    // Google Cloud Logging
    // Set GCP:Logging:ProjectId in appsettings.json
    // GCP credentials are loaded from GOOGLE_APPLICATION_CREDENTIALS environment variable
    var gcpProjectId = builder.Configuration["GCP:Logging:ProjectId"];
    if (!string.IsNullOrEmpty(gcpProjectId))
    {
        loggerConfig.WriteTo.GoogleCloudLogging(new GoogleCloudLoggingSinkOptions
        {
            ProjectId = gcpProjectId
        });
    }
    //#endif
}

Log.Logger = loggerConfig.CreateLogger();

// Register Serilog with the host - required for UseSerilogRequestLogging()
// Pass the logger explicitly to avoid conflicts with test configuration
builder.Host.UseSerilog(Log.Logger, dispose: true);

builder.Services.AddAppDependencies(builder.Environment, builder.Configuration);
builder.Services.AddControllers();

var app = builder.Build();

// Auto-migrate database in Development for frictionless startup
// Production deployments should use explicit migrations
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
    Log.Information("Database migrated successfully");
}

// SECURITY: Short-circuit setup endpoint after initial configuration
// This runs before all other middleware to minimize attack surface for DDoS
// Once setup is complete, requests to /setup are rejected with minimal processing
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api") &&
        context.Request.Path.Value?.Contains("/setup", StringComparison.OrdinalIgnoreCase) == true)
    {
        var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
        if (cache.TryGetValue("SetupService:IsSetupComplete", out bool isComplete) && isComplete)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
    }
    await next();
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Security middleware, order matters!
// 1. HSTS - only in production (tells browsers to always use HTTPS)
if (!app.Environment.IsDevelopment())
{
    // CMMC SI.L2-3.14.1 - System Flaw Identification
    // Use a generic error handler to prevent stack trace leakage
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseSerilogRequestLogging();

// 2. Redirect HTTP to HTTPS
app.UseHttpsRedirection();

// 3. Add security headers (X-Frame-Options, CSP, etc.)
app.UseSecurityHeaders();

// 4. Rate limiting
app.UseRateLimiting();

// 5. CORS - must be before authentication to handle preflight requests
app.UseCors();

// Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Make Program class accessible to integration tests
public partial class Program { }