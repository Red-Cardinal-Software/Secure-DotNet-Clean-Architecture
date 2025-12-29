using Application.Common.Configuration;
using Application.Common.Email;
using Application.Common.Interfaces;
using Application.DTOs.Mfa;
using Application.DTOs.Mfa.EmailMfa;
using Application.DTOs.Mfa.WebAuthn;
using Application.DTOs.Users;
using Application.Interfaces.Mappers;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Interfaces.Validation;
using Application.Logging;
using Application.Mapper.Base;
using Application.Mapper.Custom;
using Application.Security;
using Application.Services.AppUser;
using Application.Services.AccountLockout;
using Application.Services.Auth;
using Application.Services.Email;
using Application.Services.Audit;
using Application.Services.Mfa;
using Application.Services.PasswordReset;
using Application.Services.Setup;
using Application.Validators;
using AutoMapper;
using FluentValidation;
using Infrastructure.Emailing;
using Infrastructure.HealthChecks;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Interceptors;
using Infrastructure.Repositories;
using Infrastructure.Security;
using Infrastructure.Security.Repository;
using Infrastructure.Web.Validation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Application.Interfaces.Providers;
using Asp.Versioning;
using Fido2NetLib;
using Infrastructure.Providers;
using Infrastructure.Services;
using Infrastructure.Services.Development;
using Infrastructure.Security.SigningKey;
using Infrastructure.Telemetry;
using MediatR;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace DependencyInjectionConfiguration;

/// <summary>
/// Class representing configurable options for application-level dependency injection setup.
/// This provides flags to enable or disable specific dependency injection configurations
/// such as repositories, services, database, validation, authorization, and AutoMapper.
/// </summary>
public class AppDependencyOptions
{
    public bool IncludeRepositories { get; set; } = true;
    public bool IncludeServices { get; set; } = true;
    public bool IncludeDb { get; set; } = true;
    public bool IncludeValidation { get; set; } = true;
    public bool IncludeAuthorization { get; set; } = true;
    public bool IncludeAutoMapper { get; set; } = true;
    public bool IncludeHealthChecks { get; set; } = true;
    public bool IncludeAuthentication { get; set; } = true;
    public bool IncludeRateLimiting { get; set; } = true;
    public bool IncludeCaching { get; set; } = true;
    public bool IncludeCors { get; set; } = true;
    public bool IncludeApiVersioning { get; set; } = true;
}

/// <summary>
/// Provides extension methods for configuring application-level dependency injection
/// with options to include various components such as repositories, services,
/// database context, validation, authorization policies, and AutoMapper.
/// This class is designed to streamline the registration of dependencies
/// by utilizing a customizable configuration.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures application-level dependency injection by registering various components such as
    /// repositories, services, database context, validation, authorization policies, and AutoMapper.
    /// This method provides customization options to include or exclude specific components.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which dependencies will be added.</param>
    /// <param name="environment">The IHostEnvironment instance that provides information about the application's hosting environment.</param>
    /// <param name="configuration">The IConfiguration instance for reading application settings.</param>
    /// <param name="configure">
    /// An optional Action to configure the <see cref="AppDependencyOptions"/> for determining which components to include.
    /// </param>
    /// <returns>The modified <see cref="IServiceCollection"/> instance.</returns>
    public static IServiceCollection AddAppDependencies(this IServiceCollection services, IHostEnvironment environment, IConfiguration configuration, Action<AppDependencyOptions>? configure = null)
    {
        var options = new AppDependencyOptions();
        configure?.Invoke(options);

        if (options.IncludeDb) services.AddDbContext(environment);
        if (options.IncludeAutoMapper) services.AddAutoMapper();
        services.AddCoreInfrastructure(); // assumed to always be needed
        services.AddAppOptions(); // Add this before services so options are available
        services.AddOpenTelemetryObservability(environment); // assumed to always need logging
        if (options.IncludeRepositories) services.AddRepositories();
        if (options.IncludeServices) services.AddServices();
        if (options.IncludeAuthentication) services.AddSecureJwtAuthentication(configuration);
        if (options.IncludeAuthorization) services.AddAuthorizationPolicies();
        if (options.IncludeValidation) services.AddValidation();
        if (options.IncludeHealthChecks) services.AddAppHealthChecks(configuration);
        if (options.IncludeRateLimiting) services.AddRateLimiting(configuration);
        if (options.IncludeCors) services.AddConfigurableCors(configuration);
        if (options.IncludeApiVersioning) services.AddApiVersioningConfiguration();
        if (options.IncludeCaching)
        {
            // IMemoryCache for in-process caching (used by SetupService, etc.)
            services.AddMemoryCache();

            // IDistributedCache: Support both local (memory) and Cloud (redis) automatically
            var redisConnection = configuration.GetConnectionString("Redis");

            if (!string.IsNullOrWhiteSpace(redisConnection))
            {
                services.AddStackExchangeRedisCache(cacheOptions =>
                {
                    cacheOptions.Configuration = configuration.GetConnectionString("redis");
                    cacheOptions.InstanceName = "StarbaseTemplate_";
                });
            }
            else
            {
                // Development: Fallback to Memory if no redis config is found.
                // Implements the IDistributedCache so your services don't need to change.
                services.AddDistributedMemoryCache();
            }
        }

        return services;
    }

    /// <summary>
    /// Registers repository-related services with the dependency injection container.
    /// This includes implementations for user management, password management,
    /// token management, role management, email templates, and email template rendering.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which repository services will be added.</param>
    /// <returns>The modified IServiceCollection instance after adding repository services.</returns>
    private static IServiceCollection AddRepositories(this IServiceCollection services)
    {
        services.AddScoped<IAppUserRepository, AppUserRepository>();
        services.AddScoped<IBlacklistedPasswordRepository, BlacklistedPasswordRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IPasswordResetTokenRepository, PasswordResetTokenRepository>();
        services.AddScoped<IEmailTemplateRepository, EmailTemplateRepository>();
        services.AddScoped<IEmailTemplateRenderer, EmailTemplateRenderer>();
        services.AddScoped<IAccountLockoutRepository, AccountLockoutRepository>();
        services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
        services.AddScoped<IMfaMethodRepository, MfaMethodRepository>();
        services.AddScoped<IMfaChallengeRepository, MfaChallengeRepository>();
        services.AddScoped<IMfaEmailCodeRepository, MfaEmailCodeRepository>();
        services.AddScoped<IWebAuthnCredentialRepository, WebAuthnCredentialRepository>();
        services.AddScoped<IMfaPushRepository, MfaPushRepository>();
        services.AddScoped<IPushNotificationProvider, MockPushNotificationProvider>();
        services.AddScoped<IAuditLedgerRepository, AuditLedgerRepository>();
        services.AddScoped<IOrganizationRepository, OrganizationRepository>();

        return services;
    }

    /// <summary>
    /// Registers service layer dependencies to the dependency injection container.
    /// This includes application-specific services, mappers, and utilities required for the application functionality.
    /// </summary>
    /// <param name="services">The IServiceCollection instance where dependencies will be registered.</param>
    /// <returns>The modified IServiceCollection instance with the registered services.</returns>
    private static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddScoped<IUserContext, UserContext>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAppUserMapper, AppUserMapper>();
        services.AddScoped<IPasswordResetEmailService, PasswordResetEmailService>();
        services.AddScoped<IPasswordHasher, BcryptPasswordHasher>();
        services.AddScoped<IPasswordResetService, PasswordResetService>();
        services.AddScoped<IAppUserService, AppUserService>();
        // Development: Logs emails to console. Replace with SendGrid/Postmark/SES for production.
        services.AddScoped<IEmailService, ConsoleEmailService>();
        services.AddScoped<IAccountLockoutService, AccountLockoutService>();
        services.AddScoped<IMfaConfigurationService, MfaConfigurationService>();
        services.AddScoped<IMfaAuthenticationService, MfaAuthenticationService>();
        services.AddScoped<IMfaEmailService, MfaEmailService>();
        services.AddScoped<IMfaEmailAuthenticationService, MfaEmailAuthenticationService>();
        services.AddScoped<IMfaWebAuthnService, MfaWebAuthnService>();
        services.AddScoped<MfaRecoveryCodeService>();
        services.AddScoped<IWebAuthnService, WebAuthnService>();
        services.AddScoped<IFido2>(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = configuration["WebAuthn:ServerDomain"] ?? "localhost",
                ServerName = configuration["WebAuthn:ServerName"] ?? "Starbase Template .NET API",
                Origins = new HashSet<string>(configuration.GetSection("WebAuthn:Origins").Get<string[]>() ?? new[] { "https://localhost" }),
                TimestampDriftTolerance = 300000 // 5 minutes
            };
            return new Fido2(fido2Configuration);
        });
        services.AddScoped<ITotpProvider, TotpProvider>();
        services.AddScoped<IMfaPushService, MfaPushService>();
        services.AddScoped<IAuditLedger, AuditLedgerService>();
        services.AddScoped<ISetupService, SetupService>();

        // Audit archive services
        services.AddScoped<IAuditArchiver, AuditArchiverService>();
        // Development: Writes to local file system. Replace with Azure Blob/S3 for production.
        services.AddScoped<IAuditBlobStorage, FileSystemAuditBlobStorage>();
        services.AddHostedService<AuditArchiveBackgroundService>();

        // MediatR for domain events (auth auditing, extensibility)
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssemblyContaining<AuditQueue>());

        // Audit queue for batched processing mode
        // Singleton: shared across all scopes, background processor consumes from same queue
        services.AddSingleton<IAuditQueue, AuditQueue>();
        services.AddHostedService<AuditQueueProcessor>();

        // Signing key provider for JWT key rotation
        // Cloud providers support automatic rotation; local provider is for development only
        ////#if (UseAzure)
        //services.AddSingleton<ISigningKeyProvider, AzureKeyVaultSigningKeyProvider>();
        ////#elseif (UseAWS)
        //services.AddSingleton<ISigningKeyProvider, AwsSecretsManagerSigningKeyProvider>();
        ////#elseif (UseGCP)
        //services.AddSingleton<ISigningKeyProvider, GcpSecretManagerSigningKeyProvider>();
        ////#else
        services.AddSingleton<ISigningKeyProvider, LocalSigningKeyProvider>();
        ////#endif

        // Background service for automatic key rotation (only active when enabled in config)
        services.AddHostedService<SigningKeyRotationBackgroundService>();

        return services;
    }

    /// <summary>
    /// Registers strongly-typed configuration options with validation and startup configuration binding.
    /// This method configures all application options classes to bind to their respective configuration sections,
    /// validates them using data annotations, and ensures they are validated at application startup.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which options will be added.</param>
    /// <returns>The modified IServiceCollection instance with options configured.</returns>
    private static IServiceCollection AddAppOptions(this IServiceCollection services)
    {
        services.AddOptions<AppOptions>()
            .BindConfiguration("AppSettings")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EmailMfaOptions>()
            .BindConfiguration(EmailMfaOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<PushMfaOptions>()
            .BindConfiguration(PushMfaOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<MfaOptions>()
            .BindConfiguration(MfaOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<WebAuthnOptions>()
            .BindConfiguration(WebAuthnOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<RateLimitingOptions>()
            .BindConfiguration(RateLimitingOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<HealthCheckOptions>()
            .BindConfiguration(HealthCheckOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<AccountLockoutOptions>()
            .BindConfiguration(AccountLockoutOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<CorsOptions>()
            .BindConfiguration(CorsOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<AuditArchiveOptions>()
            .BindConfiguration(AuditArchiveOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<AuditOptions>()
            .BindConfiguration(AuditOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Signing key rotation options (for JWT key rotation)
        services.AddOptions<SigningKeyRotationOptions>()
            .BindConfiguration(SigningKeyRotationOptions.SectionName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        ////#if (UseAzure)
        //services.AddOptions<AzureKeyVaultOptions>()
        //    .BindConfiguration(AzureKeyVaultOptions.SectionName)
        //    .ValidateDataAnnotations()
        //    .ValidateOnStart();
        ////#endif

        ////#if (UseAWS)
        //services.AddOptions<AwsSecretsManagerOptions>()
        //    .BindConfiguration(AwsSecretsManagerOptions.SectionName)
        //    .ValidateDataAnnotations()
        //    .ValidateOnStart();
        ////#endif

        ////#if (UseGCP)
        //services.AddOptions<GcpSecretManagerOptions>()
        //    .BindConfiguration(GcpSecretManagerOptions.SectionName)
        //    .ValidateDataAnnotations()
        //    .ValidateOnStart();
        ////#endif

        return services;
    }

    /// <summary>
    /// Adds custom authorization policies and their associated handlers to the service collection.
    /// This enables fine-grained authorization by configuring policies and associating them with handlers.
    /// </summary>
    /// <param name="services">
    /// The IServiceCollection instance used for registering the authorization policy provider
    /// and policy handlers.
    /// </param>
    /// <returns>The modified IServiceCollection instance.</returns>
    private static IServiceCollection AddAuthorizationPolicies(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationPolicyProvider, PrivilegePolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PrivilegeAuthorizationHandler>();

        return services;
    }

    /// <summary>
    /// Adds and configures the database context and related persistence components, such as the unit of work
    /// and CRUD operators, for dependency injection in the service collection.
    /// The database context is configured with environment-specific options, such as enabling sensitive data
    /// logging in development.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which the database context and persistence components will be added.</param>
    /// <param name="environment">The IHostEnvironment instance that provides information about the application's hosting environment.</param>
    /// <returns>The modified IServiceCollection instance with the registered database and persistence components.</returns>
    private static IServiceCollection AddDbContext(this IServiceCollection services, IHostEnvironment environment)
    {
        // Register the audit interceptor as scoped (each DbContext gets its own instance)
        services.AddScoped<AuditInterceptor>();

        services.AddDbContext<AppDbContext>((sp, options) =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var connectionString = configuration.GetConnectionString("SqlConnection");

            ////#if (UsePostgreSql)
            //options.UseNpgsql(connectionString);
            ////#elseif (UseOracle)
            //options.UseOracle(connectionString);
            ////#else
            options.UseSqlServer(connectionString);
            ////#endif

            // Add audit interceptor for automatic entity change tracking
            var auditInterceptor = sp.GetRequiredService<AuditInterceptor>();
            options.AddInterceptors(auditInterceptor);

            // Only allow sensitive data logging when in development
            if (environment.IsDevelopment())
            {
                options.EnableSensitiveDataLogging();
            }
        });

        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped(typeof(ICrudOperator<>), typeof(CrudOperator<>));

        return services;
    }

    /// <summary>
    /// Registers AutoMapper into the dependency injection container by configuring
    /// and adding the necessary AutoMapper components, including creating a MapperConfiguration
    /// and setting up a scoped instance of IMapper.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which AutoMapper will be added.</param>
    /// <returns>The modified IServiceCollection instance with AutoMapper configured.</returns>
    private static IServiceCollection AddAutoMapper(this IServiceCollection services)
    {
        var automapperConfig = new MapperConfiguration(config =>
        {
            config.AddProfile(new BaseProfile());
        }, new LoggerFactory());

        services.AddScoped(provider => automapperConfig.CreateMapper());

        return services;
    }

    /// <summary>
    /// Configures core infrastructure dependencies required by the application.
    /// This includes services such as HttpContextAccessor and logging.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which core infrastructure dependencies will be registered.</param>
    /// <returns>The modified IServiceCollection instance.</returns>
    private static IServiceCollection AddCoreInfrastructure(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddLogging();

        return services;
    }

    /// <summary>
    /// Registers validation-related services and configurations, enabling dependency injection for validation response factories
    /// and typed validators tailored to specific DTO types.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which validation services will be added.</param>
    /// <returns>The modified IServiceCollection instance.</returns>
    private static IServiceCollection AddValidation(this IServiceCollection services)
    {
        services.AddScoped<IValidationResponseFactory, ProblemDetailsValidationResponseFactory>();
        services.AddTypedValidation<PasswordValidator, string>();
        services.AddTypedValidation<NewUserValidator, CreateNewUserDto>();
        services.AddTypedValidation<UpdateUserValidator, AppUserDto>();

        // MFA Validators
        services.AddTypedValidation<SendEmailCodeValidator, SendEmailCodeDto>();
        services.AddTypedValidation<VerifyEmailCodeValidator, VerifyEmailCodeDto>();
        services.AddTypedValidation<UpdateCredentialNameValidator, UpdateCredentialNameDto>();
        services.AddTypedValidation<SendPushChallengeValidator, SendPushChallengeDto>();
        services.AddTypedValidation<UpdatePushTokenValidator, UpdatePushTokenDto>();

        return services;
    }

    /// <summary>
    /// Registers a strongly-typed validator for a specific data transfer object (DTO) type in the application's dependency injection container.
    /// This method ensures that the specified <typeparamref name="TAbstractValidator"/> and corresponding <typeparamref name="TDto"/> are properly registered
    /// for use within the application's validation pipeline.
    /// </summary>
    /// <typeparam name="TAbstractValidator">The type of the abstract validator to be registered. Must inherit from <see cref="FluentValidation.AbstractValidator{TDto}"/>.</typeparam>
    /// <typeparam name="TDto">The type of the DTO that the validator validates.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> instance to which the validator will be added.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> instance.</returns>
    private static IServiceCollection AddTypedValidation<TAbstractValidator, TDto>(this IServiceCollection services)
        where TAbstractValidator : AbstractValidator<TDto> => services.AddScoped<TAbstractValidator>()
        .AddScoped<IValidator<TDto>, TAbstractValidator>(x => x.GetService<TAbstractValidator>() ?? throw new InvalidOperationException());

    /// <summary>
    /// Configures health checks for monitoring application health and readiness.
    /// Includes database connectivity checks and optional memory monitoring for privileged access.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which health checks will be added.</param>
    /// <param name="configuration">The IConfiguration instance for reading health check settings.</param>
    /// <returns>The modified IServiceCollection instance.</returns>
    private static IServiceCollection AddAppHealthChecks(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<DatabaseHealthCheck>();

        var healthChecksBuilder = services.AddHealthChecks()
            .AddCheck<DatabaseHealthCheck>("database",
                failureStatus: HealthStatus.Unhealthy,
                tags: ["db", "sql", "ready"]);

        // Use strongly-typed configuration instead of raw config values
        var healthCheckOptions = configuration.GetSection(HealthCheckOptions.SectionName).Get<HealthCheckOptions>() ?? new HealthCheckOptions();

        if (healthCheckOptions.IncludeMemoryCheck)
        {
            services.AddScoped<MemoryHealthCheck>();
            healthChecksBuilder.AddCheck<MemoryHealthCheck>("memory",
                failureStatus: HealthStatus.Degraded,
                tags: ["memory", "privileged"]); // Tag as privileged for security
        }

        return services;
    }

    /// <summary>
    /// Configures JWT Bearer authentication with proper security validation and key rotation support.
    /// This method sets up secure JWT token validation including issuer, audience, and signing key validation
    /// to prevent token misuse and security vulnerabilities. Supports validating tokens signed with
    /// multiple keys during key rotation windows.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which JWT authentication will be added.</param>
    /// <param name="configuration">Configuration instance to read JWT settings from</param>
    /// <returns>The modified IServiceCollection instance with JWT authentication configured.</returns>
    private static IServiceCollection AddSecureJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        // Configure JWT Bearer options to use IssuerSigningKeyResolver for multi-key validation
        // This enables seamless key rotation by validating against current and previous keys
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IServiceProvider>((jwtOptions, sp) =>
            {
                var appOptions = configuration.GetSection("AppSettings").Get<AppOptions>();

                if (appOptions == null)
                    throw new InvalidOperationException("AppSettings configuration section not found");
                if (string.IsNullOrEmpty(appOptions.JwtIssuer))
                    throw new InvalidOperationException("JWT issuer is not configured");
                if (string.IsNullOrEmpty(appOptions.JwtAudience))
                    throw new InvalidOperationException("JWT audience is not configured");

                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,

                    // Use IssuerSigningKeyResolver to support multiple valid keys during rotation
                    // This allows tokens signed with previous keys to remain valid during the overlap window
                    IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                    {
                        var keyProvider = sp.GetService<ISigningKeyProvider>();
                        if (keyProvider != null)
                        {
                            // Get all valid keys from the provider (current + previous within overlap window)
                            var keysTask = keyProvider.GetValidationKeysAsync();
                            keysTask.Wait(); // Safe in this context as it's cached
                            return keysTask.Result.Select(k => k.Key);
                        }

                        // Fallback to static key from configuration if no provider registered
                        if (string.IsNullOrEmpty(appOptions.JwtSigningKey))
                            throw new InvalidOperationException("JWT signing key is not configured and no ISigningKeyProvider is registered");

                        return new[] { new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appOptions.JwtSigningKey)) };
                    },

                    // SECURITY: Enable issuer validation to prevent cross-application token attacks
                    ValidateIssuer = true,
                    ValidIssuer = appOptions.JwtIssuer,

                    // SECURITY: Enable audience validation to prevent token misuse
                    ValidateAudience = true,
                    ValidAudience = appOptions.JwtAudience,

                    // Validate token lifetime
                    ValidateLifetime = true,

                    // Zero clock skew for maximum security
                    ClockSkew = TimeSpan.Zero, // No tolerance for clock drift

                    // Ensure tokens have not been tampered with
                    RequireSignedTokens = true,

                    // Ensure the token has an expiration
                    RequireExpirationTime = true
                };
            });

        return services;
    }

    private static IServiceCollection AddOpenTelemetryObservability(this IServiceCollection services, IHostEnvironment environment)
    {
        services.AddOpenTelemetry()
            .WithTracing(tracing =>
            {
                tracing
                    .AddAspNetCoreInstrumentation(options =>
                    {
                        // Don't record request/response bodies - may contain sensitive data
                        options.RecordException = true;
                    })
                    .AddHttpClientInstrumentation(options =>
                    {
                        // Filter sensitive headers from outbound requests
                        options.FilterHttpRequestMessage = request =>
                        {
                            // Don't trace requests to sensitive endpoints
                            var path = request.RequestUri?.AbsolutePath ?? "";
                            return !path.Contains("token", StringComparison.OrdinalIgnoreCase) &&
                                   !path.Contains("auth", StringComparison.OrdinalIgnoreCase);
                        };
                    })
                    .AddSqlClientInstrumentation()
                    .AddSource("StarbaseTemplateAPI")
                    // Add sensitive data processor to sanitize span attributes
                    .AddProcessor(new SensitiveDataActivityProcessor())
                    .AddOtlpExporter();

                if (environment.IsDevelopment())
                {
                    tracing.AddConsoleExporter();
                }
            })
            .WithMetrics(metrics => metrics
                .AddAspNetCoreInstrumentation());

        return services;
    }

    /// <summary>
    /// Configures Cross-Origin Resource Sharing (CORS) based on application settings.
    /// This method reads CORS configuration from appsettings.json and sets up the appropriate
    /// policy with allowed origins, methods, headers, and credentials.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which CORS will be added.</param>
    /// <param name="configuration">The IConfiguration instance for reading CORS settings.</param>
    /// <returns>The modified IServiceCollection instance with CORS configured.</returns>
    public static IServiceCollection AddConfigurableCors(this IServiceCollection services, IConfiguration configuration)
    {
        var corsOptions = configuration.GetSection(CorsOptions.SectionName).Get<CorsOptions>() ?? new CorsOptions();

        if (!corsOptions.Enabled)
        {
            return services;
        }

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                // Configure allowed origins
                if (corsOptions.AllowedOrigins.Length == 0)
                {
                    // No origins configured - deny all cross-origin requests
                    // This is the secure default
                }
                else if (corsOptions.AllowedOrigins.Length == 1 && corsOptions.AllowedOrigins[0] == "*")
                {
                    // Allow any origin (not recommended with credentials)
                    policy.AllowAnyOrigin();
                }
                else
                {
                    policy.WithOrigins(corsOptions.AllowedOrigins);
                }

                // Configure allowed methods
                if (corsOptions.AllowedMethods.Length == 1 && corsOptions.AllowedMethods[0] == "*")
                {
                    policy.AllowAnyMethod();
                }
                else
                {
                    policy.WithMethods(corsOptions.AllowedMethods);
                }

                // Configure allowed headers
                if (corsOptions.AllowedHeaders.Length == 1 && corsOptions.AllowedHeaders[0] == "*")
                {
                    policy.AllowAnyHeader();
                }
                else
                {
                    policy.WithHeaders(corsOptions.AllowedHeaders);
                }

                // Configure exposed headers
                if (corsOptions.ExposedHeaders.Length > 0)
                {
                    policy.WithExposedHeaders(corsOptions.ExposedHeaders);
                }

                // Configure credentials
                // Note: AllowCredentials cannot be used with AllowAnyOrigin
                if (corsOptions.AllowCredentials &&
                    !(corsOptions.AllowedOrigins.Length == 1 && corsOptions.AllowedOrigins[0] == "*"))
                {
                    policy.AllowCredentials();
                }

                // Configure preflight cache
                if (corsOptions.PreflightMaxAgeSeconds > 0)
                {
                    policy.SetPreflightMaxAge(TimeSpan.FromSeconds(corsOptions.PreflightMaxAgeSeconds));
                }
            });
        });

        return services;
    }

    /// <summary>
    /// Configures API versioning for the application.
    /// Uses URL path versioning (e.g., /api/v1/users) with v1 as the default.
    /// Reports available versions in response headers for API discoverability.
    /// </summary>
    /// <param name="services">The IServiceCollection instance to which API versioning will be added.</param>
    /// <returns>The modified IServiceCollection instance with API versioning configured.</returns>
    private static IServiceCollection AddApiVersioningConfiguration(this IServiceCollection services)
    {
        services.AddApiVersioning(options =>
        {
            // Default to v1 when no version is specified
            options.DefaultApiVersion = new ApiVersion(1, 0);
            options.AssumeDefaultVersionWhenUnspecified = true;

            // Report available versions in response headers
            options.ReportApiVersions = true;

            // Read version from URL path segment (e.g., /api/v1/users)
            options.ApiVersionReader = new UrlSegmentApiVersionReader();
        })
        .AddApiExplorer(options =>
        {
            // Format version as 'v'major[.minor] (e.g., v1, v1.1)
            options.GroupNameFormat = "'v'VVV";
            options.SubstituteApiVersionInUrl = true;
        });

        return services;
    }
}
