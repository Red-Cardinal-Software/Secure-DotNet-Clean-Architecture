using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Application.DTOs.Email;
using Application.Interfaces.Providers;
using Application.Interfaces.Services;
using Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Serilog;

namespace WebApi.Integration.Tests.Fixtures;

/// <summary>
/// A test email service that captures sent emails and verification codes for testing.
/// Codes can be retrieved via GetLastCodeForEmail() to verify MFA flows.
/// </summary>
internal partial class TestEmailService : IEmailService
{
    // Static storage so codes persist across scoped instances
    private static readonly ConcurrentDictionary<string, string> LastCodes = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, RenderedEmail> LastEmails = new(StringComparer.OrdinalIgnoreCase);

    public Task SendEmailAsync(string to, RenderedEmail email)
    {
        LastEmails[to] = email;

        // Try to extract verification code from email body
        // Pattern matches: "Your verification code is: <strong>12345678</strong>"
        var match = VerificationCodeRegex().Match(email.Body ?? "");
        if (match.Success)
        {
            LastCodes[to] = match.Groups[1].Value;
        }

        return Task.CompletedTask;
    }

    public Task SendMfaVerificationCodeAsync(string to, string verificationCode, int expiresInMinutes, string appName, CancellationToken cancellationToken = default)
    {
        LastCodes[to] = verificationCode;
        return Task.CompletedTask;
    }

    public Task SendMfaSetupVerificationCodeAsync(string to, string verificationCode, int expiresInMinutes, string appName, CancellationToken cancellationToken = default)
    {
        LastCodes[to] = verificationCode;
        return Task.CompletedTask;
    }

    public Task SendMfaSecurityNotificationAsync(string to, string eventType, string eventDetails, DateTimeOffset timestamp, string? ipAddress, string appName, CancellationToken cancellationToken = default) => Task.CompletedTask;

    /// <summary>
    /// Gets the last verification code sent to the specified email address.
    /// </summary>
    public static string? GetLastCodeForEmail(string email) =>
        LastCodes.TryGetValue(email, out var code) ? code : null;

    /// <summary>
    /// Gets the last email sent to the specified address.
    /// </summary>
    public static RenderedEmail? GetLastEmailForAddress(string email) =>
        LastEmails.TryGetValue(email, out var renderedEmail) ? renderedEmail : null;

    /// <summary>
    /// Clears all captured codes and emails. Call between tests if needed.
    /// </summary>
    public static void ClearAll()
    {
        LastCodes.Clear();
        LastEmails.Clear();
    }

    [GeneratedRegex(@"verification code is:\s*<strong>(\d+)</strong>", RegexOptions.IgnoreCase)]
    private static partial Regex VerificationCodeRegex();
}

/// <summary>
/// A no-op password reset email service for integration tests.
/// </summary>
internal class TestPasswordResetEmailService : IPasswordResetEmailService
{
    public Task SendPasswordResetEmail(Domain.Entities.Identity.AppUser user, Domain.Entities.Identity.PasswordResetToken token) => Task.CompletedTask;
}

/// <summary>
/// A test push notification provider that accepts all requests and validates all tokens.
/// </summary>
internal class TestPushNotificationProvider : IPushNotificationProvider
{
    public string ProviderName => "TestProvider";

    public Task<bool> SendPushNotificationAsync(
        string pushToken,
        string title,
        string body,
        Dictionary<string, string> data,
        CancellationToken cancellationToken = default) => Task.FromResult(true);

    public bool ValidatePushToken(string pushToken, string platform) =>
        !string.IsNullOrWhiteSpace(pushToken) && !string.IsNullOrWhiteSpace(platform);
}

/// <summary>
/// Custom WebApplicationFactory that configures the application to use the SQL Server test container.
/// </summary>
internal class IntegrationTestWebApplicationFactory(SqlServerContainerFixture dbFixture)
    : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Override configuration for testing
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SqlConnection"] = dbFixture.ConnectionString,
                // Disable rate limiting for tests by setting high limits
                ["RateLimiting:Auth:PermitLimit"] = "10000",
                ["RateLimiting:Auth:WindowMinutes"] = "1",
                ["RateLimiting:Api:PermitLimit"] = "10000",
                ["RateLimiting:Global:PermitLimit"] = "10000",
                ["RateLimiting:PasswordReset:PermitLimit"] = "10000",
                ["RateLimiting:PasswordReset:WindowMinutes"] = "1",
                ["RateLimiting:MfaSetup:PermitLimit"] = "10000",
                ["RateLimiting:MfaSetup:WindowMinutes"] = "1"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Remove the existing DbContext registration
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<AppDbContext>();

            // Add DbContext with the test container's connection string
            services.AddDbContext<AppDbContext>((sp, options) =>
            {
                var configuration = sp.GetRequiredService<IConfiguration>();
                var connectionString = configuration.GetConnectionString("SqlConnection");
                DatabaseProviderSetup.Configure(options, connectionString);
            });

            // Replace email services with no-op test implementations
            services.RemoveAll<IEmailService>();
            services.AddScoped<IEmailService, TestEmailService>();

            services.RemoveAll<IPasswordResetEmailService>();
            services.AddScoped<IPasswordResetEmailService, TestPasswordResetEmailService>();

            // Replace push notification provider with test implementation
            services.RemoveAll<IPushNotificationProvider>();
            services.AddScoped<IPushNotificationProvider, TestPushNotificationProvider>();

            // Replace audit blob storage with test implementation
            services.RemoveAll<IAuditBlobStorage>();
            services.AddScoped<IAuditBlobStorage, TestAuditBlobStorage>();
        });

        builder.UseEnvironment("Testing");
    }

    /// <summary>
    /// Ensures the database is created and migrations are applied.
    /// Call this after creating the factory.
    /// </summary>
    public async Task InitializeDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
    }
}