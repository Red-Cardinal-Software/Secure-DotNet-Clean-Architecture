using Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace WebApi.Integration.Tests.Fixtures;

/// <summary>
/// WebApplicationFactory configured with strict rate limiting for testing rate limit behavior.
/// </summary>
internal class RateLimitedWebApplicationFactory(SqlServerContainerFixture dbFixture)
    : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseSerilog((_, config) =>
        {
            config.MinimumLevel.Warning();
        });

        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SqlConnection"] = dbFixture.ConnectionString,
                // Configure strict rate limits for testing
                ["RateLimiting:Auth:PermitLimit"] = "3",
                ["RateLimiting:Auth:WindowMinutes"] = "1",
                ["RateLimiting:Api:PermitLimit"] = "5",
                ["RateLimiting:Api:WindowMinutes"] = "1",
                ["RateLimiting:Global:PermitLimit"] = "10",
                ["RateLimiting:Global:WindowMinutes"] = "1"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<AppDbContext>();

            services.AddDbContext<AppDbContext>((sp, options) =>
            {
                var configuration = sp.GetRequiredService<IConfiguration>();
                var connectionString = configuration.GetConnectionString("SqlConnection");
                DatabaseProviderSetup.Configure(options, connectionString);
            });
        });

        builder.UseEnvironment("Testing");
    }
}