using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

/// <summary>
/// PostgreSQL variant of the provider setup. Ships as a .cs.pp file (not compiled in the template
/// source); the template renames it to DatabaseProviderSetup.cs when DatabaseProvider is PostgreSQL.
/// See the SqlServer variant for the full explanation.
/// </summary>
public static class DatabaseProviderSetup
{
    public static void Configure(DbContextOptionsBuilder options, string? connectionString, bool enableRetry = false)
    {
        options.UseNpgsql(connectionString, npgsqlOptions =>
        {
            if (enableRetry)
            {
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorCodesToAdd: null);
            }
        });
    }
}
