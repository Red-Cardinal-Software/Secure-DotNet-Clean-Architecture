using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

/// <summary>
/// Oracle variant of the provider setup. Ships as a .cs.pp file (not compiled in the template
/// source); the template renames it to DatabaseProviderSetup.cs when DatabaseProvider is Oracle.
/// See the SqlServer variant for the full explanation.
/// </summary>
public static class DatabaseProviderSetup
{
    public static void Configure(DbContextOptionsBuilder options, string? connectionString, bool enableRetry = false)
    {
        // The Oracle EF provider has no retrying execution strategy, so enableRetry is accepted for
        // a uniform signature but not applied.
        _ = enableRetry;
        options.UseOracle(connectionString, oracleOptions =>
        {
            oracleOptions.CommandTimeout(30);
        });
    }
}
