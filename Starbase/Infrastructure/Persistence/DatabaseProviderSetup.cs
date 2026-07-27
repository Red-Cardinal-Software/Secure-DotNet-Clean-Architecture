using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

/// <summary>
/// Single point where the EF Core database provider is configured.
/// </summary>
/// <remarks>
/// The provider is chosen by the <c>DatabaseProvider</c> template switch. This SqlServer version
/// ships as <c>DatabaseProviderSetup.cs</c>; the PostgreSQL and Oracle versions ship as
/// <c>DatabaseProviderSetup.PostgreSql.cs.pp</c> / <c>.Oracle.cs.pp</c> and the template renames the
/// chosen one into place (excluding the others). Because only one variant compiles, exactly one
/// provider is ever registered - which is why this is a file swap rather than in-code conditionals
/// (those would either leave every provider's <c>UseX</c> call live at once, or rely on the
/// template engine's non-functional uncomment feature).
/// </remarks>
public static class DatabaseProviderSetup
{
    /// <param name="enableRetry">
    /// Off by default because several paths (the audit ledger append, the blacklisted-password
    /// seeder) open explicit transactions, which a retrying execution strategy rejects. Opt in only
    /// for contexts that never start a transaction manually.
    /// </param>
    public static void Configure(DbContextOptionsBuilder options, string? connectionString, bool enableRetry = false)
    {
        options.UseSqlServer(connectionString, sqlOptions =>
        {
            if (enableRetry)
            {
                sqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorNumbersToAdd: null);
            }
        });
    }
}
