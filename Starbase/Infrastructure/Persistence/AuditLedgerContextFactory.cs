using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Infrastructure.Persistence;

/// <summary>
/// Creates short-lived <see cref="AppDbContext"/> instances dedicated to audit ledger appends.
/// </summary>
/// <remarks>
/// <para>
/// This deliberately does NOT go through <c>IDbContextFactory&lt;AppDbContext&gt;</c>. Registering
/// both <c>AddDbContext</c> and <c>AddDbContextFactory</c> for the same context type makes them
/// compete over the <c>DbContextOptions&lt;AppDbContext&gt;</c> registration, which could silently
/// strip the audit interceptor off the request-scoped context and disable auditing entirely.
/// Building the options here keeps the two configurations independent.
/// </para>
/// <para>
/// Contexts produced here have NO interceptors attached. That is load-bearing: the request-scoped
/// context runs <see cref="Interceptors.AuditInterceptor"/>, which calls back into the audit ledger
/// on SaveChanges. If the ledger's own writes went through an intercepted context, appending an
/// entry could re-enter the append path and deadlock on its own lock. With no interceptor here,
/// re-entry is impossible by construction rather than by convention.
/// </para>
/// <para>
/// Using a separate context also means an audit append commits ONLY audit rows. The previous
/// implementation shared the request-scoped context, so recording an entry flushed whatever else
/// the caller had pending - committing a business transaction that had not finished yet.
/// </para>
/// </remarks>
public sealed class AuditLedgerContextFactory(IConfiguration configuration)
{
    /// <summary>
    /// Creates a new, unintercepted context for an audit ledger append.
    /// The caller owns the returned instance and must dispose it.
    /// </summary>
    public AppDbContext Create()
    {
        var connectionString = configuration.GetConnectionString("SqlConnection");

        var builder = new DbContextOptionsBuilder<AppDbContext>();

        // No retrying execution strategy: the append path opens explicit transactions (and does its
        // own conflict retry), which a retrying strategy would reject.
        DatabaseProviderSetup.Configure(builder, connectionString, enableRetry: false);

        return new AppDbContext(builder.Options, configuration);
    }
}