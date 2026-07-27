using Domain.Entities.Audit;
using Domain.Entities.Configuration;
using Domain.Entities.Email;
using Domain.Entities.Identity;
using Domain.Entities.Security;
using Infrastructure.Persistence.Extensions;
using Infrastructure.Security.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Infrastructure.Persistence;

public class AppDbContext(DbContextOptions<AppDbContext> options, IConfiguration configuration) : DbContext(options)
{
    // Auth Tables
    public DbSet<AppUser> AppUsers { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<Privilege> Privileges { get; set; }
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
    public DbSet<BlacklistedPassword> BlacklistedPasswords { get; set; }

    // Configuration Tables
    public DbSet<EmailTemplate> EmailTemplates { get; set; }

    // Email Tables
    public DbSet<OutboundEmail> OutboundEmails { get; set; }

    // Security Tables
    public DbSet<LoginAttempt> LoginAttempts { get; set; }
    public DbSet<AccountLockout> AccountLockouts { get; set; }
    public DbSet<MfaMethod> MfaMethods { get; set; }
    public DbSet<MfaRecoveryCode> MfaRecoveryCodes { get; set; }
    public DbSet<MfaChallenge> MfaChallenges { get; set; }
    public DbSet<MfaEmailCode> MfaEmailCodes { get; set; }
    public DbSet<WebAuthnCredential> WebAuthnCredentials { get; set; }
    public DbSet<MfaPushDevice> MfaPushDevices { get; set; }
    public DbSet<MfaPushChallenge> MfaPushChallenges { get; set; }

    // App Tables
    public DbSet<Organization> Organizations { get; set; }

    // Audit Tables
    public DbSet<AuditLedgerEntry> AuditLedger { get; set; }
    public DbSet<AuditArchiveManifest> AuditArchiveManifests { get; set; }

    // Model Creating and Configuring
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(GetType().Assembly);

        // Oracle: schemas are database users, so the per-schema layout used by the other providers
        // (Audit/Security/Identity/...) would require a pre-created user per schema. Collapse every
        // table into the single connecting schema instead. This is a runtime provider check (a
        // string compare, so it needs no Oracle-specific package reference) and is a no-op on the
        // other providers, which keep their schemas.
        if (Database.ProviderName == "Oracle.EntityFrameworkCore")
        {
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                entityType.SetSchema(null);

                // Oracle maps long/unbounded strings to NCLOB, which cannot be indexed
                // (ORA-02327). Drop any index whose key includes such a column.
                foreach (var index in entityType.GetIndexes().ToList())
                {
                    var indexesLob = index.Properties.Any(p =>
                        p.ClrType == typeof(string) && p.GetMaxLength() is null or > 2000);
                    if (indexesLob)
                    {
                        entityType.RemoveIndex(index);
                    }
                }
            }
        }
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        base.OnConfiguring(options);

        // Only configure the database provider if not already configured (e.g., by tests)
        if (!options.IsConfigured)
        {
            var connectionString = configuration.GetConnectionString("SqlConnection");

            DatabaseProviderSetup.Configure(options, connectionString);
        }

        options.UseSeeding((context, _) =>
            {
                context.ApplySeedData();
                context.SaveChanges();
            })
            .UseAsyncSeeding(async (context, _, cancellationToken) =>
            {
                await context.ApplySeedDataAsync();
                await context.SaveChangesAsync(cancellationToken);
            });
    }

}
