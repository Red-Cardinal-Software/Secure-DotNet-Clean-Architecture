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
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        base.OnConfiguring(options);

        // Only configure the database provider if not already configured (e.g., by tests)
        if (!options.IsConfigured)
        {
            var connectionString = configuration.GetConnectionString("SqlConnection");

            ////#if (UsePostgreSql)
            //options.UseNpgsql(connectionString, npgsqlOptions =>
            //{
            //    npgsqlOptions.EnableRetryOnFailure(
            //        maxRetryCount: 3,
            //        maxRetryDelay: TimeSpan.FromSeconds(5),
            //        errorCodesToAdd: null);
            //});
            ////#elseif (UseOracle)
            //options.UseOracle(connectionString, oracleOptions =>
            //{
            //    oracleOptions.CommandTimeout(30);
            //});
            ////#else
            options.UseSqlServer(connectionString, sqlOptions =>
            {
                sqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorNumbersToAdd: null);
            });
            ////#endif
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
