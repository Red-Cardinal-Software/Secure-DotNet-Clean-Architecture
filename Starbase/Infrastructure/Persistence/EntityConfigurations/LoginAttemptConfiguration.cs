using Infrastructure.Persistence;
using Domain.Entities.Security;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework configuration for the LoginAttempt entity.
/// Defines database schema, constraints, and indexes for optimal query performance
/// and data integrity of login attempt tracking.
/// </summary>
internal class LoginAttemptConfiguration : EntityTypeConfiguration<LoginAttempt>
{
    protected override void PerformConfiguration(EntityTypeBuilder<LoginAttempt> builder)
    {
        // Table configuration
        builder.ToTable("LoginAttempts", "Security");

        // Primary key
        builder.HasKey(x => x.Id);

        // Properties
        builder.Property(x => x.Id)
            .IsRequired()
            .ValueGeneratedNever(); // Generated in domain logic

        builder.Property(x => x.UserId)
            .IsRequired();

        builder.Property(x => x.AttemptedUsername)
            .IsRequired()
            .HasMaxLength(255)
            .HasConversion(
                v => v.ToLowerInvariant(), // Store usernames in lowercase for consistency
                v => v);

        builder.Property(x => x.IpAddress)
            .HasMaxLength(45) // IPv6 max length
            .IsRequired(false);

        builder.Property(x => x.UserAgent)
            .HasMaxLength(1000)
            .IsRequired(false);

        builder.Property(x => x.IsSuccessful)
            .IsRequired();

        builder.Property(x => x.FailureReason)
            .HasMaxLength(500)
            .IsRequired(false);

        builder.Property(x => x.AttemptedAt)
            .IsRequired();
        // UTC "now" default is provider-specific SQL.
        //#if (UsePostgreSql)
        builder.Property(x => x.AttemptedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
        //#elseif (UseOracle)
        builder.Property(x => x.AttemptedAt).HasDefaultValueSql("SYS_EXTRACT_UTC(SYSTIMESTAMP)");
        //#else
        builder.Property(x => x.AttemptedAt).HasDefaultValueSql("GETUTCDATE()");
        //#endif

        builder.Property(x => x.Metadata)
            .HasMaxLength(4000) // Large enough for JSON metadata
            .IsRequired(false);

        // Indexes for query performance
        // Index on UserId for efficient user-specific queries
        builder.HasIndex(x => x.UserId)
            .HasDatabaseName("IX_LoginAttempts_UserId");

        // Index on AttemptedAt for time-based queries and cleanup
        builder.HasIndex(x => x.AttemptedAt)
            .HasDatabaseName("IX_LoginAttempts_AttemptedAt");

        // Composite index for failed attempts by user within timeframe
        builder.HasIndex(x => new { x.UserId, x.IsSuccessful, x.AttemptedAt })
            .HasDatabaseName("IX_LoginAttempts_UserId_IsSuccessful_AttemptedAt")
            .SqlServerFilter("IsSuccessful = 0"); // Only index failed attempts for efficiency

        // Index on IP address for security monitoring
        builder.HasIndex(x => x.IpAddress)
            .HasDatabaseName("IX_LoginAttempts_IpAddress")
            .SqlServerFilter("IpAddress IS NOT NULL");

        // Index on attempted username for auditing and analysis
        builder.HasIndex(x => x.AttemptedUsername)
            .HasDatabaseName("IX_LoginAttempts_AttemptedUsername");

        // Composite index for IP-based failed attempt tracking
        builder.HasIndex(x => new { x.IpAddress, x.IsSuccessful, x.AttemptedAt })
            .HasDatabaseName("IX_LoginAttempts_IpAddress_IsSuccessful_AttemptedAt")
            .SqlServerFilter("IpAddress IS NOT NULL AND IsSuccessful = 0");

        // Foreign key relationship (optional - depends on your domain design)
        // Uncomment if you want to enforce referential integrity
        // builder.HasOne<AppUser>()
        //     .WithMany()
        //     .HasForeignKey(x => x.UserId)
        //     .OnDelete(DeleteBehavior.Cascade);
    }
}