using Domain.Entities.Security;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework configuration for the AccountLockout entity.
/// Defines database schema, constraints, and indexes for efficient
/// account lockout tracking and management.
/// </summary>
internal class AccountLockoutConfiguration : EntityTypeConfiguration<AccountLockout>
{
    protected override void PerformConfiguration(EntityTypeBuilder<AccountLockout> builder)
    {
        // Table configuration
        builder.ToTable("AccountLockouts", "Security");

        // Primary key
        builder.HasKey(x => x.Id);

        // Properties
        builder.Property(x => x.Id)
            .IsRequired()
            .ValueGeneratedNever(); // Generated in domain logic

        builder.Property(x => x.UserId)
            .IsRequired();

        builder.Property(x => x.FailedAttemptCount)
            .IsRequired()
            .HasDefaultValue(0)
            .IsConcurrencyToken();

        builder.Property(x => x.IsLockedOut)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(x => x.LockedOutAt)
            .IsRequired(false);

        builder.Property(x => x.LockoutExpiresAt)
            .IsRequired(false);

        builder.Property(x => x.LastFailedAttemptAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()"); // SQL Server function

        builder.Property(x => x.CreatedAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()"); // SQL Server function

        builder.Property(x => x.UpdatedAt)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()"); // SQL Server function

        builder.Property(x => x.LockoutReason)
            .HasMaxLength(1000)
            .IsRequired(false);

        builder.Property(x => x.LockedByUserId)
            .IsRequired(false);

        // Unique constraint - one lockout record per user
        builder.HasIndex(x => x.UserId)
            .IsUnique()
            .HasDatabaseName("UX_AccountLockouts_UserId");

        // Index for finding active lockouts
        builder.HasIndex(x => new { x.IsLockedOut, x.LockoutExpiresAt })
            .HasDatabaseName("IX_AccountLockouts_IsLockedOut_LockoutExpiresAt")
            .HasFilter("IsLockedOut = 1");

        // Index for cleanup operations (finding expired lockouts)
        builder.HasIndex(x => x.LockoutExpiresAt)
            .HasDatabaseName("IX_AccountLockouts_LockoutExpiresAt")
            .HasFilter("LockoutExpiresAt IS NOT NULL");

        // Index for auditing locked accounts by administrator
        builder.HasIndex(x => x.LockedByUserId)
            .HasDatabaseName("IX_AccountLockouts_LockedByUserId")
            .HasFilter("LockedByUserId IS NOT NULL");

        // Index for time-based queries
        builder.HasIndex(x => x.LastFailedAttemptAt)
            .HasDatabaseName("IX_AccountLockouts_LastFailedAttemptAt");

        // Foreign key relationships (optional - depends on your domain design)
        // Uncomment if you want to enforce referential integrity
        // builder.HasOne<AppUser>()
        //     .WithOne() // One-to-one relationship
        //     .HasForeignKey<AccountLockout>(x => x.UserId)
        //     .OnDelete(DeleteBehavior.Cascade);

        // builder.HasOne<AppUser>()
        //     .WithMany()
        //     .HasForeignKey(x => x.LockedByUserId)
        //     .OnDelete(DeleteBehavior.SetNull);
    }
}