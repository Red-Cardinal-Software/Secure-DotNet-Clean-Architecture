using Domain.Entities.Security;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework Core configuration for the MfaChallenge entity.
/// </summary>
internal class MfaChallengeConfiguration : EntityTypeConfiguration<MfaChallenge>
{
    protected override void PerformConfiguration(EntityTypeBuilder<MfaChallenge> builder)
    {
        // Table configuration
        builder.ToTable("MfaChallenges", "Security");

        // Primary key
        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id)
            .ValueGeneratedNever();

        // Properties
        builder.Property(c => c.UserId)
            .IsRequired();

        builder.Property(c => c.ChallengeToken)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(c => c.Type)
            .IsRequired()
            .HasConversion<int>();

        builder.Property(c => c.MfaMethodId)
            .IsRequired(false);

        builder.Property(c => c.IsCompleted)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(c => c.IsInvalid)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(c => c.AttemptCount)
            .IsRequired()
            .HasDefaultValue(0)
            .IsConcurrencyToken();

        builder.Property(c => c.IpAddress)
            .HasMaxLength(45) // IPv6 length
            .IsRequired(false);

        builder.Property(c => c.UserAgent)
            .HasMaxLength(500)
            .IsRequired(false);

        builder.Property(c => c.Metadata)
            .HasMaxLength(1000)
            .IsRequired(false);

        builder.Property(c => c.CreatedAt)
            .IsRequired();

        builder.Property(c => c.ExpiresAt)
            .IsRequired();

        builder.Property(c => c.CompletedAt)
            .IsRequired(false);

        builder.Property(c => c.LastAttemptAt)
            .IsRequired(false);

        // Indexes
        builder.HasIndex(c => c.UserId)
            .HasDatabaseName("IX_MfaChallenges_UserId");

        builder.HasIndex(c => c.ChallengeToken)
            .HasDatabaseName("IX_MfaChallenges_ChallengeToken")
            .IsUnique();

        builder.HasIndex(c => new { c.UserId, c.IsCompleted })
            .HasDatabaseName("IX_MfaChallenges_UserId_IsCompleted");

        builder.HasIndex(c => c.ExpiresAt)
            .HasDatabaseName("IX_MfaChallenges_ExpiresAt");

        builder.HasIndex(c => c.CreatedAt)
            .HasDatabaseName("IX_MfaChallenges_CreatedAt");

        // Relationships
        builder.HasOne<Domain.Entities.Identity.AppUser>()
            .WithMany()
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.NoAction);

        builder.HasOne<MfaMethod>()
            .WithMany()
            .HasForeignKey(c => c.MfaMethodId)
            .OnDelete(DeleteBehavior.NoAction)
            .IsRequired(false);
    }
}
