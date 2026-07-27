using Infrastructure.Persistence;
using Domain.Entities.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework configuration for the MfaEmailCode entity.
/// Defines database schema, relationships, and constraints for email MFA codes.
/// </summary>
public class MfaEmailCodeConfiguration : IEntityTypeConfiguration<MfaEmailCode>
{
    public void Configure(EntityTypeBuilder<MfaEmailCode> builder)
    {
        builder.ToTable("MfaEmailCodes", "Security");

        // Primary key
        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id)
            .ValueGeneratedNever(); // GUID generated client-side

        // Properties
        builder.Property(e => e.MfaChallengeId)
            .IsRequired();

        builder.Property(e => e.UserId)
            .IsRequired();

        builder.Property(e => e.EmailAddress)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(e => e.HashedCode)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(e => e.IsUsed)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.Property(e => e.SentAt)
            .IsRequired();

        builder.Property(e => e.UsedAt)
            .IsRequired(false);

        builder.Property(e => e.AttemptCount)
            .IsRequired()
            .HasDefaultValue(0);

        builder.Property(e => e.IpAddress)
            .IsRequired(false)
            .HasMaxLength(45); // IPv6 max length

        // Indexes
        builder.HasIndex(e => e.MfaChallengeId)
            .HasDatabaseName("IX_MfaEmailCodes_ChallengeId");

        builder.HasIndex(e => e.UserId)
            .HasDatabaseName("IX_MfaEmailCodes_UserId");

        builder.HasIndex(e => new { e.UserId, e.IsUsed, e.ExpiresAt })
            .HasDatabaseName("IX_MfaEmailCodes_User_Status");

        builder.HasIndex(e => e.ExpiresAt)
            .HasDatabaseName("IX_MfaEmailCodes_ExpiresAt")
            .SqlServerFilter("[IsUsed] = 0"); // Only index non-used codes

        // Relationships
        builder.HasOne(e => e.Challenge)
            .WithMany()
            .HasForeignKey(e => e.MfaChallengeId)
            .OnDelete(DeleteBehavior.Cascade);

        // User relationship without cascade to avoid circular paths
        builder.HasOne<Domain.Entities.Identity.AppUser>()
            .WithMany()
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.NoAction);
    }
}
