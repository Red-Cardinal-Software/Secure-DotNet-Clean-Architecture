using Infrastructure.Persistence;
using Domain.Entities.Security;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework Core configuration for the MfaMethod entity.
/// </summary>
internal class MfaMethodConfiguration : EntityTypeConfiguration<MfaMethod>
{
    protected override void PerformConfiguration(EntityTypeBuilder<MfaMethod> builder)
    {
        // Table configuration
        builder.ToTable("MfaMethods", "Security");

        // Primary key
        builder.HasKey(m => m.Id);
        builder.Property(m => m.Id)
            .ValueGeneratedNever(); // GUID generated client-side

        // Properties
        builder.Property(m => m.UserId)
            .IsRequired();

        builder.Property(m => m.Type)
            .IsRequired()
            .HasConversion<int>();

        builder.Property(m => m.Secret)
            .HasMaxLength(500)
            .IsRequired(false); // Some MFA types don't need secrets

        builder.Property(m => m.Metadata)
            .HasMaxLength(2000)
            .IsRequired(false);

        builder.Property(m => m.Name)
            .HasMaxLength(100)
            .IsRequired(false);

        builder.Property(m => m.IsEnabled)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(m => m.IsDefault)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(m => m.CreatedAt)
            .IsRequired();

        builder.Property(m => m.VerifiedAt)
            .IsRequired(false);

        builder.Property(m => m.LastUsedAt)
            .IsRequired(false);

        builder.Property(m => m.UpdatedAt)
            .IsRequired();

        // Indexes
        builder.HasIndex(m => m.UserId)
            .HasDatabaseName("IX_MfaMethods_UserId");

        builder.HasIndex(m => new { m.UserId, m.Type })
            .HasDatabaseName("IX_MfaMethods_UserId_Type");

        builder.HasIndex(m => new { m.UserId, m.IsEnabled })
            .HasDatabaseName("IX_MfaMethods_UserId_IsEnabled");

        builder.HasIndex(m => new { m.UserId, m.IsDefault })
            .HasDatabaseName("IX_MfaMethods_UserId_IsDefault")
            .SqlServerFilter("[IsDefault] = 1"); // Partial index for performance

        // Relationships
        builder.HasOne(m => m.User)
            .WithMany()
            .HasForeignKey(m => m.UserId)
            .OnDelete(DeleteBehavior.NoAction);

        builder.HasMany(m => m.RecoveryCodes)
            .WithOne(r => r.MfaMethod)
            .HasForeignKey(r => r.MfaMethodId)
            .OnDelete(DeleteBehavior.Cascade);

        // Constraints
        // Ensure only one default MFA method per user (handled in domain logic)
    }
}
