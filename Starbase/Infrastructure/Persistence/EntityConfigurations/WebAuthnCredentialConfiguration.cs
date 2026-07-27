using Infrastructure.Persistence;
using Domain.Entities.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System.Text.Json;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// Entity Framework configuration for the WebAuthnCredential entity.
/// Defines database schema, relationships, and constraints for WebAuthn credentials.
/// </summary>
public class WebAuthnCredentialConfiguration : IEntityTypeConfiguration<WebAuthnCredential>
{
    public void Configure(EntityTypeBuilder<WebAuthnCredential> builder)
    {
        builder.ToTable("WebAuthnCredentials", "Security");

        // Primary key
        builder.HasKey(w => w.Id);
        builder.Property(w => w.Id)
            .ValueGeneratedNever(); // GUID generated client-side

        // Properties
        builder.Property(w => w.MfaMethodId)
            .IsRequired();

        builder.Property(w => w.UserId)
            .IsRequired();

        builder.Property(w => w.CredentialId)
            .IsRequired()
            .HasMaxLength(512); // Base64URL can be quite long

        builder.Property(w => w.PublicKey)
            .IsRequired()
            .HasMaxLength(2048); // Public keys can be large

        builder.Property(w => w.SignCount)
            .IsRequired()
            .HasDefaultValue(0u);

        builder.Property(w => w.AuthenticatorType)
            .IsRequired()
            .HasConversion<int>();

        // Store transport array as JSON
        builder.Property(w => w.Transports)
            .HasConversion(
                v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                v => JsonSerializer.Deserialize<AuthenticatorTransport[]>(v, (JsonSerializerOptions?)null) ?? Array.Empty<AuthenticatorTransport>());
        // Column type is provider-specific.
        //#if (UsePostgreSql)
        builder.Property(w => w.Transports).HasColumnType("text");
        //#elseif (UseOracle)
        builder.Property(w => w.Transports).HasColumnType("CLOB");
        //#else
        builder.Property(w => w.Transports).HasColumnType("nvarchar(max)");
        //#endif

        builder.Property(w => w.SupportsUserVerification)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(w => w.Name)
            .HasMaxLength(100);

        builder.Property(w => w.AttestationType)
            .HasMaxLength(50);

        builder.Property(w => w.Aaguid)
            .HasMaxLength(36); // GUID format

        builder.Property(w => w.CreatedAt)
            .IsRequired();

        builder.Property(w => w.LastUsedAt);

        builder.Property(w => w.IsActive)
            .IsRequired()
            .HasDefaultValue(true);

        builder.Property(w => w.RegistrationIpAddress)
            .HasMaxLength(45); // IPv6 max length

        builder.Property(w => w.RegistrationUserAgent)
            .HasMaxLength(512);

        // Indexes
        builder.HasIndex(w => w.CredentialId)
            .IsUnique()
            .HasDatabaseName("IX_WebAuthnCredentials_CredentialId");

        builder.HasIndex(w => w.MfaMethodId)
            .HasDatabaseName("IX_WebAuthnCredentials_MfaMethodId");

        builder.HasIndex(w => w.UserId)
            .HasDatabaseName("IX_WebAuthnCredentials_UserId");

        builder.HasIndex(w => new { w.UserId, w.IsActive })
            .HasDatabaseName("IX_WebAuthnCredentials_User_Active");

        builder.HasIndex(w => w.LastUsedAt)
            .HasDatabaseName("IX_WebAuthnCredentials_LastUsed")
            .SqlServerFilter("[LastUsedAt] IS NOT NULL");

        // Relationships
        builder.HasOne(w => w.MfaMethod)
            .WithMany()
            .HasForeignKey(w => w.MfaMethodId)
            .OnDelete(DeleteBehavior.Cascade);

        // User relationship without cascade to avoid circular paths
        builder.HasOne<Domain.Entities.Identity.AppUser>()
            .WithMany()
            .HasForeignKey(w => w.UserId)
            .OnDelete(DeleteBehavior.NoAction);
    }
}
