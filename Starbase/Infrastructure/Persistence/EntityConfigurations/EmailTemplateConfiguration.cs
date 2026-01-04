using Domain.Entities.Configuration;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

internal class EmailTemplateConfiguration : EntityTypeConfiguration<EmailTemplate>
{
    protected override void PerformConfiguration(EntityTypeBuilder<EmailTemplate> builder)
    {
        builder.ToTable("EmailTemplates", "Configuration");

        builder.Property(e => e.Key)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(e => e.Subject)
            .IsRequired()
            .HasMaxLength(500);

        builder.Property(e => e.HtmlBody)
            .IsRequired();

        builder.Property(e => e.TextBody);

        builder.Property(e => e.LayoutKey)
            .HasMaxLength(100);

        builder.Property(e => e.IsActive)
            .IsRequired()
            .HasDefaultValue(true);

        builder.Property(e => e.CreatedAt)
            .IsRequired();

        builder.Property(e => e.ModifiedAt);

        // Unique constraint: Key + OrganizationId combination must be unique
        // This allows same key for different orgs, and one global (null org) template per key
        builder.HasIndex(e => new { e.Key, e.OrganizationId })
            .IsUnique()
            .HasDatabaseName("IX_EmailTemplates_Key_OrganizationId");

        // Index for fast lookups by key
        builder.HasIndex(e => e.Key)
            .HasDatabaseName("IX_EmailTemplates_Key");

        // Index for organization-specific queries
        builder.HasIndex(e => e.OrganizationId)
            .HasDatabaseName("IX_EmailTemplates_OrganizationId");

        // Relationship to Organization
        builder.HasOne(e => e.Organization)
            .WithMany()
            .HasForeignKey(e => e.OrganizationId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}