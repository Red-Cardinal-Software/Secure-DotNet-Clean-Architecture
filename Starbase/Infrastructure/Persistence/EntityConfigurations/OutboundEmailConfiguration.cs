using Domain.Entities.Email;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

internal class OutboundEmailConfiguration : EntityTypeConfiguration<OutboundEmail>
{
    protected override void PerformConfiguration(EntityTypeBuilder<OutboundEmail> builder)
    {
        builder.ToTable("OutboundEmails", "Email");

        builder.Property(e => e.To)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(e => e.Subject)
            .IsRequired()
            .HasMaxLength(500);

        builder.Property(e => e.HtmlBody)
            .IsRequired();

        builder.Property(e => e.TextBody);

        builder.Property(e => e.TemplateKey)
            .HasMaxLength(100);

        builder.Property(e => e.Status)
            .IsRequired()
            .HasConversion<int>();

        builder.Property(e => e.Attempts)
            .IsRequired()
            .HasDefaultValue(0);

        builder.Property(e => e.MaxAttempts)
            .IsRequired()
            .HasDefaultValue(3);

        builder.Property(e => e.NextAttemptAt);

        builder.Property(e => e.ErrorMessage)
            .HasMaxLength(2000);

        builder.Property(e => e.ProviderMessageId)
            .HasMaxLength(256);

        builder.Property(e => e.SentAt);

        builder.Property(e => e.CreatedAt)
            .IsRequired();

        builder.Property(e => e.OrganizationId);

        builder.Property(e => e.CorrelationId)
            .HasMaxLength(100);

        builder.Property(e => e.Priority)
            .IsRequired()
            .HasDefaultValue(10);

        // Index for queue processing: pending emails ready for delivery
        builder.HasIndex(e => new { e.Status, e.NextAttemptAt, e.Priority })
            .HasDatabaseName("IX_OutboundEmails_Queue")
            .HasFilter("[Status] = 0"); // Pending only

        // Index for finding emails by status
        builder.HasIndex(e => e.Status)
            .HasDatabaseName("IX_OutboundEmails_Status");

        // Index for correlation ID lookups
        builder.HasIndex(e => e.CorrelationId)
            .HasDatabaseName("IX_OutboundEmails_CorrelationId")
            .HasFilter("[CorrelationId] IS NOT NULL");

        // Index for organization-specific queries
        builder.HasIndex(e => e.OrganizationId)
            .HasDatabaseName("IX_OutboundEmails_OrganizationId")
            .HasFilter("[OrganizationId] IS NOT NULL");

        // Index for cleanup of old sent/failed emails
        builder.HasIndex(e => new { e.Status, e.CreatedAt })
            .HasDatabaseName("IX_OutboundEmails_Cleanup");
    }
}