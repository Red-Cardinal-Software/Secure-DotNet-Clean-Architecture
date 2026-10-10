using Domain.Entities.Audit;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

/// <summary>
/// EF Core configuration for the AuditArchiveManifest entity.
/// Tracks archived audit partitions for compliance chain of custody.
/// </summary>
internal class AuditArchiveManifestConfiguration : EntityTypeConfiguration<AuditArchiveManifest>
{
    protected override void PerformConfiguration(EntityTypeBuilder<AuditArchiveManifest> builder)
    {
        builder.ToTable("AuditArchiveManifest", "Audit");

        builder.HasKey(e => e.Id);

        // Partition identification
        ////#if (UsePostgreSql)
        //builder.Property(e => e.PartitionBoundary)
        //    .IsRequired()
        //    .HasColumnType("timestamp without time zone");
        ////#else
        builder.Property(e => e.PartitionBoundary)
            .IsRequired();
        ////#endif
        builder.HasIndex(e => e.PartitionBoundary)
            .IsUnique();

        // Sequence range
        builder.Property(e => e.FirstSequenceNumber)
            .IsRequired();

        builder.Property(e => e.LastSequenceNumber)
            .IsRequired();

        builder.Property(e => e.RecordCount)
            .IsRequired();

        // Hash chain endpoints for verification
        builder.Property(e => e.FirstRecordHash)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.LastRecordHash)
            .IsRequired()
            .HasMaxLength(64);

        // SQL Server Ledger digest (JSON structure)
        //#if (UsePostgreSql)
        builder.Property(e => e.LedgerDigest)
            .IsRequired()
            .HasColumnType("text");
        //#elseif (UseOracle)
        builder.Property(e => e.LedgerDigest)
            .IsRequired()
            .HasColumnType("CLOB");
        //#else
        builder.Property(e => e.LedgerDigest)
            .IsRequired()
            .HasColumnType("nvarchar(max)");
        //#endif

        // Archive location and integrity
        builder.Property(e => e.ArchiveUri)
            .IsRequired()
            .HasMaxLength(2048);

        builder.Property(e => e.ArchiveBlobHash)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.ArchiveSizeBytes)
            .IsRequired();

        // Audit trail
        builder.Property(e => e.ArchivedAt)
            .IsRequired();

        builder.Property(e => e.ArchivedBy)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(e => e.PurgedAt);

        builder.Property(e => e.RetentionPolicy)
            .HasMaxLength(128);
    }
}