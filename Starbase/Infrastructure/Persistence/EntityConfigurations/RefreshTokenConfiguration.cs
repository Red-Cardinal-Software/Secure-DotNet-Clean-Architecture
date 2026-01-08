using Domain.Entities.Identity;
using Infrastructure.Persistence.EntityConfigurations.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfigurations;

internal class RefreshTokenConfiguration : EntityTypeConfiguration<RefreshToken>
{
    protected override void PerformConfiguration(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens", "Identity");

        builder.Property(x => x.CreatedByIp).IsRequired().HasMaxLength(50);
        builder.Property(x => x.ReplacedBy)
            .HasMaxLength(50)
            .IsConcurrencyToken();
    }
}
