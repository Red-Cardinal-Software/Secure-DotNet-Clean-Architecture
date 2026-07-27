using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence;

/// <summary>
/// Applies SQL Server filtered-index predicates. The predicates use T-SQL syntax
/// (bracket-quoted identifiers, <c>= 0</c>/<c>= 1</c> for bit columns) that is not portable, so on
/// PostgreSQL and Oracle the template swaps this file (via <c>.cs.pp</c> variants) for a no-op that
/// produces a plain, unfiltered index. Keeping the SqlServer version as the source default means the
/// SQL Server model still matches its existing (filtered-index) migrations.
/// </summary>
internal static class IndexBuilderExtensions
{
    public static IndexBuilder SqlServerFilter(this IndexBuilder index, string filter)
        => index.HasFilter(filter);
}
