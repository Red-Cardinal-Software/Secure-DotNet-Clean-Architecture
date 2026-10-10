using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence;

/// <summary>
/// PostgreSQL variant: filtered-index predicates are SQL Server T-SQL and are not portable, so this
/// is a no-op that yields a plain index. Ships via template rename when DatabaseProvider is PostgreSQL.
/// </summary>
internal static class IndexBuilderExtensions
{
    public static IndexBuilder SqlServerFilter(this IndexBuilder index, string filter)
        => index;
}
