using Domain.Entities.Audit;

namespace Application.Interfaces.Repositories;

/// <summary>
/// Repository for audit ledger entries.
/// Provides append-only operations with hash chain integrity.
/// </summary>
public interface IAuditLedgerRepository
{
    /// <summary>
    /// Atomically appends a batch of entries to the tail of the ledger.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reading the tail (sequence number + hash) and inserting the new entries happens inside a
    /// single serializable transaction on a dedicated connection, so the read-then-write cannot
    /// interleave with a concurrent append - including one from another process or replica. This
    /// replaces the previous <c>GetNextSequenceNumberAsync</c> / <c>GetLastHashAsync</c> /
    /// <c>AppendAsync</c> trio, which was a non-atomic read-modify-write guarded only by an
    /// in-process lock and therefore forked the hash chain when scaled horizontally.
    /// </para>
    /// <para>
    /// The transaction commits only ledger rows; it never flushes the caller's unit of work.
    /// </para>
    /// </remarks>
    /// <param name="buildEntries">
    /// Builds the entries to append, given the sequence number the first entry must take and the
    /// hash of the current tail (or the genesis hash if the ledger is empty). This runs inside the
    /// transaction and may be invoked more than once if the append is retried after a conflict, so
    /// it must be free of side effects.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The entries as appended, in sequence order.</returns>
    Task<List<AuditLedgerEntry>> AppendChainedAsync(
        Func<long, string, List<AuditLedgerEntry>> buildEntries,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Queries entries with filtering.
    /// </summary>
    /// <param name="predicate">Filter predicate.</param>
    /// <param name="skip">Number of entries to skip.</param>
    /// <param name="take">Number of entries to take.</param>
    /// <returns>Filtered entries.</returns>
    Task<(List<AuditLedgerEntry> Items, int TotalCount)> QueryAsync(
        Func<IQueryable<AuditLedgerEntry>, IQueryable<AuditLedgerEntry>> predicate,
        int skip,
        int take);

    /// <summary>
    /// Gets entries in a sequence range for verification.
    /// </summary>
    /// <param name="fromSequence">Starting sequence (inclusive).</param>
    /// <param name="toSequence">Ending sequence (inclusive).</param>
    /// <returns>Entries in the range.</returns>
    Task<List<AuditLedgerEntry>> GetRangeAsync(long fromSequence, long toSequence);

    /// <summary>
    /// Gets undispatched entries for the outbox pattern.
    /// </summary>
    /// <param name="batchSize">Maximum entries to return.</param>
    /// <returns>Undispatched entries.</returns>
    Task<List<AuditLedgerEntry>> GetUndispatchedAsync(int batchSize);

    /// <summary>
    /// Marks entries as dispatched.
    /// </summary>
    /// <param name="sequenceNumbers">Sequence numbers to mark.</param>
    Task MarkDispatchedAsync(IEnumerable<long> sequenceNumbers);

    /// <summary>
    /// Gets the minimum and maximum sequence numbers.
    /// </summary>
    /// <returns>Tuple of (min, max) sequence numbers.</returns>
    Task<(long Min, long Max)> GetSequenceRangeAsync();
}