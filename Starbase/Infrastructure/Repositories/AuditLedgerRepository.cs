using System.Data;
using System.Data.Common;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Domain.Entities.Audit;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Infrastructure.Repositories;

/// <summary>
/// Repository implementation for the audit ledger.
/// Provides append-only operations with hash chain support.
/// </summary>
/// <remarks>
/// Reads go through the request-scoped <see cref="ICrudOperator{TEntity}"/>. Appends deliberately
/// do not - see <see cref="AppendChainedAsync"/>.
/// </remarks>
public class AuditLedgerRepository(
    ICrudOperator<AuditLedgerEntry> crudOperator,
    AuditLedgerContextFactory contextFactory) : IAuditLedgerRepository
{
    /// <summary>
    /// Genesis hash for the first entry in the ledger.
    /// </summary>
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// How many times to retry an append that lost a race with a concurrent writer.
    /// </summary>
    private const int MaxAppendAttempts = 8;

    /// <summary>
    /// Serializes appends within this process.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a throughput optimisation, NOT the correctness mechanism - correctness comes from
    /// the serializable transaction below, which also holds across processes. Without this,
    /// concurrent in-process writers all range-lock the ledger tail and deadlock each other
    /// constantly, burning retries on contention this process can trivially avoid.
    /// </para>
    /// <para>
    /// A static, non-reentrant semaphore here is only safe because nothing inside it can call
    /// back into the ledger: the context comes from <see cref="AuditLedgerContextFactory"/> and
    /// carries no interceptors, and <c>buildEntries</c> is a pure hash computation. The previous
    /// implementation held an equivalent lock across a SaveChanges on the *intercepted*
    /// request-scoped context, which re-entered this method and deadlocked. Do not move this lock
    /// to wrap an intercepted context.
    /// </para>
    /// </remarks>
    private static readonly SemaphoreSlim InProcessAppendLock = new(1, 1);

    /// <inheritdoc />
    public async Task<List<AuditLedgerEntry>> AppendChainedAsync(
        Func<long, string, List<AuditLedgerEntry>> buildEntries,
        CancellationToken cancellationToken = default)
    {
        await InProcessAppendLock.WaitAsync(cancellationToken);
        try
        {
            return await AppendWithRetryAsync(buildEntries, cancellationToken);
        }
        finally
        {
            InProcessAppendLock.Release();
        }
    }

    private async Task<List<AuditLedgerEntry>> AppendWithRetryAsync(
        Func<long, string, List<AuditLedgerEntry>> buildEntries,
        CancellationToken cancellationToken)
    {
        Exception? lastConflict = null;

        for (var attempt = 1; attempt <= MaxAppendAttempts; attempt++)
        {
            // A dedicated, uninterceptored context: commits only ledger rows, and cannot
            // re-enter the audit pipeline via SaveChanges interceptors.
            await using var context = contextFactory.Create();

            // Serializable is what makes the tail read and the insert atomic against other
            // processes. Under SQL Server it range-locks the tail so a concurrent append blocks
            // or deadlocks; under PostgreSQL/Oracle it surfaces as a serialization failure.
            // Either way it lands in the retry below.
            await using var transaction = await context.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

            try
            {
                // Single read for both values - they must come from the same tail row.
                var tail = await context.AuditLedger
                    .OrderByDescending(e => e.SequenceNumber)
                    .Select(e => new { e.SequenceNumber, e.Hash })
                    .FirstOrDefaultAsync(cancellationToken);

                var startSequence = (tail?.SequenceNumber ?? 0) + 1;
                var previousHash = tail?.Hash ?? GenesisHash;

                var entries = buildEntries(startSequence, previousHash);
                if (entries.Count == 0)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return entries;
                }

                context.AuditLedger.AddRange(entries);
                await context.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);

                return entries;
            }
            catch (Exception ex) when (IsAppendConflict(ex) && attempt < MaxAppendAttempts)
            {
                // Another writer took the sequence numbers we picked, or the database refused to
                // serialize us. Rebuilding from a fresh read is safe because buildEntries has no
                // side effects and the whole attempt rolls back, so no partial chain is visible.
                lastConflict = ex;
                await SafeRollbackAsync(transaction, cancellationToken);
                await Task.Delay(BackoffFor(attempt), cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"Audit ledger append failed after {MaxAppendAttempts} attempts due to concurrent writers.",
            lastConflict);
    }

    /// <summary>
    /// Identifies failures that mean "another writer beat us to these sequence numbers" and are
    /// therefore safe to retry, as opposed to genuine data errors.
    /// </summary>
    /// <remarks>
    /// Walks the whole inner-exception chain. EF Core wraps transient provider failures (SQL
    /// Server deadlocks in particular) in an <see cref="InvalidOperationException"/> recommending
    /// EnableRetryOnFailure, so matching only the outer type silently misses every deadlock.
    /// </remarks>
    private static bool IsAppendConflict(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is not DbException dbException)
            {
                continue;
            }

            // Serialization / deadlock: PostgreSQL 40001 (serialization_failure),
            // 40P01 (deadlock_detected). Primary key collision: PostgreSQL 23505.
            if (dbException.SqlState is "23505" or "40001" or "40P01")
            {
                return true;
            }

            // SQL Server 1205 (deadlock victim), 2627/2601 (PK / unique violation).
            // Oracle ORA-00001 (unique constraint), ORA-08177 (cannot serialize access).
            if (dbException.ErrorCode is 1205 or 2627 or 2601 or 1 or 8177)
            {
                return true;
            }
        }

        return false;
    }

    private static TimeSpan BackoffFor(int attempt) => TimeSpan.FromMilliseconds(25 * attempt);

    private static async Task SafeRollbackAsync(IDbContextTransaction transaction, CancellationToken cancellationToken)
    {
        try
        {
            await transaction.RollbackAsync(cancellationToken);
        }
        catch (Exception)
        {
            // The transaction may already be dead; the context is disposed either way and the
            // original conflict is what we want to surface.
        }
    }

    /// <inheritdoc />
    public async Task<(List<AuditLedgerEntry> Items, int TotalCount)> QueryAsync(
        Func<IQueryable<AuditLedgerEntry>, IQueryable<AuditLedgerEntry>> predicate,
        int skip,
        int take)
    {
        var query = predicate(crudOperator.GetAll());

        var totalCount = await query.CountAsync();
        var items = await query
            .Skip(skip)
            .Take(take)
            .ToListAsync();

        return (items, totalCount);
    }

    /// <inheritdoc />
    public async Task<List<AuditLedgerEntry>> GetRangeAsync(long fromSequence, long toSequence)
    {
        return await crudOperator.GetAll()
            .Where(e => e.SequenceNumber >= fromSequence && e.SequenceNumber <= toSequence)
            .OrderBy(e => e.SequenceNumber)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<List<AuditLedgerEntry>> GetUndispatchedAsync(int batchSize)
    {
        return await crudOperator.GetAll()
            .Where(e => !e.Dispatched)
            .OrderBy(e => e.SequenceNumber)
            .Take(batchSize)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task MarkDispatchedAsync(IEnumerable<long> sequenceNumbers)
    {
        var sequenceList = sequenceNumbers.ToList();
        if (sequenceList.Count == 0) return;

        var entries = await crudOperator.GetAll()
            .Where(e => sequenceList.Contains(e.SequenceNumber))
            .ToListAsync();

        var now = DateTime.UtcNow;
        foreach (var entry in entries)
        {
            entry.Dispatched = true;
            entry.DispatchedAt = now;
        }
    }

    /// <inheritdoc />
    public async Task<(long Min, long Max)> GetSequenceRangeAsync()
    {
        var query = crudOperator.GetAll();

        var min = await query.MinAsync(e => (long?)e.SequenceNumber) ?? 0;
        var max = await query.MaxAsync(e => (long?)e.SequenceNumber) ?? 0;

        return (min, max);
    }
}