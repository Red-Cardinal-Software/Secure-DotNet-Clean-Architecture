using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Domain.Entities.Email;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

/// <summary>
/// Repository for managing outbound email queue.
/// </summary>
public class OutboundEmailRepository(ICrudOperator<OutboundEmail> crudOperator) : IOutboundEmailRepository
{
    /// <inheritdoc />
    public async Task<OutboundEmail> AddAsync(OutboundEmail email, CancellationToken cancellationToken = default)
    {
        return await crudOperator.AddAsync(email, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboundEmail>> GetPendingEmailsAsync(int batchSize, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        return await crudOperator.GetAll()
            .Where(e => e.Status == OutboundEmailStatus.Pending && e.NextAttemptAt <= now)
            .OrderBy(e => e.Priority)
            .ThenBy(e => e.NextAttemptAt)
            .Take(batchSize)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<OutboundEmail?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await crudOperator.GetAll()
            .FirstOrDefaultAsync(e => e.Id == id, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboundEmail>> GetByCorrelationIdAsync(string correlationId, CancellationToken cancellationToken = default)
    {
        return await crudOperator.GetAll()
            .Where(e => e.CorrelationId == correlationId)
            .OrderByDescending(e => e.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboundEmail>> GetByStatusAsync(OutboundEmailStatus status, int limit = 100, CancellationToken cancellationToken = default)
    {
        return await crudOperator.GetAll()
            .Where(e => e.Status == status)
            .OrderByDescending(e => e.CreatedAt)
            .Take(limit)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<int> DeleteOldEmailsAsync(DateTimeOffset olderThan, OutboundEmailStatus[] statuses, CancellationToken cancellationToken = default)
    {
        var emailsToDelete = await crudOperator.GetAll()
            .Where(e => statuses.Contains(e.Status) && e.CreatedAt < olderThan)
            .ToListAsync(cancellationToken);

        if (emailsToDelete.Count > 0)
        {
            crudOperator.DeleteMany(emailsToDelete);
        }

        return emailsToDelete.Count;
    }

    /// <inheritdoc />
    public async Task<EmailQueueStats> GetQueueStatsAsync(CancellationToken cancellationToken = default)
    {
        var query = crudOperator.GetAll();

        var pendingCount = await query.CountAsync(e => e.Status == OutboundEmailStatus.Pending, cancellationToken);
        var processingCount = await query.CountAsync(e => e.Status == OutboundEmailStatus.Processing, cancellationToken);
        var sentCount = await query.CountAsync(e => e.Status == OutboundEmailStatus.Sent, cancellationToken);
        var failedCount = await query.CountAsync(e => e.Status == OutboundEmailStatus.Failed, cancellationToken);

        var oldestPending = await query
            .Where(e => e.Status == OutboundEmailStatus.Pending)
            .OrderBy(e => e.CreatedAt)
            .Select(e => (DateTimeOffset?)e.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);

        return new EmailQueueStats
        {
            PendingCount = pendingCount,
            ProcessingCount = processingCount,
            SentCount = sentCount,
            FailedCount = failedCount,
            OldestPendingAt = oldestPending
        };
    }
}