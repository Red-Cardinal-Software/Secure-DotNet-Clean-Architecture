using Domain.Entities.Email;

namespace Application.Interfaces.Repositories;

/// <summary>
/// Repository for managing outbound email queue.
/// </summary>
public interface IOutboundEmailRepository
{
    /// <summary>
    /// Adds a new email to the queue.
    /// </summary>
    Task<OutboundEmail> AddAsync(OutboundEmail email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets emails that are ready to be sent (pending and due for next attempt).
    /// </summary>
    /// <param name="batchSize">Maximum number of emails to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of emails ready for processing.</returns>
    Task<IReadOnlyList<OutboundEmail>> GetPendingEmailsAsync(int batchSize, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an email by its ID.
    /// </summary>
    Task<OutboundEmail?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets emails by correlation ID.
    /// </summary>
    Task<IReadOnlyList<OutboundEmail>> GetByCorrelationIdAsync(string correlationId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets emails by status.
    /// </summary>
    Task<IReadOnlyList<OutboundEmail>> GetByStatusAsync(OutboundEmailStatus status, int limit = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes old sent/failed emails for cleanup.
    /// </summary>
    /// <param name="olderThan">Delete emails created before this date.</param>
    /// <param name="statuses">Only delete emails with these statuses.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Number of deleted emails.</returns>
    Task<int> DeleteOldEmailsAsync(DateTimeOffset olderThan, OutboundEmailStatus[] statuses, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets queue statistics.
    /// </summary>
    Task<EmailQueueStats> GetQueueStatsAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Statistics about the email queue.
/// </summary>
public record EmailQueueStats
{
    public int PendingCount { get; init; }
    public int ProcessingCount { get; init; }
    public int SentCount { get; init; }
    public int FailedCount { get; init; }
    public DateTimeOffset? OldestPendingAt { get; init; }
}