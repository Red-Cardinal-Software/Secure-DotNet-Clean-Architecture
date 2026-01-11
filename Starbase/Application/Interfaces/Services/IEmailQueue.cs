using Application.Common.Email;

namespace Application.Interfaces.Services;

/// <summary>
/// Service for queuing emails for delivery.
/// Emails are stored in the database and processed by a background service.
/// </summary>
public interface IEmailQueue
{
    /// <summary>
    /// Queues an email for delivery.
    /// </summary>
    /// <param name="to">Recipient email address.</param>
    /// <param name="subject">Email subject.</param>
    /// <param name="htmlBody">HTML body content.</param>
    /// <param name="textBody">Plain text body (optional).</param>
    /// <param name="templateKey">Template key used (for tracking).</param>
    /// <param name="organizationId">Organization ID for multi-tenant scenarios.</param>
    /// <param name="correlationId">Correlation ID for tracking related emails.</param>
    /// <param name="priority">Priority (lower = higher priority, default 10).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The queued email ID.</returns>
    Task<Guid> QueueAsync(
        string to,
        string subject,
        string htmlBody,
        string? textBody = null,
        string? templateKey = null,
        Guid? organizationId = null,
        string? correlationId = null,
        int priority = 10,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Queues a rendered email for delivery.
    /// </summary>
    Task<Guid> QueueAsync(
        string to,
        RenderedEmailTemplate email,
        Guid? organizationId = null,
        string? correlationId = null,
        int priority = 10,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Cancels a queued email if it hasn't been sent yet.
    /// </summary>
    /// <param name="emailId">The email ID to cancel.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if cancelled, false if already sent or not found.</returns>
    Task<bool> CancelAsync(Guid emailId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the status of a queued email.
    /// </summary>
    Task<EmailQueueStatus?> GetStatusAsync(Guid emailId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Status of a queued email.
/// </summary>
public record EmailQueueStatus
{
    public Guid Id { get; init; }
    public string To { get; init; } = null!;
    public string Subject { get; init; } = null!;
    public string Status { get; init; } = null!;
    public int Attempts { get; init; }
    public int MaxAttempts { get; init; }
    public string? ErrorMessage { get; init; }
    public DateTimeOffset? SentAt { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? NextAttemptAt { get; init; }
}