namespace Domain.Entities.Email;

/// <summary>
/// Represents an email queued for delivery.
/// Supports retry logic with exponential backoff.
/// </summary>
public class OutboundEmail
{
    /// <summary>
    /// Unique identifier for the outbound email.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Recipient email address.
    /// </summary>
    public string To { get; private set; } = null!;

    /// <summary>
    /// Email subject line.
    /// </summary>
    public string Subject { get; private set; } = null!;

    /// <summary>
    /// HTML body content.
    /// </summary>
    public string HtmlBody { get; private set; } = null!;

    /// <summary>
    /// Plain text body content (optional).
    /// </summary>
    public string? TextBody { get; private set; }

    /// <summary>
    /// Template key used to generate this email (for tracking).
    /// </summary>
    public string? TemplateKey { get; private set; }

    /// <summary>
    /// Current delivery status.
    /// </summary>
    public OutboundEmailStatus Status { get; private set; }

    /// <summary>
    /// Number of delivery attempts made.
    /// </summary>
    public int Attempts { get; private set; }

    /// <summary>
    /// Maximum number of delivery attempts before marking as failed.
    /// </summary>
    public int MaxAttempts { get; private set; }

    /// <summary>
    /// When the next delivery attempt should be made (for retry scheduling).
    /// </summary>
    public DateTimeOffset? NextAttemptAt { get; private set; }

    /// <summary>
    /// Last error message if delivery failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Provider-specific message ID after successful send.
    /// </summary>
    public string? ProviderMessageId { get; private set; }

    /// <summary>
    /// When the email was successfully sent.
    /// </summary>
    public DateTimeOffset? SentAt { get; private set; }

    /// <summary>
    /// When the email was queued.
    /// </summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// Optional organization ID for multi-tenant scenarios.
    /// </summary>
    public Guid? OrganizationId { get; private set; }

    /// <summary>
    /// Optional correlation ID for tracking related emails.
    /// </summary>
    public string? CorrelationId { get; private set; }

    /// <summary>
    /// Priority level (lower = higher priority).
    /// </summary>
    public int Priority { get; private set; }

    /// <summary>
    /// EF Core constructor.
    /// </summary>
    protected OutboundEmail() { }

    /// <summary>
    /// Creates a new outbound email.
    /// </summary>
    public OutboundEmail(
        string to,
        string subject,
        string htmlBody,
        string? textBody = null,
        string? templateKey = null,
        Guid? organizationId = null,
        string? correlationId = null,
        int priority = 10,
        int maxAttempts = 3)
    {
        if (string.IsNullOrWhiteSpace(to))
            throw new ArgumentNullException(nameof(to));
        if (string.IsNullOrWhiteSpace(subject))
            throw new ArgumentNullException(nameof(subject));
        if (string.IsNullOrWhiteSpace(htmlBody))
            throw new ArgumentNullException(nameof(htmlBody));

        Id = Guid.NewGuid();
        To = to;
        Subject = subject;
        HtmlBody = htmlBody;
        TextBody = textBody;
        TemplateKey = templateKey;
        OrganizationId = organizationId;
        CorrelationId = correlationId;
        Priority = priority;
        MaxAttempts = maxAttempts;
        Status = OutboundEmailStatus.Pending;
        Attempts = 0;
        NextAttemptAt = DateTimeOffset.UtcNow;
        CreatedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Marks the email as being processed.
    /// </summary>
    public void MarkProcessing()
    {
        Status = OutboundEmailStatus.Processing;
    }

    /// <summary>
    /// Marks the email as successfully sent.
    /// </summary>
    public void MarkSent(string? providerMessageId = null)
    {
        Status = OutboundEmailStatus.Sent;
        SentAt = DateTimeOffset.UtcNow;
        ProviderMessageId = providerMessageId;
        ErrorMessage = null;
    }

    /// <summary>
    /// Records a failed delivery attempt and schedules retry if attempts remain.
    /// Uses exponential backoff: 1min, 5min, 15min, 30min, 1hr...
    /// </summary>
    public void RecordFailure(string errorMessage)
    {
        Attempts++;
        ErrorMessage = errorMessage;

        if (Attempts >= MaxAttempts)
        {
            Status = OutboundEmailStatus.Failed;
            NextAttemptAt = null;
        }
        else
        {
            Status = OutboundEmailStatus.Pending;
            // Exponential backoff: 1, 5, 15, 30, 60 minutes
            var delayMinutes = Attempts switch
            {
                1 => 1,
                2 => 5,
                3 => 15,
                4 => 30,
                _ => 60
            };
            NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(delayMinutes);
        }
    }

    /// <summary>
    /// Cancels the email (won't be sent).
    /// </summary>
    public void Cancel()
    {
        if (Status == OutboundEmailStatus.Sent)
            throw new InvalidOperationException("Cannot cancel an email that has already been sent.");

        Status = OutboundEmailStatus.Cancelled;
        NextAttemptAt = null;
    }
}

/// <summary>
/// Status of an outbound email.
/// </summary>
public enum OutboundEmailStatus
{
    /// <summary>
    /// Queued and waiting to be sent.
    /// </summary>
    Pending = 0,

    /// <summary>
    /// Currently being processed by the background service.
    /// </summary>
    Processing = 1,

    /// <summary>
    /// Successfully delivered to the email provider.
    /// </summary>
    Sent = 2,

    /// <summary>
    /// Failed after exhausting all retry attempts.
    /// </summary>
    Failed = 3,

    /// <summary>
    /// Cancelled before being sent.
    /// </summary>
    Cancelled = 4
}