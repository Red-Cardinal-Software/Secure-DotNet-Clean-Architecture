namespace Application.Common.Email;

/// <summary>
/// Represents a fully rendered email message ready to be sent.
/// </summary>
public class EmailMessage
{
    /// <summary>
    /// The recipient email address.
    /// </summary>
    public required string To { get; init; }

    /// <summary>
    /// The email subject line.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The HTML body content.
    /// </summary>
    public required string HtmlBody { get; init; }

    /// <summary>
    /// The plain text body content. Auto-generated from HTML if not provided.
    /// </summary>
    public string? TextBody { get; init; }

    /// <summary>
    /// Optional CC recipients.
    /// </summary>
    public IReadOnlyList<string>? Cc { get; init; }

    /// <summary>
    /// Optional BCC recipients.
    /// </summary>
    public IReadOnlyList<string>? Bcc { get; init; }

    /// <summary>
    /// Optional reply-to address.
    /// </summary>
    public string? ReplyTo { get; init; }

    /// <summary>
    /// Optional custom headers.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>
    /// Optional tags for tracking/categorization.
    /// </summary>
    public IReadOnlyList<string>? Tags { get; init; }
}

/// <summary>
/// Result of sending an email.
/// </summary>
public class EmailSendResult
{
    /// <summary>
    /// Whether the email was sent successfully.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// The message ID from the provider (if available).
    /// </summary>
    public string? MessageId { get; init; }

    /// <summary>
    /// Error message if sending failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// The provider that handled the request.
    /// </summary>
    public string? Provider { get; init; }

    public static EmailSendResult Succeeded(string? messageId = null, string? provider = null) => new()
    {
        Success = true,
        MessageId = messageId,
        Provider = provider
    };

    public static EmailSendResult Failed(string errorMessage, string? provider = null) => new()
    {
        Success = false,
        ErrorMessage = errorMessage,
        Provider = provider
    };
}