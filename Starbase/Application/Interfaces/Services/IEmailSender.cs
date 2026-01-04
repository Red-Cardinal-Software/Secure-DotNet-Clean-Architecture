using Application.Common.Email;

namespace Application.Interfaces.Services;

/// <summary>
/// Low-level interface for sending emails via a specific provider.
/// Implementations handle the actual delivery (SMTP, SendGrid, SES, etc.).
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// The name of this email provider.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Sends an email message.
    /// </summary>
    /// <param name="message">The email message to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the send operation.</returns>
    Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates that the provider is properly configured.
    /// </summary>
    /// <returns>True if the provider is ready to send emails.</returns>
    bool IsConfigured();
}