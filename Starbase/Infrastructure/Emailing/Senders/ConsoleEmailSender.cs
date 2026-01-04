using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Development email sender that logs emails to the console instead of sending them.
/// Useful for testing and local development.
/// </summary>
public class ConsoleEmailSender(ILogger<ConsoleEmailSender> logger) : IEmailSender
{
    /// <inheritdoc />
    public string ProviderName => "Console";

    /// <inheritdoc />
    public bool IsConfigured() => true;

    /// <inheritdoc />
    public Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var messageId = Guid.NewGuid().ToString();

        logger.LogInformation(
            """

            ╔══════════════════════════════════════════════════════════════════╗
            ║  DEVELOPMENT EMAIL - Not actually sent                           ║
            ╠══════════════════════════════════════════════════════════════════╣
            ║  MessageId: {MessageId}
            ║  To: {To}
            ║  Subject: {Subject}
            ╠══════════════════════════════════════════════════════════════════╣
            ║  HTML Body:
            ╠══════════════════════════════════════════════════════════════════╣
            {HtmlBody}
            ╠══════════════════════════════════════════════════════════════════╣
            ║  Plain Text Body:
            ╠══════════════════════════════════════════════════════════════════╣
            {TextBody}
            ╚══════════════════════════════════════════════════════════════════╝

            """,
            messageId,
            message.To,
            message.Subject,
            message.HtmlBody,
            message.TextBody ?? "(auto-generated from HTML)");

        return Task.FromResult(EmailSendResult.Succeeded(messageId, ProviderName));
    }
}