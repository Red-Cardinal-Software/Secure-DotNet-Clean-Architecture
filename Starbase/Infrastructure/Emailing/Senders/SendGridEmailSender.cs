using Application.Common.Configuration;
using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using the SendGrid API.
/// </summary>
public class SendGridEmailSender(
    IOptions<EmailOptions> options,
    ILogger<SendGridEmailSender> logger)
    : IEmailSender
{
    private readonly EmailOptions _options = options.Value;
    private SendGridClient? _client;

    /// <inheritdoc />
    public string ProviderName => "SendGrid";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(_options.SendGrid.ApiKey);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("SendGrid API key is not configured", ProviderName);
        }

        try
        {
            var client = GetClient();
            var msg = CreateSendGridMessage(message);

            var response = await client.SendEmailAsync(msg, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                // Extract message ID from headers
                var messageId = response.Headers.TryGetValues("X-Message-Id", out var values)
                    ? values.FirstOrDefault()
                    : null;

                logger.LogDebug(
                    "SendGrid email sent to {Recipient}, MessageId: {MessageId}",
                    message.To,
                    messageId);

                return EmailSendResult.Succeeded(messageId, ProviderName);
            }

            var body = await response.Body.ReadAsStringAsync(cancellationToken);
            logger.LogWarning(
                "SendGrid returned {StatusCode} for email to {Recipient}: {Body}",
                response.StatusCode,
                message.To,
                body);

            return EmailSendResult.Failed($"SendGrid error: {response.StatusCode}", ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending email via SendGrid to {Recipient}", message.To);
            return EmailSendResult.Failed($"SendGrid error: {ex.Message}", ProviderName);
        }
    }

    private SendGridClient GetClient()
    {
        return _client ??= new SendGridClient(_options.SendGrid.ApiKey);
    }

    private SendGridMessage CreateSendGridMessage(EmailMessage message)
    {
        var msg = new SendGridMessage
        {
            From = new EmailAddress(_options.FromAddress, _options.FromName),
            Subject = message.Subject,
            HtmlContent = message.HtmlBody,
            PlainTextContent = message.TextBody
        };

        msg.AddTo(message.To);

        // Add CC recipients
        if (message.Cc is { Count: > 0 })
        {
            msg.AddCcs(message.Cc.Select(cc => new EmailAddress(cc)).ToList());
        }

        // Add BCC recipients
        if (message.Bcc is { Count: > 0 })
        {
            msg.AddBccs(message.Bcc.Select(bcc => new EmailAddress(bcc)).ToList());
        }

        // Set reply-to
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            msg.ReplyTo = new EmailAddress(message.ReplyTo);
        }

        // Add custom headers
        if (message.Headers != null)
        {
            foreach (var header in message.Headers)
            {
                msg.AddHeader(header.Key, header.Value);
            }
        }

        // Add categories/tags
        if (message.Tags is { Count: > 0 })
        {
            msg.AddCategories(message.Tags.ToList());
        }

        // Enable sandbox mode for testing
        if (_options.SendGrid.SandboxMode)
        {
            msg.MailSettings = new MailSettings
            {
                SandboxMode = new SandboxMode { Enable = true }
            };
        }

        return msg;
    }
}