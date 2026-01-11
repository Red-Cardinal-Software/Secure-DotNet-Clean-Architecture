using System.Net;
using System.Net.Mail;
using Application.Common.Configuration;
using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using SMTP protocol.
/// </summary>
public class SmtpEmailSender(
    IOptions<EmailOptions> options,
    ILogger<SmtpEmailSender> logger)
    : IEmailSender, IDisposable
{
    private readonly EmailOptions _options = options.Value;
    private SmtpClient? _client;
    private bool _disposed;

    /// <inheritdoc />
    public string ProviderName => "SMTP";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(_options.Smtp.Host);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("SMTP is not configured", ProviderName);
        }

        try
        {
            var client = GetClient();
            var mailMessage = CreateMailMessage(message);

            await client.SendMailAsync(mailMessage, cancellationToken);

            logger.LogDebug(
                "SMTP email sent to {Recipient} via {Host}:{Port}",
                message.To,
                _options.Smtp.Host,
                _options.Smtp.Port);

            return EmailSendResult.Succeeded(
                messageId: Guid.NewGuid().ToString(),
                provider: ProviderName);
        }
        catch (SmtpException ex)
        {
            logger.LogError(ex, "SMTP error sending email to {Recipient}", message.To);
            return EmailSendResult.Failed($"SMTP error: {ex.Message}", ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error sending SMTP email to {Recipient}", message.To);
            return EmailSendResult.Failed($"Unexpected error: {ex.Message}", ProviderName);
        }
    }

    private SmtpClient GetClient()
    {
        if (_client != null)
            return _client;

        _client = new SmtpClient(_options.Smtp.Host, _options.Smtp.Port)
        {
            EnableSsl = _options.Smtp.UseSsl,
            Timeout = _options.Smtp.TimeoutSeconds * 1000
        };

        if (!string.IsNullOrWhiteSpace(_options.Smtp.Username))
        {
            _client.Credentials = new NetworkCredential(
                _options.Smtp.Username,
                _options.Smtp.Password);
        }

        return _client;
    }

    private MailMessage CreateMailMessage(EmailMessage message)
    {
        var mail = new MailMessage
        {
            From = new MailAddress(_options.FromAddress, _options.FromName),
            Subject = message.Subject,
            IsBodyHtml = true,
            Body = message.HtmlBody
        };

        mail.To.Add(message.To);

        // Add plain text alternative
        if (!string.IsNullOrWhiteSpace(message.TextBody))
        {
            var plainView = AlternateView.CreateAlternateViewFromString(
                message.TextBody,
                null,
                "text/plain");
            mail.AlternateViews.Add(plainView);

            var htmlView = AlternateView.CreateAlternateViewFromString(
                message.HtmlBody,
                null,
                "text/html");
            mail.AlternateViews.Add(htmlView);

            // When using AlternateViews, the Body is not used
            mail.Body = null;
            mail.IsBodyHtml = false;
        }

        // Add CC recipients
        if (message.Cc != null)
        {
            foreach (var cc in message.Cc)
                mail.CC.Add(cc);
        }

        // Add BCC recipients
        if (message.Bcc != null)
        {
            foreach (var bcc in message.Bcc)
                mail.Bcc.Add(bcc);
        }

        // Set reply-to
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            mail.ReplyToList.Add(message.ReplyTo);
        }

        // Add custom headers
        if (message.Headers != null)
        {
            foreach (var header in message.Headers)
                mail.Headers.Add(header.Key, header.Value);
        }

        return mail;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _client?.Dispose();
        _disposed = true;
    }
}