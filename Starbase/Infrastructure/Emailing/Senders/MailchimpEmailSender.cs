using Application.Common.Configuration;
using Application.Common.Email;
using static Application.Common.Email.EmailMaskingUtility;
using Application.Interfaces.Services;
using Mandrill;
using Mandrill.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using Mailchimp Transactional (Mandrill) API.
/// Requires a Mailchimp Standard or Premium subscription.
/// </summary>
public class MailchimpEmailSender(
    IOptions<EmailOptions> options,
    ILogger<MailchimpEmailSender> logger)
    : IEmailSender
{
    private readonly EmailOptions _options = options.Value;
    private MandrillApi? _client;

    /// <inheritdoc />
    public string ProviderName => "Mailchimp";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(_options.Mailchimp.ApiKey);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("Mailchimp/Mandrill API key is not configured", ProviderName);
        }

        try
        {
            var client = GetClient();
            var mandrillMessage = CreateMandrillMessage(message);

            var results = await client.Messages.SendAsync(mandrillMessage);

            if (results.Count == 0)
            {
                return EmailSendResult.Failed("No response from Mandrill API", ProviderName);
            }

            var result = results[0];

            if (result.Status == MandrillSendMessageResponseStatus.Sent ||
                result.Status == MandrillSendMessageResponseStatus.Queued)
            {
                logger.LogDebug(
                    "Mailchimp email sent to {Recipient}, MessageId: {MessageId}, Status: {Status}",
                    MaskEmail(message.To),
                    result.Id,
                    result.Status);

                return EmailSendResult.Succeeded(result.Id, ProviderName);
            }

            logger.LogWarning(
                "Mailchimp returned error for email to {Recipient}: {Status} - {RejectReason}",
                MaskEmail(message.To),
                result.Status,
                result.RejectReason);

            return EmailSendResult.Failed(
                $"Mailchimp error: {result.Status} - {result.RejectReason}",
                ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending email via Mailchimp to {Recipient}", MaskEmail(message.To));
            return EmailSendResult.Failed($"Mailchimp error: {ex.Message}", ProviderName);
        }
    }

    private MandrillApi GetClient()
    {
        return _client ??= new MandrillApi(_options.Mailchimp.ApiKey);
    }

    private MandrillMessage CreateMandrillMessage(EmailMessage message)
    {
        var mandrillMessage = new MandrillMessage
        {
            FromEmail = _options.FromAddress,
            FromName = _options.FromName,
            Subject = message.Subject,
            Html = message.HtmlBody,
            Text = message.TextBody,
            TrackOpens = _options.Mailchimp.TrackOpens,
            TrackClicks = _options.Mailchimp.TrackClicks,
            AutoText = _options.Mailchimp.AutoText,
            InlineCss = _options.Mailchimp.InlineCss,
            // Add primary recipient
            To = [new MandrillMailAddress { Email = message.To, Type = MandrillMailAddressType.To }]
        };

        // Add CC recipients
        if (message.Cc is { Count: > 0 })
        {
            foreach (var cc in message.Cc)
            {
                mandrillMessage.To.Add(new MandrillMailAddress { Email = cc, Type = MandrillMailAddressType.Cc });
            }
        }

        // Add BCC recipients
        if (message.Bcc is { Count: > 0 })
        {
            foreach (var bcc in message.Bcc)
            {
                mandrillMessage.To.Add(new MandrillMailAddress { Email = bcc, Type = MandrillMailAddressType.Bcc });
            }
        }

        // Set reply-to via headers
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            mandrillMessage.Headers ??= new Dictionary<string, object>();
            mandrillMessage.Headers["Reply-To"] = message.ReplyTo;
        }

        // Add custom headers
        if (message.Headers is { Count: > 0 })
        {
            mandrillMessage.Headers ??= new Dictionary<string, object>();
            foreach (var header in message.Headers)
            {
                mandrillMessage.Headers[header.Key] = header.Value;
            }
        }

        // Add tags
        if (message.Tags is { Count: > 0 })
        {
            mandrillMessage.Tags = message.Tags.ToList();
        }

        return mandrillMessage;
    }
}