using Application.Common.Configuration;
using Application.Common.Email;
using static Application.Common.Email.EmailMaskingUtility;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PostmarkDotNet;
using PostmarkDotNet.Model;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using the Postmark API.
/// </summary>
public class PostmarkEmailSender(
    IOptions<EmailOptions> options,
    ILogger<PostmarkEmailSender> logger)
    : IEmailSender
{
    private readonly EmailOptions _options = options.Value;
    private PostmarkClient? _client;

    /// <inheritdoc />
    public string ProviderName => "Postmark";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(_options.Postmark.ServerToken);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("Postmark server token is not configured", ProviderName);
        }

        try
        {
            var client = GetClient();
            var postmarkMessage = CreatePostmarkMessage(message);

            var response = await client.SendMessageAsync(postmarkMessage);

            if (response.Status == PostmarkStatus.Success)
            {
                logger.LogDebug(
                    "Postmark email sent to {Recipient}, MessageId: {MessageId}",
                    MaskEmail(message.To),
                    response.MessageID);

                return EmailSendResult.Succeeded(response.MessageID.ToString(), ProviderName);
            }

            logger.LogWarning(
                "Postmark returned error for email to {Recipient}: {ErrorCode} - {Message}",
                MaskEmail(message.To),
                response.ErrorCode,
                response.Message);

            return EmailSendResult.Failed($"Postmark error: {response.ErrorCode} - {response.Message}", ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending email via Postmark to {Recipient}", MaskEmail(message.To));
            return EmailSendResult.Failed($"Postmark error: {ex.Message}", ProviderName);
        }
    }

    private PostmarkClient GetClient()
    {
        return _client ??= new PostmarkClient(_options.Postmark.ServerToken);
    }

    private PostmarkMessage CreatePostmarkMessage(EmailMessage message)
    {
        var postmarkMessage = new PostmarkMessage
        {
            From = $"{_options.FromName} <{_options.FromAddress}>",
            To = message.To,
            Subject = message.Subject,
            HtmlBody = message.HtmlBody,
            TextBody = message.TextBody,
            MessageStream = _options.Postmark.MessageStream,
            TrackOpens = _options.Postmark.TrackOpens,
            TrackLinks = ParseLinkTrackingMode(_options.Postmark.TrackLinks)
        };

        // Add CC recipients
        if (message.Cc is { Count: > 0 })
        {
            postmarkMessage.Cc = string.Join(",", message.Cc);
        }

        // Add BCC recipients
        if (message.Bcc is { Count: > 0 })
        {
            postmarkMessage.Bcc = string.Join(",", message.Bcc);
        }

        // Set reply-to
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            postmarkMessage.ReplyTo = message.ReplyTo;
        }

        // Add custom headers
        if (message.Headers is { Count: > 0 })
        {
            postmarkMessage.Headers = new HeaderCollection(
                message.Headers.ToDictionary(h => h.Key, h => h.Value));
        }

        // Add tags (Postmark supports a single tag per message)
        if (message.Tags is { Count: > 0 })
        {
            postmarkMessage.Tag = message.Tags[0];
        }

        return postmarkMessage;
    }

    private static LinkTrackingOptions ParseLinkTrackingMode(string mode)
    {
        return mode.ToLowerInvariant() switch
        {
            "htmlandtext" => LinkTrackingOptions.HtmlAndText,
            "htmlonly" => LinkTrackingOptions.HtmlOnly,
            "textonly" => LinkTrackingOptions.TextOnly,
            _ => LinkTrackingOptions.None
        };
    }
}