using Amazon;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using Application.Common.Configuration;
using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using Amazon Simple Email Service (SES) v2.
/// </summary>
public class SesEmailSender(
    IOptions<EmailOptions> options,
    ILogger<SesEmailSender> logger)
    : IEmailSender, IDisposable
{
    private readonly EmailOptions _options = options.Value;
    private AmazonSimpleEmailServiceV2Client? _client;
    private bool _disposed;

    /// <inheritdoc />
    public string ProviderName => "AWS SES";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        // SES can use default credentials chain, so just check region is set
        return !string.IsNullOrWhiteSpace(_options.Ses.Region);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("AWS SES region is not configured", ProviderName);
        }

        try
        {
            var client = GetClient();
            var request = CreateSendRequest(message);

            var response = await client.SendEmailAsync(request, cancellationToken);

            logger.LogDebug(
                "SES email sent to {Recipient}, MessageId: {MessageId}",
                message.To,
                response.MessageId);

            return EmailSendResult.Succeeded(response.MessageId, ProviderName);
        }
        catch (AccountSuspendedException ex)
        {
            logger.LogError(ex, "AWS SES account is suspended");
            return EmailSendResult.Failed("AWS SES account is suspended", ProviderName);
        }
        catch (MailFromDomainNotVerifiedException ex)
        {
            logger.LogError(ex, "AWS SES domain not verified for {FromAddress}", _options.FromAddress);
            return EmailSendResult.Failed("Sender domain not verified in SES", ProviderName);
        }
        catch (MessageRejectedException ex)
        {
            logger.LogWarning(ex, "AWS SES rejected email to {Recipient}", message.To);
            return EmailSendResult.Failed($"Email rejected: {ex.Message}", ProviderName);
        }
        catch (SendingPausedException ex)
        {
            logger.LogError(ex, "AWS SES sending is paused");
            return EmailSendResult.Failed("AWS SES sending is paused", ProviderName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending email via AWS SES to {Recipient}", message.To);
            return EmailSendResult.Failed($"SES error: {ex.Message}", ProviderName);
        }
    }

    private AmazonSimpleEmailServiceV2Client GetClient()
    {
        if (_client != null)
            return _client;

        var region = RegionEndpoint.GetBySystemName(_options.Ses.Region);

        if (!string.IsNullOrWhiteSpace(_options.Ses.AccessKeyId) &&
            !string.IsNullOrWhiteSpace(_options.Ses.SecretAccessKey))
        {
            // Use explicit credentials
            _client = new AmazonSimpleEmailServiceV2Client(
                _options.Ses.AccessKeyId,
                _options.Ses.SecretAccessKey,
                region);
        }
        else
        {
            // Use default credentials chain (IAM role, environment variables, etc.)
            _client = new AmazonSimpleEmailServiceV2Client(region);
        }

        return _client;
    }

    private SendEmailRequest CreateSendRequest(EmailMessage message)
    {
        var request = new SendEmailRequest
        {
            FromEmailAddress = $"{_options.FromName} <{_options.FromAddress}>",
            Destination = new Destination
            {
                ToAddresses = [message.To]
            },
            Content = new EmailContent
            {
                Simple = new Message
                {
                    Subject = new Content { Data = message.Subject },
                    Body = new Body
                    {
                        Html = new Content { Data = message.HtmlBody }
                    }
                }
            }
        };

        // Add plain text body
        if (!string.IsNullOrWhiteSpace(message.TextBody))
        {
            request.Content.Simple.Body.Text = new Content { Data = message.TextBody };
        }

        // Add CC recipients
        if (message.Cc is { Count: > 0 })
        {
            request.Destination.CcAddresses = message.Cc.ToList();
        }

        // Add BCC recipients
        if (message.Bcc is { Count: > 0 })
        {
            request.Destination.BccAddresses = message.Bcc.ToList();
        }

        // Set reply-to
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            request.ReplyToAddresses = [message.ReplyTo];
        }

        // Set configuration set for tracking
        if (!string.IsNullOrWhiteSpace(_options.Ses.ConfigurationSetName))
        {
            request.ConfigurationSetName = _options.Ses.ConfigurationSetName;
        }

        // Add tags
        if (message.Tags is { Count: > 0 })
        {
            request.EmailTags = message.Tags
                .Select(tag => new MessageTag { Name = "Category", Value = tag })
                .ToList();
        }

        return request;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _client?.Dispose();
        _disposed = true;
    }
}