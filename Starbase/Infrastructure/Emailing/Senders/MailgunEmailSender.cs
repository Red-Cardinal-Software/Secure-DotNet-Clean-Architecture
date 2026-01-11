using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Application.Common.Configuration;
using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing.Senders;

/// <summary>
/// Sends emails using the Mailgun HTTP API.
/// Uses HttpClient directly for simplicity - no external SDK required.
/// </summary>
public class MailgunEmailSender : IEmailSender, IDisposable
{
    private readonly EmailOptions _options;
    private readonly ILogger<MailgunEmailSender> _logger;
    private readonly HttpClient _httpClient;
    private bool _disposed;

    public MailgunEmailSender(
        IOptions<EmailOptions> options,
        ILogger<MailgunEmailSender> logger,
        IHttpClientFactory? httpClientFactory = null)
    {
        _options = options.Value;
        _logger = logger;

        // Use IHttpClientFactory if available, otherwise create a new client
        _httpClient = httpClientFactory?.CreateClient("Mailgun") ?? new HttpClient();
        ConfigureHttpClient();
    }

    /// <inheritdoc />
    public string ProviderName => "Mailgun";

    /// <inheritdoc />
    public bool IsConfigured()
    {
        return !string.IsNullOrWhiteSpace(_options.Mailgun.ApiKey) &&
               !string.IsNullOrWhiteSpace(_options.Mailgun.Domain);
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!IsConfigured())
        {
            return EmailSendResult.Failed("Mailgun API key or domain is not configured", ProviderName);
        }

        try
        {
            var content = CreateFormContent(message);
            var endpoint = $"{_options.Mailgun.BaseUrl}/v3/{_options.Mailgun.Domain}/messages";

            var response = await _httpClient.PostAsync(endpoint, content, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize<MailgunResponse>(responseBody);
                var messageId = result?.Id ?? Guid.NewGuid().ToString();

                _logger.LogDebug(
                    "Mailgun email sent to {Recipient}, MessageId: {MessageId}",
                    message.To,
                    messageId);

                return EmailSendResult.Succeeded(messageId, ProviderName);
            }

            _logger.LogWarning(
                "Mailgun returned error for email to {Recipient}: {StatusCode} - {Response}",
                message.To,
                response.StatusCode,
                responseBody);

            return EmailSendResult.Failed($"Mailgun error: {response.StatusCode} - {responseBody}", ProviderName);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP error sending email via Mailgun to {Recipient}", message.To);
            return EmailSendResult.Failed($"Mailgun HTTP error: {ex.Message}", ProviderName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email via Mailgun to {Recipient}", message.To);
            return EmailSendResult.Failed($"Mailgun error: {ex.Message}", ProviderName);
        }
    }

    private void ConfigureHttpClient()
    {
        if (!IsConfigured())
            return;

        // Mailgun uses Basic Auth with "api" as username and the API key as password
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{_options.Mailgun.ApiKey}"));
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    private MultipartFormDataContent CreateFormContent(EmailMessage message)
    {
        var content = new MultipartFormDataContent();

        // Required fields
        content.Add(new StringContent($"{_options.FromName} <{_options.FromAddress}>"), "from");
        content.Add(new StringContent(message.To), "to");
        content.Add(new StringContent(message.Subject), "subject");

        // Body content
        if (!string.IsNullOrWhiteSpace(message.HtmlBody))
        {
            content.Add(new StringContent(message.HtmlBody), "html");
        }

        if (!string.IsNullOrWhiteSpace(message.TextBody))
        {
            content.Add(new StringContent(message.TextBody), "text");
        }

        // CC recipients
        if (message.Cc is { Count: > 0 })
        {
            content.Add(new StringContent(string.Join(",", message.Cc)), "cc");
        }

        // BCC recipients
        if (message.Bcc is { Count: > 0 })
        {
            content.Add(new StringContent(string.Join(",", message.Bcc)), "bcc");
        }

        // Reply-to
        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            content.Add(new StringContent(message.ReplyTo), "h:Reply-To");
        }

        // Tags
        if (message.Tags is { Count: > 0 })
        {
            foreach (var tag in message.Tags)
            {
                content.Add(new StringContent(tag), "o:tag");
            }
        }

        // Custom headers
        if (message.Headers is { Count: > 0 })
        {
            foreach (var header in message.Headers)
            {
                content.Add(new StringContent(header.Value), $"h:{header.Key}");
            }
        }

        // Tracking options
        content.Add(new StringContent(_options.Mailgun.TrackOpens ? "yes" : "no"), "o:tracking-opens");
        content.Add(new StringContent(_options.Mailgun.TrackClicks ? "yes" : "no"), "o:tracking-clicks");

        if (_options.Mailgun.RequireTls)
        {
            content.Add(new StringContent("true"), "o:require-tls");
        }

        return content;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _httpClient.Dispose();
        _disposed = true;
    }

    private class MailgunResponse
    {
        public string? Id { get; set; }
        public string? Message { get; set; }
    }
}