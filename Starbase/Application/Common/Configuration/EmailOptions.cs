using System.ComponentModel.DataAnnotations;

namespace Application.Common.Configuration;

/// <summary>
/// Configuration options for the email subsystem.
/// The email provider is selected at compile-time via template flags (UseSendGrid, UseAwsSes, UseSmtp).
/// </summary>
public class EmailOptions
{
    public const string SectionName = "Email";

    /// <summary>
    /// The email address to send from.
    /// </summary>
    [Required]
    [EmailAddress]
    public string FromAddress { get; set; } = "noreply@example.com";

    /// <summary>
    /// The display name for the sender.
    /// </summary>
    [Required]
    public string FromName { get; set; } = "Starbase";

    /// <summary>
    /// Whether to include a plain text version of HTML emails.
    /// </summary>
    public bool IncludePlainText { get; set; } = true;

    /// <summary>
    /// SMTP provider configuration (when UseSmtp flag is set).
    /// </summary>
    public SmtpOptions Smtp { get; set; } = new();

    /// <summary>
    /// SendGrid provider configuration (when UseSendGrid flag is set).
    /// </summary>
    public SendGridOptions SendGrid { get; set; } = new();

    /// <summary>
    /// AWS SES provider configuration (when UseAwsSes flag is set).
    /// </summary>
    public SesOptions Ses { get; set; } = new();

    /// <summary>
    /// Postmark provider configuration (when UsePostmark flag is set).
    /// </summary>
    public PostmarkOptions Postmark { get; set; } = new();

    /// <summary>
    /// Mailgun provider configuration (when UseMailgun flag is set).
    /// </summary>
    public MailgunOptions Mailgun { get; set; } = new();

    /// <summary>
    /// Mailchimp Transactional (Mandrill) provider configuration (when UseMailchimp flag is set).
    /// </summary>
    public MailchimpOptions Mailchimp { get; set; } = new();

    /// <summary>
    /// Template configuration.
    /// </summary>
    public EmailTemplateOptions Templates { get; set; } = new();
}

/// <summary>
/// SMTP email provider configuration.
/// </summary>
public class SmtpOptions
{
    /// <summary>
    /// SMTP server hostname.
    /// </summary>
    public string Host { get; set; } = "localhost";

    /// <summary>
    /// SMTP server port.
    /// </summary>
    [Range(1, 65535)]
    public int Port { get; set; } = 587;

    /// <summary>
    /// Whether to use SSL/TLS.
    /// </summary>
    public bool UseSsl { get; set; } = true;

    /// <summary>
    /// SMTP username for authentication. Leave empty for no authentication.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// SMTP password for authentication.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Connection timeout in seconds.
    /// </summary>
    [Range(5, 120)]
    public int TimeoutSeconds { get; set; } = 30;
}

/// <summary>
/// SendGrid email provider configuration.
/// </summary>
public class SendGridOptions
{
    /// <summary>
    /// SendGrid API key.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Whether to use the sandbox mode for testing.
    /// </summary>
    public bool SandboxMode { get; set; } = false;
}

/// <summary>
/// AWS SES email provider configuration.
/// </summary>
public class SesOptions
{
    /// <summary>
    /// AWS region for SES (e.g., "us-east-1").
    /// </summary>
    public string Region { get; set; } = "us-east-1";

    /// <summary>
    /// AWS access key ID. Leave empty to use default credentials chain.
    /// </summary>
    public string? AccessKeyId { get; set; }

    /// <summary>
    /// AWS secret access key.
    /// </summary>
    public string? SecretAccessKey { get; set; }

    /// <summary>
    /// Optional configuration set name for tracking.
    /// </summary>
    public string? ConfigurationSetName { get; set; }
}

/// <summary>
/// Postmark email provider configuration.
/// </summary>
public class PostmarkOptions
{
    /// <summary>
    /// Postmark server API token.
    /// </summary>
    public string? ServerToken { get; set; }

    /// <summary>
    /// Optional message stream ID for transactional vs broadcast emails.
    /// Defaults to "outbound" (transactional).
    /// </summary>
    public string MessageStream { get; set; } = "outbound";

    /// <summary>
    /// Whether to track email opens.
    /// </summary>
    public bool TrackOpens { get; set; } = true;

    /// <summary>
    /// Link tracking mode: None, HtmlAndText, HtmlOnly, TextOnly.
    /// </summary>
    public string TrackLinks { get; set; } = "None";
}

/// <summary>
/// Mailgun email provider configuration.
/// </summary>
public class MailgunOptions
{
    /// <summary>
    /// Mailgun API key.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Mailgun sending domain (e.g., "mg.yourdomain.com").
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>
    /// Mailgun API base URL. Use "https://api.eu.mailgun.net" for EU region.
    /// </summary>
    public string BaseUrl { get; set; } = "https://api.mailgun.net";

    /// <summary>
    /// Whether to track email opens.
    /// </summary>
    public bool TrackOpens { get; set; } = true;

    /// <summary>
    /// Whether to track email clicks.
    /// </summary>
    public bool TrackClicks { get; set; } = false;

    /// <summary>
    /// Whether to require TLS for delivery.
    /// </summary>
    public bool RequireTls { get; set; } = false;
}

/// <summary>
/// Mailchimp Transactional (Mandrill) email provider configuration.
/// Requires a Mailchimp Standard or Premium subscription.
/// </summary>
public class MailchimpOptions
{
    /// <summary>
    /// Mandrill API key from your Mailchimp Transactional account.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Whether to track email opens.
    /// </summary>
    public bool TrackOpens { get; set; } = true;

    /// <summary>
    /// Whether to track email clicks.
    /// </summary>
    public bool TrackClicks { get; set; } = true;

    /// <summary>
    /// Whether to automatically generate a text part for messages without one.
    /// </summary>
    public bool AutoText { get; set; } = true;

    /// <summary>
    /// Whether to automatically inline CSS styles for better email client compatibility.
    /// </summary>
    public bool InlineCss { get; set; } = true;
}

/// <summary>
/// Email queue processor configuration.
/// </summary>
public class EmailQueueOptions
{
    public const string SectionName = "EmailQueue";

    /// <summary>
    /// Whether the email queue processor is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Number of emails to process per batch.
    /// </summary>
    [Range(1, 100)]
    public int BatchSize { get; set; } = 10;

    /// <summary>
    /// Maximum number of delivery attempts before marking as failed.
    /// </summary>
    [Range(1, 10)]
    public int MaxAttempts { get; set; } = 3;

    /// <summary>
    /// Number of days to keep sent/failed emails before cleanup.
    /// </summary>
    [Range(1, 365)]
    public int RetentionDays { get; set; } = 30;
}

/// <summary>
/// Email template configuration.
/// </summary>
public class EmailTemplateOptions
{
    /// <summary>
    /// Whether to enable database template overrides.
    /// When false, only file-based templates are used.
    /// </summary>
    public bool EnableDatabaseTemplates { get; set; } = true;

    /// <summary>
    /// Whether to enable organization-specific template overrides.
    /// Requires EnableDatabaseTemplates to be true.
    /// </summary>
    public bool EnableOrganizationTemplates { get; set; } = true;

    /// <summary>
    /// Default layout template key to use when no layout is specified.
    /// </summary>
    public string DefaultLayout { get; set; } = "default";

    /// <summary>
    /// Cache duration for templates in minutes.
    /// </summary>
    [Range(1, 1440)]
    public int CacheDurationMinutes { get; set; } = 15;
}