using Domain.Entities.Identity;

namespace Domain.Entities.Configuration;

/// <summary>
/// Represents a template for emails within the system.
/// Supports organization-specific overrides, layouts, and both HTML and plain text content.
/// </summary>
/// <remarks>
/// Templates use Liquid syntax for dynamic content. Resolution order:
/// 1. Organization-specific template (if OrganizationId matches)
/// 2. Global template (OrganizationId is null)
/// 3. File-based template (embedded resources)
/// </remarks>
public class EmailTemplate
{
    /// <summary>
    /// Gets the unique identifier for the email template.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Gets the unique key associated with the email template (e.g., "password-reset").
    /// </summary>
    public string Key { get; private set; } = null!;

    /// <summary>
    /// Gets the organization ID for tenant-specific templates.
    /// Null indicates a global template.
    /// </summary>
    public Guid? OrganizationId { get; private set; }

    /// <summary>
    /// Gets the subject of the email template. Supports Liquid syntax.
    /// </summary>
    public string Subject { get; private set; } = null!;

    /// <summary>
    /// Gets the HTML body content of the email template. Supports Liquid syntax.
    /// </summary>
    public string HtmlBody { get; private set; } = null!;

    /// <summary>
    /// Gets the optional plain text body content.
    /// If null, plain text will be auto-generated from HTML.
    /// </summary>
    public string? TextBody { get; private set; }

    /// <summary>
    /// Gets the optional layout template key to wrap this template.
    /// </summary>
    public string? LayoutKey { get; private set; }

    /// <summary>
    /// Indicates whether the template is active.
    /// Inactive templates are skipped during resolution.
    /// </summary>
    public bool IsActive { get; private set; } = true;

    /// <summary>
    /// Gets the timestamp when this template was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// Gets the timestamp when this template was last modified.
    /// </summary>
    public DateTimeOffset? ModifiedAt { get; private set; }

    /// <summary>
    /// Navigation property to the organization (if tenant-specific).
    /// </summary>
    public Organization? Organization { get; private set; }

    /// <summary>
    /// Constructor for EF Core
    /// </summary>
    protected EmailTemplate() { }

    /// <summary>
    /// Creates a new email template.
    /// </summary>
    /// <param name="key">The unique template key.</param>
    /// <param name="subject">The email subject (supports Liquid syntax).</param>
    /// <param name="htmlBody">The HTML body content (supports Liquid syntax).</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific template.</param>
    /// <param name="textBody">Optional plain text body. If null, will be auto-generated.</param>
    /// <param name="layoutKey">Optional layout template key.</param>
    public EmailTemplate(
        string key,
        string subject,
        string htmlBody,
        Guid? organizationId = null,
        string? textBody = null,
        string? layoutKey = null)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentNullException(nameof(key), "Email template key cannot be null or whitespace.");

        if (string.IsNullOrWhiteSpace(subject))
            throw new ArgumentNullException(nameof(subject), "Subject cannot be null or whitespace.");

        if (string.IsNullOrWhiteSpace(htmlBody))
            throw new ArgumentNullException(nameof(htmlBody), "HTML body cannot be null or whitespace.");

        Id = Guid.NewGuid();
        Key = key.ToLowerInvariant();
        OrganizationId = organizationId;
        Subject = subject;
        HtmlBody = htmlBody;
        TextBody = textBody;
        LayoutKey = layoutKey;
        IsActive = true;
        CreatedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Updates the content of the email template.
    /// </summary>
    public void UpdateContent(string subject, string htmlBody, string? textBody = null)
    {
        if (string.IsNullOrWhiteSpace(subject))
            throw new ArgumentNullException(nameof(subject), "Subject cannot be null or whitespace.");
        if (string.IsNullOrWhiteSpace(htmlBody))
            throw new ArgumentNullException(nameof(htmlBody), "HTML body cannot be null or whitespace.");

        Subject = subject;
        HtmlBody = htmlBody;
        TextBody = textBody;
        ModifiedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Sets the layout template key.
    /// </summary>
    public void SetLayout(string? layoutKey)
    {
        LayoutKey = layoutKey;
        ModifiedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Activates or deactivates the template.
    /// </summary>
    public void SetActive(bool isActive)
    {
        IsActive = isActive;
        ModifiedAt = DateTimeOffset.UtcNow;
    }
}
