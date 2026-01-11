namespace Application.Interfaces.Services;

/// <summary>
/// Provides email templates with support for file-based defaults,
/// database overrides, and organization-specific customization.
/// </summary>
public interface IEmailTemplateProvider
{
    /// <summary>
    /// Gets an email template by key with optional organization-specific override.
    /// Resolution order: Org-specific DB -> Global DB -> File-based -> null
    /// </summary>
    /// <param name="templateKey">The template key (e.g., "password-reset").</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific templates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The template content, or null if not found.</returns>
    Task<EmailTemplateContent?> GetTemplateAsync(
        string templateKey,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a layout template by key.
    /// </summary>
    /// <param name="layoutKey">The layout key (e.g., "default").</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific layouts.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The layout content, or null if not found.</returns>
    Task<EmailTemplateContent?> GetLayoutAsync(
        string layoutKey,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a template exists.
    /// </summary>
    /// <param name="templateKey">The template key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the template exists in any source.</returns>
    Task<bool> TemplateExistsAsync(string templateKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all available template keys.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of all template keys.</returns>
    Task<IReadOnlyList<string>> GetTemplateKeysAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents the content of an email template.
/// </summary>
public class EmailTemplateContent
{
    /// <summary>
    /// The template key.
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// The email subject template (supports Liquid syntax).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The HTML body template (supports Liquid syntax).
    /// </summary>
    public required string HtmlBody { get; init; }

    /// <summary>
    /// Optional plain text body template. If null, will be auto-generated from HTML.
    /// </summary>
    public string? TextBody { get; init; }

    /// <summary>
    /// Optional layout key to wrap this template.
    /// </summary>
    public string? LayoutKey { get; init; }

    /// <summary>
    /// The source of this template (File, Database, DatabaseOrg).
    /// </summary>
    public EmailTemplateSource Source { get; init; }

    /// <summary>
    /// The organization ID if this is an org-specific template.
    /// </summary>
    public Guid? OrganizationId { get; init; }
}

/// <summary>
/// The source of an email template.
/// </summary>
public enum EmailTemplateSource
{
    /// <summary>
    /// Template loaded from embedded file resources.
    /// </summary>
    File,

    /// <summary>
    /// Template loaded from database (global).
    /// </summary>
    Database,

    /// <summary>
    /// Template loaded from database (organization-specific).
    /// </summary>
    DatabaseOrganization
}