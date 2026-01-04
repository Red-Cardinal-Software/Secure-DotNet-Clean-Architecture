using Application.Common.Email;

namespace Application.Interfaces.Services;

/// <summary>
/// Renders email templates using the Fluid (Liquid) template engine.
/// Supports layouts, partials, and organization-specific templates.
/// </summary>
public interface IEmailTemplateRenderer
{
    /// <summary>
    /// Renders an email template with the provided model.
    /// </summary>
    /// <typeparam name="TModel">The model type.</typeparam>
    /// <param name="templateKey">The template key (e.g., "password-reset").</param>
    /// <param name="model">The model containing template data.</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific templates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The rendered email content.</returns>
    Task<RenderedEmailTemplate> RenderAsync<TModel>(
        string templateKey,
        TModel model,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default) where TModel : class;

    /// <summary>
    /// Renders an email template with the provided model and sends it.
    /// </summary>
    /// <typeparam name="TModel">The model type.</typeparam>
    /// <param name="templateKey">The template key.</param>
    /// <param name="to">The recipient email address.</param>
    /// <param name="model">The model containing template data.</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific templates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the send operation.</returns>
    Task<EmailSendResult> RenderAndSendAsync<TModel>(
        string templateKey,
        string to,
        TModel model,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default) where TModel : class;
}

/// <summary>
/// Represents a fully rendered email template.
/// </summary>
public class RenderedEmailTemplate
{
    /// <summary>
    /// The rendered subject line.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The rendered HTML body.
    /// </summary>
    public required string HtmlBody { get; init; }

    /// <summary>
    /// The rendered plain text body.
    /// </summary>
    public required string TextBody { get; init; }

    /// <summary>
    /// The template key that was rendered.
    /// </summary>
    public required string TemplateKey { get; init; }

    /// <summary>
    /// The source of the template that was used.
    /// </summary>
    public EmailTemplateSource Source { get; init; }
}