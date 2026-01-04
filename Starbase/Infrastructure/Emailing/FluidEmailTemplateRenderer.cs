using Application.Common.Configuration;
using Application.Common.Email;
using static Application.Common.Email.EmailMaskingUtility;
using Application.Interfaces.Services;
using Fluid;
using Fluid.Values;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing;

/// <summary>
/// Renders email templates using the Fluid (Liquid) template engine.
/// Supports layouts, caching, and organization-specific templates.
/// Emails are queued for delivery by the background processor.
/// </summary>
public class FluidEmailTemplateRenderer : IEmailTemplateRenderer
{
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly IEmailQueue _emailQueue;
    private readonly ILogger<FluidEmailTemplateRenderer> _logger;
    private readonly FluidParser _parser;
    private readonly TemplateOptions _templateOptions;

    public FluidEmailTemplateRenderer(
        IEmailTemplateProvider templateProvider,
        IEmailQueue emailQueue,
        ILogger<FluidEmailTemplateRenderer> logger)
    {
        _templateProvider = templateProvider;
        _emailQueue = emailQueue;
        _logger = logger;
        _parser = new FluidParser();

        _templateOptions = new TemplateOptions
        {
            MemberAccessStrategy = new UnsafeMemberAccessStrategy()
        };

        // Register custom filters
        _templateOptions.Filters.AddFilter("mask_email", MaskEmailFilter);
        _templateOptions.Filters.AddFilter("format_date", FormatDateFilter);
    }

    /// <inheritdoc />
    public async Task<RenderedEmailTemplate> RenderAsync<TModel>(
        string templateKey,
        TModel model,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default) where TModel : class
    {
        templateKey = templateKey.ToLowerInvariant();

        // Get the template
        var template = await _templateProvider.GetTemplateAsync(templateKey, organizationId, cancellationToken);
        if (template == null)
        {
            throw new InvalidOperationException($"Email template '{templateKey}' not found.");
        }

        // Create the template context
        var context = new TemplateContext(model, _templateOptions);
        context.SetValue("model", model);

        // Render subject
        var subjectTemplate = ParseTemplate(template.Subject, $"{templateKey}:subject");
        var renderedSubject = await subjectTemplate.RenderAsync(context);

        // Render HTML body
        var htmlBodyTemplate = ParseTemplate(template.HtmlBody, $"{templateKey}:html");
        var renderedHtmlBody = await htmlBodyTemplate.RenderAsync(context);

        // Apply layout if specified
        if (!string.IsNullOrEmpty(template.LayoutKey))
        {
            renderedHtmlBody = await ApplyLayoutAsync(
                template.LayoutKey,
                renderedHtmlBody,
                model,
                organizationId,
                cancellationToken);
        }

        // Render or generate plain text body
        string renderedTextBody;
        if (!string.IsNullOrEmpty(template.TextBody))
        {
            var textBodyTemplate = ParseTemplate(template.TextBody, $"{templateKey}:text");
            renderedTextBody = await textBodyTemplate.RenderAsync(context);
        }
        else
        {
            // Auto-generate plain text from HTML
            renderedTextBody = HtmlToTextConverter.Convert(renderedHtmlBody);
        }

        _logger.LogDebug(
            "Rendered email template {TemplateKey} from {Source}",
            templateKey,
            template.Source);

        return new RenderedEmailTemplate
        {
            Subject = renderedSubject.Trim(),
            HtmlBody = renderedHtmlBody,
            TextBody = renderedTextBody,
            TemplateKey = templateKey,
            Source = template.Source
        };
    }

    /// <inheritdoc />
    public async Task<EmailSendResult> RenderAndSendAsync<TModel>(
        string templateKey,
        string to,
        TModel model,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default) where TModel : class
    {
        var rendered = await RenderAsync(templateKey, model, organizationId, cancellationToken);

        try
        {
            var emailId = await _emailQueue.QueueAsync(
                to: to,
                email: rendered,
                organizationId: organizationId,
                cancellationToken: cancellationToken);

            _logger.LogInformation(
                "Email queued for delivery. Id={EmailId}, Template={TemplateKey}, To={Recipient}",
                emailId,
                templateKey,
                MaskEmail(to));

            return new EmailSendResult
            {
                Success = true,
                MessageId = emailId.ToString(),
                Provider = "Queue"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to queue email. Template={TemplateKey}, To={Recipient}",
                templateKey,
                MaskEmail(to));

            return new EmailSendResult
            {
                Success = false,
                ErrorMessage = ex.Message,
                Provider = "Queue"
            };
        }
    }

    private async Task<string> ApplyLayoutAsync<TModel>(
        string layoutKey,
        string content,
        TModel model,
        Guid? organizationId,
        CancellationToken cancellationToken) where TModel : class
    {
        var layout = await _templateProvider.GetLayoutAsync(layoutKey, organizationId, cancellationToken);
        if (layout == null)
        {
            _logger.LogWarning("Layout template '{LayoutKey}' not found, using content without layout", layoutKey);
            return content;
        }

        var context = new TemplateContext(model, _templateOptions);
        context.SetValue("model", model);
        context.SetValue("content", content);

        var layoutTemplate = ParseTemplate(layout.HtmlBody, $"layout:{layoutKey}");
        return await layoutTemplate.RenderAsync(context);
    }

    private IFluidTemplate ParseTemplate(string template, string templateName)
    {
        if (_parser.TryParse(template, out var fluidTemplate, out var error))
        {
            return fluidTemplate;
        }

        throw new InvalidOperationException($"Failed to parse template '{templateName}': {error}");
    }

    // Custom Fluid filters
    private static ValueTask<FluidValue> MaskEmailFilter(FluidValue input, FilterArguments arguments, TemplateContext context)
    {
        var email = input.ToStringValue();
        return new ValueTask<FluidValue>(new StringValue(MaskEmail(email)));
    }

    private static ValueTask<FluidValue> FormatDateFilter(FluidValue input, FilterArguments arguments, TemplateContext context)
    {
        var format = arguments.At(0).ToStringValue();
        if (string.IsNullOrEmpty(format))
            format = "yyyy-MM-dd HH:mm:ss";

        if (input.ToObjectValue() is DateTimeOffset dto)
        {
            return new ValueTask<FluidValue>(new StringValue(dto.ToString(format)));
        }

        if (input.ToObjectValue() is DateTime dt)
        {
            return new ValueTask<FluidValue>(new StringValue(dt.ToString(format)));
        }

        return new ValueTask<FluidValue>(input);
    }
}