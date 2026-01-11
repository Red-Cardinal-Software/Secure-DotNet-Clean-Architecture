using System.Reflection;
using Application.Common.Configuration;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Emailing;

/// <summary>
/// Provides email templates with hybrid resolution:
/// 1. Organization-specific database template (if org context provided)
/// 2. Global database template
/// 3. File-based embedded resource template
/// </summary>
public class HybridEmailTemplateProvider : IEmailTemplateProvider
{
    private readonly IEmailTemplateRepository _repository;
    private readonly IMemoryCache _cache;
    private readonly EmailOptions _options;
    private readonly ILogger<HybridEmailTemplateProvider> _logger;

    private const string TemplateResourcePrefix = "Infrastructure.Emailing.Templates.";
    private const string LayoutResourcePrefix = "Infrastructure.Emailing.Templates._layouts.";
    private static readonly Assembly ResourceAssembly = typeof(HybridEmailTemplateProvider).Assembly;

    // Cache of available embedded template keys
    private static readonly Lazy<IReadOnlyList<string>> EmbeddedTemplateKeys = new(LoadEmbeddedTemplateKeys);

    public HybridEmailTemplateProvider(
        IEmailTemplateRepository repository,
        IMemoryCache cache,
        IOptions<EmailOptions> options,
        ILogger<HybridEmailTemplateProvider> logger)
    {
        _repository = repository;
        _cache = cache;
        _options = options.Value;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<EmailTemplateContent?> GetTemplateAsync(
        string templateKey,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default)
    {
        templateKey = templateKey.ToLowerInvariant();
        var cacheKey = GetCacheKey(templateKey, organizationId);

        // Try cache first
        if (_cache.TryGetValue(cacheKey, out EmailTemplateContent? cached))
        {
            return cached;
        }

        EmailTemplateContent? template = null;

        // 1. Try organization-specific database template
        if (_options.Templates.EnableDatabaseTemplates &&
            _options.Templates.EnableOrganizationTemplates &&
            organizationId.HasValue)
        {
            template = await GetDatabaseTemplateAsync(templateKey, organizationId.Value, cancellationToken);
            if (template != null)
            {
                _logger.LogDebug(
                    "Resolved template {TemplateKey} from organization {OrganizationId} database",
                    templateKey,
                    organizationId);
            }
        }

        // 2. Try global database template
        if (template == null && _options.Templates.EnableDatabaseTemplates)
        {
            template = await GetDatabaseTemplateAsync(templateKey, null, cancellationToken);
            if (template != null)
            {
                _logger.LogDebug("Resolved template {TemplateKey} from global database", templateKey);
            }
        }

        // 3. Fall back to file-based template
        if (template == null)
        {
            template = GetFileTemplate(templateKey);
            if (template != null)
            {
                _logger.LogDebug("Resolved template {TemplateKey} from embedded resources", templateKey);
            }
        }

        // Cache the result (even if null, to avoid repeated lookups)
        if (template != null)
        {
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromMinutes(_options.Templates.CacheDurationMinutes));
            _cache.Set(cacheKey, template, cacheOptions);
        }

        return template;
    }

    /// <inheritdoc />
    public async Task<EmailTemplateContent?> GetLayoutAsync(
        string layoutKey,
        Guid? organizationId = null,
        CancellationToken cancellationToken = default)
    {
        // Layouts use the same resolution logic but with a "_layout." prefix
        var templateKey = $"_layout.{layoutKey.ToLowerInvariant()}";
        return await GetTemplateAsync(templateKey, organizationId, cancellationToken)
            ?? GetFileLayout(layoutKey.ToLowerInvariant());
    }

    /// <inheritdoc />
    public async Task<bool> TemplateExistsAsync(string templateKey, CancellationToken cancellationToken = default)
    {
        templateKey = templateKey.ToLowerInvariant();

        // Check embedded resources first (fast)
        if (EmbeddedTemplateKeys.Value.Contains(templateKey))
            return true;

        // Check database
        if (_options.Templates.EnableDatabaseTemplates)
        {
            var dbTemplate = await _repository.GetEmailTemplateByKeyAsync(templateKey);
            return dbTemplate != null;
        }

        return false;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetTemplateKeysAsync(CancellationToken cancellationToken = default)
    {
        var keys = new HashSet<string>(EmbeddedTemplateKeys.Value);

        if (_options.Templates.EnableDatabaseTemplates)
        {
            var dbKeys = await _repository.GetAllTemplateKeysAsync();
            foreach (var key in dbKeys)
            {
                keys.Add(key.ToLowerInvariant());
            }
        }

        return keys.OrderBy(k => k).ToList();
    }

    private async Task<EmailTemplateContent?> GetDatabaseTemplateAsync(
        string templateKey,
        Guid? organizationId,
        CancellationToken cancellationToken)
    {
        var template = await _repository.GetTemplateAsync(templateKey, organizationId);
        if (template == null || !template.IsActive)
            return null;

        return new EmailTemplateContent
        {
            Key = template.Key,
            Subject = template.Subject,
            HtmlBody = template.HtmlBody,
            TextBody = template.TextBody,
            LayoutKey = template.LayoutKey ?? _options.Templates.DefaultLayout,
            Source = organizationId.HasValue
                ? EmailTemplateSource.DatabaseOrganization
                : EmailTemplateSource.Database,
            OrganizationId = template.OrganizationId
        };
    }

    private EmailTemplateContent? GetFileTemplate(string templateKey)
    {
        var htmlResourceName = $"{TemplateResourcePrefix}{templateKey}.html";
        var subjectResourceName = $"{TemplateResourcePrefix}{templateKey}.subject.txt";
        var textResourceName = $"{TemplateResourcePrefix}{templateKey}.txt";

        var htmlContent = ReadEmbeddedResource(htmlResourceName);
        if (htmlContent == null)
            return null;

        var subject = ReadEmbeddedResource(subjectResourceName)
            ?? ExtractSubjectFromHtml(htmlContent)
            ?? $"[{templateKey}]";

        var textContent = ReadEmbeddedResource(textResourceName);

        return new EmailTemplateContent
        {
            Key = templateKey,
            Subject = subject.Trim(),
            HtmlBody = htmlContent,
            TextBody = textContent,
            LayoutKey = _options.Templates.DefaultLayout,
            Source = EmailTemplateSource.File
        };
    }

    private EmailTemplateContent? GetFileLayout(string layoutKey)
    {
        var resourceName = $"{LayoutResourcePrefix}{layoutKey}.html";
        var content = ReadEmbeddedResource(resourceName);

        if (content == null)
            return null;

        return new EmailTemplateContent
        {
            Key = $"_layout.{layoutKey}",
            Subject = string.Empty,
            HtmlBody = content,
            Source = EmailTemplateSource.File
        };
    }

    private static string? ReadEmbeddedResource(string resourceName)
    {
        using var stream = ResourceAssembly.GetManifestResourceStream(resourceName);
        if (stream == null)
            return null;

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string? ExtractSubjectFromHtml(string html)
    {
        // Try to extract subject from <title> tag
        var titleStart = html.IndexOf("<title>", StringComparison.OrdinalIgnoreCase);
        if (titleStart < 0)
            return null;

        titleStart += 7; // Length of "<title>"
        var titleEnd = html.IndexOf("</title>", titleStart, StringComparison.OrdinalIgnoreCase);
        if (titleEnd < 0)
            return null;

        return html[titleStart..titleEnd].Trim();
    }

    private static string GetCacheKey(string templateKey, Guid? organizationId)
    {
        return organizationId.HasValue
            ? $"email_template:{templateKey}:org:{organizationId}"
            : $"email_template:{templateKey}:global";
    }

    private static IReadOnlyList<string> LoadEmbeddedTemplateKeys()
    {
        var resources = ResourceAssembly.GetManifestResourceNames();

        var candidateKeys = resources
            .Where(r => r.StartsWith(TemplateResourcePrefix))
            .Where(r => !r.StartsWith(LayoutResourcePrefix))
            .Select(r => r[TemplateResourcePrefix.Length..])
            .Where(r => r.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            .Select(r => r[..^5]); // Remove ".html"

        return candidateKeys
            .Distinct()
            .ToList();
    }
}