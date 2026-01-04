using Application.Common.Email;
using Serilog.Core;
using Serilog.Events;

namespace Infrastructure.Logging;

/// <summary>
/// Serilog enricher that automatically masks email addresses in log properties.
/// Detects properties by name (Email, To, Recipient, etc.) and masks their values.
/// </summary>
public class EmailMaskingEnricher : ILogEventEnricher
{
    private static readonly HashSet<string> EmailPropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Email",
        "EmailAddress",
        "To",
        "From",
        "Recipient",
        "Cc",
        "Bcc",
        "ReplyTo",
        "SenderEmail",
        "RecipientEmail"
    };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        var maskedProperties = logEvent.Properties
            .Where(p => EmailPropertyNames.Contains(p.Key) &&
                        p.Value is ScalarValue { Value: string })
            .Select(p => propertyFactory.CreateProperty(
                p.Key,
                EmailMaskingUtility.MaskEmail(((ScalarValue)p.Value).Value as string ?? string.Empty)))
            .ToList();

        foreach (var property in maskedProperties)
        {
            logEvent.AddOrUpdateProperty(property);
        }
    }
}