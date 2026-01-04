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
        var propertiesToUpdate = new List<LogEventProperty>();

        foreach (var property in logEvent.Properties)
        {
            if (EmailPropertyNames.Contains(property.Key) &&
                property.Value is ScalarValue { Value: string email })
            {
                var maskedProperty = propertyFactory.CreateProperty(
                    property.Key,
                    EmailMaskingUtility.MaskEmail(email));
                propertiesToUpdate.Add(maskedProperty);
            }
        }

        foreach (var property in propertiesToUpdate)
        {
            logEvent.AddOrUpdateProperty(property);
        }
    }
}