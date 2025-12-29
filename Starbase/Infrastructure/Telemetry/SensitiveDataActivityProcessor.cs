using System.Diagnostics;
using System.Text.RegularExpressions;
using OpenTelemetry;

namespace Infrastructure.Telemetry;

/// <summary>
/// OpenTelemetry activity processor that redacts sensitive data from span attributes.
/// Provides consistent masking with Serilog and the audit ledger.
/// </summary>
public partial class SensitiveDataActivityProcessor : BaseProcessor<Activity>
{
    private const string RedactedValue = "[REDACTED]";

    /// <summary>
    /// Attribute keys that should always be redacted.
    /// </summary>
    private static readonly HashSet<string> SensitiveAttributeKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "db.statement",        // SQL queries may contain sensitive values
        "http.request.body",   // Request bodies
        "http.response.body",  // Response bodies
        "enduser.id",          // Could be sensitive
        "enduser.credential",  // Auth credentials
        "db.connection_string" // Connection strings with passwords
    };

    /// <summary>
    /// Patterns in attribute keys that indicate sensitivity.
    /// </summary>
    private static readonly string[] SensitiveKeyPatterns =
    [
        "password",
        "secret",
        "token",
        "credential",
        "apikey",
        "api_key",
        "authorization"
    ];

    /// <summary>
    /// Regex patterns for values that look like secrets.
    /// </summary>
    private static readonly Regex[] SensitiveValuePatterns =
    [
        JwtPattern(),        // JWT tokens
        BearerPattern(),     // Bearer tokens
        BasicAuthPattern(),  // Basic auth
        ApiKeyPattern(),     // Common API key formats
        PasswordPattern()    // Password in connection strings
    ];

    public override void OnEnd(Activity data)
    {
        if (data.TagObjects == null)
            return;

        var tagsToRedact = new List<KeyValuePair<string, object?>>();

        foreach (var tag in data.TagObjects)
        {
            if (ShouldRedact(tag.Key, tag.Value))
            {
                tagsToRedact.Add(tag);
            }
        }

        // Replace sensitive tags with redacted versions
        foreach (var tag in tagsToRedact)
        {
            data.SetTag(tag.Key, RedactedValue);
        }

        // Sanitize SQL statements - keep structure but redact values
        var dbStatement = data.GetTagItem("db.statement") as string;
        if (!string.IsNullOrEmpty(dbStatement))
        {
            data.SetTag("db.statement", SanitizeSqlStatement(dbStatement));
        }

        base.OnEnd(data);
    }

    private static bool ShouldRedact(string key, object? value)
    {
        // Check if key is in sensitive list
        if (SensitiveAttributeKeys.Contains(key))
            return true;

        // Check if key contains sensitive patterns
        var lowerKey = key.ToLowerInvariant();
        foreach (var pattern in SensitiveKeyPatterns)
        {
            if (lowerKey.Contains(pattern))
                return true;
        }

        // Check if value looks like a secret
        if (value is string strValue && !string.IsNullOrEmpty(strValue))
        {
            foreach (var pattern in SensitiveValuePatterns)
            {
                if (pattern.IsMatch(strValue))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Sanitizes SQL statements by replacing literal values with placeholders.
    /// Preserves query structure for debugging while protecting data.
    /// </summary>
    private static string SanitizeSqlStatement(string sql)
    {
        // Replace string literals 'value' with '?'
        sql = StringLiteralPattern().Replace(sql, "'?'");

        // Replace numeric values (but not in identifiers)
        sql = NumericValuePattern().Replace(sql, " ? ");

        // Replace N'unicode strings'
        sql = UnicodeStringPattern().Replace(sql, "N'?'");

        return sql;
    }

    // Regex patterns compiled for performance
    [GeneratedRegex(@"'[^']*'")]
    private static partial Regex StringLiteralPattern();

    [GeneratedRegex(@"(?<=\s|=|,)\d+(?=\s|,|$|\))")]
    private static partial Regex NumericValuePattern();

    [GeneratedRegex(@"N'[^']*'")]
    private static partial Regex UnicodeStringPattern();

    [GeneratedRegex(@"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")]
    private static partial Regex JwtPattern();

    [GeneratedRegex(@"^Bearer\s+.+", RegexOptions.IgnoreCase)]
    private static partial Regex BearerPattern();

    [GeneratedRegex(@"^Basic\s+[A-Za-z0-9+/=]+", RegexOptions.IgnoreCase)]
    private static partial Regex BasicAuthPattern();

    [GeneratedRegex(@"^[A-Za-z0-9]{32,}$")]
    private static partial Regex ApiKeyPattern();

    [GeneratedRegex(@"password=[^;]+", RegexOptions.IgnoreCase)]
    private static partial Regex PasswordPattern();
}