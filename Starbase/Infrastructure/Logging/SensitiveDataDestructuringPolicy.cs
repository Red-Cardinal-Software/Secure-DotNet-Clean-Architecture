using System;
using System.Linq;
using System.Reflection;
using Domain.Attributes;
using Serilog.Core;
using Serilog.Events;

namespace Infrastructure.Logging;

/// <summary>
/// Serilog destructuring policy that masks properties marked with [SensitiveData] attribute
/// or matching known sensitive property names.
/// This provides consistent masking between Serilog logs and the audit ledger.
/// </summary>
public class SensitiveDataDestructuringPolicy : IDestructuringPolicy
{
    private const string RedactedValue = "[REDACTED]";

    /// <summary>
    /// Default sensitive property names - matches AuditInterceptor.DefaultSensitiveProperties.
    /// </summary>
    private static readonly HashSet<string> DefaultSensitiveProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "Password",
        "PasswordHash",
        "SecretKey",
        "TotpSecret",
        "RecoveryCode",
        "Token",
        "RefreshToken",
        "PushToken",
        "PublicKey",
        "PrivateKey",
        "Secret",
        "ApiKey",
        "AccessToken",
        "Credential",
        "Credentials"
    };

    public bool TryDestructure(object value, ILogEventPropertyValueFactory propertyValueFactory, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out LogEventPropertyValue? result)
    {
        result = null;

        if (value == null)
            return false;

        var type = value.GetType();

        // Only process complex objects, not primitives
        if (type.IsPrimitive || type == typeof(string) || type == typeof(decimal) || type.IsEnum)
            return false;

        // Skip collections - let Serilog handle them, but their items will be processed
        if (type.IsArray || (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>)))
            return false;

        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        // If no properties need masking, let Serilog handle it normally
        if (!HasSensitiveProperties(properties))
            return false;

        var logEventProperties = new List<LogEventProperty>();

        foreach (var prop in properties.Where(p => p.CanRead))
        {
            try
            {
                var propValue = prop.GetValue(value);
                var isSensitive = IsSensitiveProperty(prop);

                LogEventPropertyValue logValue;
                if (isSensitive)
                {
                    logValue = new ScalarValue(RedactedValue);
                }
                else if (propValue == null)
                {
                    logValue = new ScalarValue(null);
                }
                else
                {
                    logValue = propertyValueFactory.CreatePropertyValue(propValue, destructureObjects: true);
                }

                logEventProperties.Add(new LogEventProperty(prop.Name, logValue));
            }
            catch (Exception ex) when (
                ex is TargetInvocationException or MethodAccessException or TargetException or ArgumentException or InvalidOperationException or NotSupportedException
                )
            {
                // Prefer the underlying getter exception when present
                var root = (ex as TargetInvocationException)?.InnerException ?? ex;

                logEventProperties.Add(new LogEventProperty(prop.Name, new ScalarValue($"[ERROR READING: {root.GetType().Name}: {root.Message}")));
            }
        }

        result = new StructureValue(logEventProperties, type.Name);
        return true;
    }

    private static bool HasSensitiveProperties(PropertyInfo[] properties)
    {
        return properties.Any(IsSensitiveProperty);
    }

    private static bool IsSensitiveProperty(PropertyInfo prop)
    {
        // Check for [SensitiveData] attribute
        if (prop.GetCustomAttribute<SensitiveDataAttribute>() != null)
            return true;

        // Check against default sensitive property names
        if (DefaultSensitiveProperties.Contains(prop.Name))
            return true;

        // Check if property name contains sensitive keywords
        var lowerName = prop.Name.ToLowerInvariant();
        return lowerName.Contains("password") ||
               lowerName.Contains("secret") ||
               lowerName.Contains("token") ||
               lowerName.Contains("credential") ||
               lowerName.Contains("apikey");
    }
}