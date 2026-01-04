namespace Application.Common.Email;

/// <summary>
/// Utility class for masking email addresses for security purposes.
/// </summary>
public static class EmailMaskingUtility
{
    /// <summary>
    /// Masks an email address by showing only the first and last few characters of the username
    /// and the domain.
    /// </summary>
    /// <param name="email">The email address to mask</param>
    /// <returns>The masked email address</returns>
    /// <example>john.doe@example.com -> j***e@example.com</example>
    public static string MaskEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return string.Empty;

        var parts = email.Split('@');
        if (parts.Length != 2)
            return "***";

        var username = parts[0];
        var domain = parts[1];

        return username.Length switch
        {
            <= 2 => username[0] + new string('*', username.Length - 1) + "@" + domain,
            <= 4 => username[0] + new string('*', username.Length - 2) + username[^1] + "@" + domain,
            _ => username[..2] + "***" + username[^1] + "@" + domain
        };
    }
}