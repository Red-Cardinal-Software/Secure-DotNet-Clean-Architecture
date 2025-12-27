namespace Application.DTOs.Mfa.EmailMfa;

/// <summary>
/// Response DTO containing information about a sent email verification code.
/// </summary>
public class EmailCodeSentDto
{
    /// <summary>
    /// When the code expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Number of attempts remaining to verify the code.
    /// </summary>
    public int AttemptsRemaining { get; init; }

    /// <summary>
    /// The email address where the code was sent (masked for security).
    /// </summary>
    public string? MaskedEmail { get; init; }
}