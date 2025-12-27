namespace Application.DTOs.Mfa.EmailMfa;

/// <summary>
/// Response DTO for email MFA rate limit status.
/// </summary>
public class EmailRateLimitDto
{
    /// <summary>
    /// Whether the user is currently allowed to request a new code.
    /// </summary>
    public bool IsAllowed { get; init; }

    /// <summary>
    /// Number of codes used in the current rate limit window.
    /// </summary>
    public int CodesUsed { get; init; }

    /// <summary>
    /// Maximum codes allowed in the rate limit window.
    /// </summary>
    public int MaxCodes { get; init; }

    /// <summary>
    /// When the rate limit window resets.
    /// </summary>
    public DateTimeOffset? ResetTime { get; init; }
}