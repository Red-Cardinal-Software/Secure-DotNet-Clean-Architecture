namespace Application.DTOs.Mfa.EmailMfa;

/// <summary>
/// Response DTO for email code verification result.
/// </summary>
public class EmailCodeVerificationDto
{
    /// <summary>
    /// Number of attempts remaining if verification failed.
    /// </summary>
    public int? AttemptsRemaining { get; init; }
}