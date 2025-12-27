namespace Application.DTOs.Mfa;

/// <summary>
/// Data from an MFA verification attempt.
/// </summary>
public class MfaVerificationResultDto
{
    /// <summary>
    /// The user ID associated with this verification.
    /// </summary>
    public Guid UserId { get; init; }

    /// <summary>
    /// The MFA method that was used for verification.
    /// </summary>
    public Guid? MfaMethodId { get; init; }

    /// <summary>
    /// Number of verification attempts remaining for this challenge.
    /// </summary>
    public int AttemptsRemaining { get; init; }

    /// <summary>
    /// Whether this challenge has been exhausted (no more attempts allowed).
    /// </summary>
    public bool IsExhausted { get; init; }

    /// <summary>
    /// Whether a recovery code was used for this verification.
    /// </summary>
    public bool UsedRecoveryCode { get; init; }
}