namespace Application.DTOs.Mfa.WebAuthn;

/// <summary>
/// Response DTO for WebAuthn authentication completion.
/// </summary>
public class WebAuthnAuthenticationResultDto
{
    /// <summary>
    /// The authenticated user's ID.
    /// </summary>
    public Guid UserId { get; init; }

    /// <summary>
    /// The credential ID that was used for authentication.
    /// </summary>
    public Guid CredentialId { get; init; }
}