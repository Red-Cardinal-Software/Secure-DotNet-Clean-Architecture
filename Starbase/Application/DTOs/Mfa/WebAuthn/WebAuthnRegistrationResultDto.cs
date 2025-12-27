namespace Application.DTOs.Mfa.WebAuthn;

/// <summary>
/// Response DTO for WebAuthn credential registration completion.
/// </summary>
public class WebAuthnRegistrationResultDto
{
    /// <summary>
    /// The ID of the registered credential.
    /// </summary>
    public Guid CredentialId { get; init; }
}