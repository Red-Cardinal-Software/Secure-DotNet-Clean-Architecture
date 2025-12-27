using Application.DTOs.Mfa.WebAuthn;
using Application.Models;
using Domain.Entities.Security;

namespace Application.Interfaces.Services;

/// <summary>
/// Service interface for managing WebAuthn/FIDO2 operations.
/// Handles credential registration, authentication challenges, and verification.
/// </summary>
public interface IWebAuthnService
{
    /// <summary>
    /// Starts the WebAuthn registration process for a user.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="mfaMethodId">The MFA method ID</param>
    /// <param name="userName">The user's name</param>
    /// <param name="userDisplayName">The user's display name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration challenge options</returns>
    Task<ServiceResponse<WebAuthnRegistrationOptions>> StartRegistrationAsync(
        Guid userId,
        Guid mfaMethodId,
        string userName,
        string userDisplayName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the WebAuthn registration process.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="mfaMethodId">The MFA method ID</param>
    /// <param name="challenge">The original challenge from registration start</param>
    /// <param name="attestationResponse">The attestation response from the authenticator</param>
    /// <param name="credentialName">User-friendly name for the credential</param>
    /// <param name="ipAddress">Optional IP address for security tracking</param>
    /// <param name="userAgent">Optional user agent for security tracking</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Registration completion result</returns>
    Task<ServiceResponse<WebAuthnRegistrationResultDto>> CompleteRegistrationAsync(
        Guid userId,
        Guid mfaMethodId,
        string challenge,
        WebAuthnAttestationResponse attestationResponse,
        string? credentialName = null,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts the WebAuthn authentication process.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication challenge options</returns>
    Task<ServiceResponse<WebAuthnAuthenticationOptions>> StartAuthenticationAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes the WebAuthn authentication process.
    /// </summary>
    /// <param name="credentialId">The credential ID from the assertion</param>
    /// <param name="challenge">The original challenge from authentication start</param>
    /// <param name="assertionResponse">The assertion response from the authenticator</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authentication verification result</returns>
    Task<ServiceResponse<WebAuthnAuthenticationResultDto>> CompleteAuthenticationAsync(
        string credentialId,
        string challenge,
        WebAuthnAssertionResponse assertionResponse,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all WebAuthn credentials for a user.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Collection of user's WebAuthn credentials</returns>
    Task<ServiceResponse<IReadOnlyList<WebAuthnCredentialInfo>>> GetUserCredentialsAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a WebAuthn credential.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="credentialId">The credential ID to remove</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Success result</returns>
    Task<ServiceResponse<bool>> RemoveCredentialAsync(
        Guid userId,
        Guid credentialId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates a credential's name.
    /// </summary>
    /// <param name="userId">The user ID</param>
    /// <param name="credentialId">The credential ID</param>
    /// <param name="name">The new name</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Success result</returns>
    Task<ServiceResponse<bool>> UpdateCredentialNameAsync(
        Guid userId,
        Guid credentialId,
        string name,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// WebAuthn registration options for the client.
/// </summary>
public class WebAuthnRegistrationOptions
{
    public string Challenge { get; init; } = string.Empty;
    public WebAuthnRelyingParty Rp { get; init; } = new();
    public WebAuthnUser User { get; init; } = new();
    public WebAuthnPubKeyCredParam[] PubKeyCredParams { get; init; } = Array.Empty<WebAuthnPubKeyCredParam>();
    public int Timeout { get; init; }
    public string AttestationPreference { get; init; } = "none";
    public WebAuthnAuthenticatorSelection AuthenticatorSelection { get; init; } = new();
    public WebAuthnCredentialDescriptor[] ExcludeCredentials { get; init; } = Array.Empty<WebAuthnCredentialDescriptor>();
}

/// <summary>
/// WebAuthn authentication options for the client.
/// </summary>
public class WebAuthnAuthenticationOptions
{
    public string Challenge { get; init; } = string.Empty;
    public int Timeout { get; init; }
    public string? RpId { get; init; }
    public WebAuthnCredentialDescriptor[] AllowCredentials { get; init; } = Array.Empty<WebAuthnCredentialDescriptor>();
    public string UserVerification { get; init; } = "preferred";
}

/// <summary>
/// WebAuthn relying party information.
/// </summary>
public class WebAuthnRelyingParty
{
    public string Name { get; init; } = string.Empty;
    public string? Id { get; init; }
}

/// <summary>
/// WebAuthn user information.
/// </summary>
public class WebAuthnUser
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
}

/// <summary>
/// WebAuthn public key credential parameters.
/// </summary>
public class WebAuthnPubKeyCredParam
{
    public string Type { get; init; } = "public-key";
    public int Alg { get; init; }
}

/// <summary>
/// WebAuthn authenticator selection criteria.
/// </summary>
public class WebAuthnAuthenticatorSelection
{
    public string? AuthenticatorAttachment { get; init; }
    public bool RequireResidentKey { get; init; }
    public string UserVerification { get; init; } = "preferred";
}

/// <summary>
/// WebAuthn credential descriptor.
/// </summary>
public class WebAuthnCredentialDescriptor
{
    public string Type { get; init; } = "public-key";
    public string Id { get; init; } = string.Empty;
    public string[] Transports { get; init; } = Array.Empty<string>();
}

/// <summary>
/// WebAuthn attestation response from the client.
/// </summary>
public class WebAuthnAttestationResponse
{
    public string Id { get; init; } = string.Empty;
    public string RawId { get; init; } = string.Empty;
    public WebAuthnAuthenticatorAttestationResponse Response { get; init; } = new();
    public string Type { get; init; } = "public-key";
}

/// <summary>
/// WebAuthn authenticator attestation response.
/// </summary>
public class WebAuthnAuthenticatorAttestationResponse
{
    public string AttestationObject { get; init; } = string.Empty;
    public string ClientDataJSON { get; init; } = string.Empty;
}

/// <summary>
/// WebAuthn assertion response from the client.
/// </summary>
public class WebAuthnAssertionResponse
{
    public string Id { get; init; } = string.Empty;
    public string RawId { get; init; } = string.Empty;
    public WebAuthnAuthenticatorAssertionResponse Response { get; init; } = new();
    public string Type { get; init; } = "public-key";
}

/// <summary>
/// WebAuthn authenticator assertion response.
/// </summary>
public class WebAuthnAuthenticatorAssertionResponse
{
    public string AuthenticatorData { get; init; } = string.Empty;
    public string ClientDataJSON { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;
    public string? UserHandle { get; init; }
}

/// <summary>
/// Information about a user's WebAuthn credential.
/// </summary>
public class WebAuthnCredentialInfo
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string AuthenticatorType { get; init; } = string.Empty;
    public string[] Transports { get; init; } = Array.Empty<string>();
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? LastUsedAt { get; init; }
    public bool IsActive { get; init; }
}