using Application.DTOs.Mfa.WebAuthn;
using Application.Models;
using System.Security.Claims;

namespace Application.Interfaces.Services;

/// <summary>
/// Service for handling WebAuthn MFA authentication flows.
/// Provides high-level operations that combine business logic with WebAuthn operations.
/// </summary>
public interface IMfaWebAuthnService
{
    /// <summary>
    /// Starts the WebAuthn credential registration process for a user.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="request">Registration start request</param>
    /// <returns>Registration options for the client</returns>
    Task<ServiceResponse<WebAuthnRegistrationOptions>> StartRegistrationAsync(ClaimsPrincipal user, StartRegistrationDto request);

    /// <summary>
    /// Completes the WebAuthn credential registration process.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="request">Registration completion request with attestation</param>
    /// <param name="ipAddress">Client IP address</param>
    /// <param name="userAgent">Client user agent</param>
    /// <returns>Registration result</returns>
    Task<ServiceResponse<WebAuthnRegistrationResultDto>> CompleteRegistrationAsync(ClaimsPrincipal user, CompleteRegistrationDto request, string? ipAddress, string? userAgent);

    /// <summary>
    /// Starts the WebAuthn authentication process for a user.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <returns>Authentication options for the client</returns>
    Task<ServiceResponse<WebAuthnAuthenticationOptions>> StartAuthenticationAsync(ClaimsPrincipal user);

    /// <summary>
    /// Completes the WebAuthn authentication process.
    /// </summary>
    /// <param name="request">Authentication completion request with assertion</param>
    /// <returns>Authentication result</returns>
    Task<ServiceResponse<WebAuthnAuthenticationResultDto>> CompleteAuthenticationAsync(CompleteAuthenticationDto request);

    /// <summary>
    /// Gets all WebAuthn credentials for a user.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <returns>List of user's WebAuthn credentials</returns>
    Task<ServiceResponse<IEnumerable<WebAuthnCredentialDto>>> GetUserCredentialsAsync(ClaimsPrincipal user);

    /// <summary>
    /// Removes a WebAuthn credential for a user.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="credentialId">The credential ID to remove</param>
    /// <returns>Success response</returns>
    Task<ServiceResponse<bool>> RemoveCredentialAsync(ClaimsPrincipal user, Guid credentialId);

    /// <summary>
    /// Updates the name of a WebAuthn credential.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="credentialId">The credential ID to update</param>
    /// <param name="request">The update request with new name</param>
    /// <returns>Success response</returns>
    Task<ServiceResponse<bool>> UpdateCredentialNameAsync(ClaimsPrincipal user, Guid credentialId, UpdateCredentialNameDto request);
}