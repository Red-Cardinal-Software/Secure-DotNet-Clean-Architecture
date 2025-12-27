using Application.Common.Factories;
using Application.Common.Utilities;
using Application.DTOs.Mfa.WebAuthn;
using Application.Interfaces.Services;
using Application.Models;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Application.Services.Mfa;

/// <summary>
/// Service for handling WebAuthn MFA authentication flows.
/// Provides high-level operations that combine business logic with WebAuthn operations.
/// </summary>
public class MfaWebAuthnService(IWebAuthnService webAuthnService, ILogger<MfaWebAuthnService> logger) : IMfaWebAuthnService
{
    /// <summary>
    /// Starts the WebAuthn credential registration process for a user.
    /// </summary>
    public async Task<ServiceResponse<WebAuthnRegistrationOptions>> StartRegistrationAsync(ClaimsPrincipal user, StartRegistrationDto request)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);
        var userName = RoleUtility.GetUserNameFromClaim(user);
        var userDisplayName = user.FindFirst("DisplayName")?.Value ?? userName;

        logger.LogInformation("Starting WebAuthn registration for user {UserId}", userId);

        var result = await webAuthnService.StartRegistrationAsync(
            userId,
            request.MfaMethodId,
            userName,
            userDisplayName);

        if (!result.Success)
        {
            logger.LogWarning("Failed to start WebAuthn registration for user {UserId}: {Error}", userId, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Completes the WebAuthn credential registration process.
    /// </summary>
    public async Task<ServiceResponse<WebAuthnRegistrationResultDto>> CompleteRegistrationAsync(ClaimsPrincipal user, CompleteRegistrationDto request, string? ipAddress, string? userAgent)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);

        logger.LogInformation("Completing WebAuthn registration for user {UserId}", userId);

        // Map DTO to service model
        var attestationResponse = new WebAuthnAttestationResponse
        {
            Id = request.Response.Id,
            RawId = request.Response.RawId,
            Type = request.Response.Type,
            Response = new WebAuthnAuthenticatorAttestationResponse
            {
                ClientDataJSON = request.Response.Response.ClientDataJSON,
                AttestationObject = request.Response.Response.AttestationObject
            }
        };

        var result = await webAuthnService.CompleteRegistrationAsync(
            userId,
            request.MfaMethodId,
            request.Challenge,
            attestationResponse,
            request.CredentialName,
            ipAddress,
            userAgent);

        if (!result.Success)
        {
            logger.LogWarning("Failed to complete WebAuthn registration for user {UserId}: {Error}", userId, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Starts the WebAuthn authentication process for a user.
    /// </summary>
    public async Task<ServiceResponse<WebAuthnAuthenticationOptions>> StartAuthenticationAsync(ClaimsPrincipal user)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);

        logger.LogInformation("Starting WebAuthn authentication for user {UserId}", userId);

        var result = await webAuthnService.StartAuthenticationAsync(userId);

        if (!result.Success)
        {
            logger.LogWarning("Failed to start WebAuthn authentication for user {UserId}: {Error}", userId, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Completes the WebAuthn authentication process.
    /// </summary>
    public async Task<ServiceResponse<WebAuthnAuthenticationResultDto>> CompleteAuthenticationAsync(CompleteAuthenticationDto request)
    {
        logger.LogInformation("Completing WebAuthn authentication for credential {CredentialId}", request.CredentialId);

        // Map DTO to service model
        var assertionResponse = new WebAuthnAssertionResponse
        {
            Id = request.Response.Id,
            RawId = request.Response.RawId,
            Type = request.Response.Type,
            Response = new WebAuthnAuthenticatorAssertionResponse
            {
                ClientDataJSON = request.Response.Response.ClientDataJSON,
                AuthenticatorData = request.Response.Response.AuthenticatorData,
                Signature = request.Response.Response.Signature,
                UserHandle = request.Response.Response.UserHandle
            }
        };

        var result = await webAuthnService.CompleteAuthenticationAsync(
            request.CredentialId,
            request.Challenge,
            assertionResponse);

        if (!result.Success)
        {
            logger.LogWarning("Failed to complete WebAuthn authentication for credential {CredentialId}: {Error}", request.CredentialId, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Gets all WebAuthn credentials for a user.
    /// </summary>
    public async Task<ServiceResponse<IEnumerable<WebAuthnCredentialDto>>> GetUserCredentialsAsync(ClaimsPrincipal user)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);

        logger.LogDebug("Getting WebAuthn credentials for user {UserId}", userId);

        var result = await webAuthnService.GetUserCredentialsAsync(userId);

        if (!result.Success)
        {
            logger.LogWarning("Failed to get WebAuthn credentials for user {UserId}: {Error}", userId, result.Message);
            return ServiceResponseFactory.Error<IEnumerable<WebAuthnCredentialDto>>(result.Message, result.Status);
        }

        // Map WebAuthnCredentialInfo to WebAuthnCredentialDto
        var credentialDtos = result.Data!.Select(c => new WebAuthnCredentialDto
        {
            Id = c.Id,
            Name = c.Name,
            AuthenticatorType = c.AuthenticatorType,
            Transports = c.Transports,
            CreatedAt = c.CreatedAt,
            LastUsedAt = c.LastUsedAt,
            IsActive = c.IsActive
        });

        return ServiceResponseFactory.Success(credentialDtos);
    }

    /// <summary>
    /// Removes a WebAuthn credential for a user.
    /// </summary>
    public async Task<ServiceResponse<bool>> RemoveCredentialAsync(ClaimsPrincipal user, Guid credentialId)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);

        logger.LogInformation("Removing WebAuthn credential {CredentialId} for user {UserId}", credentialId, userId);

        var result = await webAuthnService.RemoveCredentialAsync(userId, credentialId);

        if (!result.Success)
        {
            logger.LogWarning("Failed to remove WebAuthn credential {CredentialId} for user {UserId}: {Error}", credentialId, userId, result.Message);
        }

        return result;
    }

    /// <summary>
    /// Updates the name of a WebAuthn credential.
    /// </summary>
    public async Task<ServiceResponse<bool>> UpdateCredentialNameAsync(ClaimsPrincipal user, Guid credentialId, UpdateCredentialNameDto request)
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);

        logger.LogInformation("Updating name for WebAuthn credential {CredentialId} for user {UserId}", credentialId, userId);

        var result = await webAuthnService.UpdateCredentialNameAsync(userId, credentialId, request.Name);

        if (!result.Success)
        {
            logger.LogWarning("Failed to update name for WebAuthn credential {CredentialId} for user {UserId}: {Error}", credentialId, userId, result.Message);
        }

        return result;
    }
}