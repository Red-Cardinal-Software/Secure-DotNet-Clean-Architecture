using Application.Common.Factories;
using Application.DTOs.Mfa.WebAuthn;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Application.Logging;
using Application.Models;
using Domain.Entities.Security;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using DomainAuthenticatorTransport = Domain.Entities.Security.AuthenticatorTransport;

namespace Application.Services.Mfa;

/// <summary>
/// WebAuthn service using Fido2.NetLib.
/// Provides secure FIDO2/WebAuthn credential management with full cryptographic verification.
/// </summary>
public class WebAuthnService(
    IFido2 fido2,
    IWebAuthnCredentialRepository credentialRepository,
    IDistributedCache distributedCache,
    ILogger<WebAuthnService> logger) : IWebAuthnService
{
    /// <inheritdoc />
    public async Task<ServiceResponse<WebAuthnRegistrationOptions>> StartRegistrationAsync(
        Guid userId,
        Guid mfaMethodId,
        string userName,
        string userDisplayName,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Create FIDO2 user object
            var user = new Fido2User
            {
                Name = userName,
                Id = userId.ToByteArray(),
                DisplayName = userDisplayName
            };

            // Get existing credentials to exclude
            var existingCredentials = await credentialRepository.GetActiveByUserIdAsync(userId, cancellationToken);
            var excludeCredentials = existingCredentials
                .Select(c => new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.CredentialId)))
                .ToList();

            // Set authenticator selection criteria
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Discouraged,
                UserVerification = UserVerificationRequirement.Preferred
            };

            // Create credential creation options
            var options = fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = user,
                ExcludeCredentials = excludeCredentials,
                AuthenticatorSelection = authenticatorSelection,
                AttestationPreference = AttestationConveyancePreference.None
            });

            // Store challenge for verification
            var challengeKey = $"webauthn:reg:{Convert.ToBase64String(options.Challenge)}";
            var storedChallenge = new StoredRegistrationChallenge
            {
                UserId = userId,
                MfaMethodId = mfaMethodId,
                Options = options,
                CreatedAt = DateTimeOffset.UtcNow
            };

            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
            };

            var json = JsonSerializer.Serialize(storedChallenge);
            await distributedCache.SetStringAsync(challengeKey, json, cacheOptions, cancellationToken);

            logger.LogInformation("WebAuthn registration started for user {UserId}", userId);

            return ServiceResponseFactory.Success(MapToRegistrationOptions(options));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error starting WebAuthn registration for user {UserId}", userId);
            return ServiceResponseFactory.Error<WebAuthnRegistrationOptions>("Failed to start registration process");
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<WebAuthnRegistrationResultDto>> CompleteRegistrationAsync(
        Guid userId,
        Guid mfaMethodId,
        string challenge,
        WebAuthnAttestationResponse attestationResponse,
        string? credentialName = null,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default)
    {
        var challengeKey = $"webauthn:reg:{challenge}";

        var json = await distributedCache.GetStringAsync(challengeKey, cancellationToken);

        if (string.IsNullOrEmpty(json))
        {
            return ServiceResponseFactory.Error<WebAuthnRegistrationResultDto>("Invalid or expired challenge");
        }

        var storedChallenge = JsonSerializer.Deserialize<StoredRegistrationChallenge>(json);

        await distributedCache.RemoveAsync(challengeKey, cancellationToken);

        if (storedChallenge?.Options == null)
        {
            logger.LogWarning("Invalid stored challenge data for user {UserId}", userId);
            return ServiceResponseFactory.Error<WebAuthnRegistrationResultDto>("Invalid challenge data");
        }

        try
        {
            // Convert our response to Fido2 format
            var fido2Response = new AuthenticatorAttestationRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = attestationResponse.RawId,
                RawId = Convert.FromBase64String(attestationResponse.RawId),
                Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                {
                    AttestationObject = Convert.FromBase64String(attestationResponse.Response.AttestationObject),
                    ClientDataJson = Convert.FromBase64String(attestationResponse.Response.ClientDataJSON)
                }
            };

            // Verify credential using Fido2 library
            var registeredCredential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = fido2Response,
                OriginalOptions = storedChallenge.Options,
                IsCredentialIdUniqueToUserCallback = IsCredentialIdUniqueToUserAsync
            }, cancellationToken);

            // Extract credential information
            var credentialIdBase64 = Convert.ToBase64String(registeredCredential.Id);
            var publicKeyBase64 = Convert.ToBase64String(registeredCredential.PublicKey);

            // Check if credential already exists (double check)
            if (await credentialRepository.CredentialExistsAsync(credentialIdBase64, cancellationToken))
            {
                return ServiceResponseFactory.Error<WebAuthnRegistrationResultDto>("Credential already registered");
            }

            // Determine authenticator type and transports
            var authenticatorType = DetermineAuthenticatorType(registeredCredential);
            var transports = ExtractTransports(registeredCredential);

            // Create and store credential
            var credential = WebAuthnCredential.Create(
                mfaMethodId,
                userId,
                credentialIdBase64,
                publicKeyBase64,
                registeredCredential.SignCount,
                authenticatorType,
                transports,
                false, // Single device detection - simplified for now
                credentialName ?? GetDefaultCredentialName(authenticatorType),
                "none", // Simplified attestation format
                registeredCredential.AaGuid.ToString(),
                ipAddress,
                userAgent);

            await credentialRepository.AddAsync(credential, cancellationToken);

            logger.LogInformation("WebAuthn registration completed for user {UserId}, credential {CredentialId}",
                userId, credential.Id);

            return ServiceResponseFactory.Success(new WebAuthnRegistrationResultDto
            {
                CredentialId = credential.Id
            }, "WebAuthn credential registered successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error completing WebAuthn registration for user {UserId}", userId);
            return ServiceResponseFactory.Error<WebAuthnRegistrationResultDto>("Failed to complete registration");
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<WebAuthnAuthenticationOptions>> StartAuthenticationAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Get user's active credentials
            var credentials = await credentialRepository.GetActiveByUserIdAsync(userId, cancellationToken);
            if (credentials.Count == 0)
            {
                return ServiceResponseFactory.Error<WebAuthnAuthenticationOptions>("No registered credentials found");
            }

            // Create allowed credentials list
            var allowedCredentials = credentials
                .Select(c => new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.CredentialId)))
                .ToList();

            // Create assertion options
            var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = allowedCredentials,
                UserVerification = UserVerificationRequirement.Preferred
            });

            // Store challenge for verification
            var challengeKey = $"webauthn:auth:{Convert.ToBase64String(options.Challenge)}";
            var storedChallenge = new StoredAuthenticationChallenge
            {
                UserId = userId,
                Options = options,
                CreatedAt = DateTimeOffset.UtcNow
            };

            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
            };

            var json = JsonSerializer.Serialize(storedChallenge);
            await distributedCache.SetStringAsync(challengeKey, json, cacheOptions, cancellationToken);

            logger.LogInformation("WebAuthn authentication started for user {UserId}", userId);

            return ServiceResponseFactory.Success(MapToAuthenticationOptions(options));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error starting WebAuthn authentication for user {UserId}", userId);
            return ServiceResponseFactory.Error<WebAuthnAuthenticationOptions>("Failed to start authentication process");
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<WebAuthnAuthenticationResultDto>> CompleteAuthenticationAsync(
        string credentialId,
        string challenge,
        WebAuthnAssertionResponse assertionResponse,
        CancellationToken cancellationToken = default)
    {

        var challengeKey = $"webauthn:auth:{challenge}";
        var json = await distributedCache.GetStringAsync(challengeKey, cancellationToken);

        if (string.IsNullOrEmpty(json))
        {
            return ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Invalid or expired challenge");
        }

        var storedChallenge = JsonSerializer.Deserialize<StoredAuthenticationChallenge>(json);

        await distributedCache.RemoveAsync(challengeKey, cancellationToken);

        if (storedChallenge?.Options == null)
        {
            logger.LogWarning("Invalid stored authentication challenge data");
            return ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Invalid challenge data");
        }

        try
        {
            // Get the credential from our database
            var credential = await credentialRepository.GetByCredentialIdAsync(credentialId, cancellationToken);
            if (credential == null || !credential.CanAuthenticate() || credential.UserId != storedChallenge.UserId)
            {
                return ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Invalid credential");
            }

            // Convert our response to Fido2 format
            var fido2Response = new AuthenticatorAssertionRawResponse
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = credentialId,
                RawId = Convert.FromBase64String(credentialId),
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = Convert.FromBase64String(assertionResponse.Response.AuthenticatorData),
                    ClientDataJson = Convert.FromBase64String(assertionResponse.Response.ClientDataJSON),
                    Signature = Convert.FromBase64String(assertionResponse.Response.Signature),
                    UserHandle = string.IsNullOrEmpty(assertionResponse.Response.UserHandle)
                        ? null
                        : Convert.FromBase64String(assertionResponse.Response.UserHandle)
                }
            };

            // Get stored public key for verification
            var storedPublicKey = Convert.FromBase64String(credential.PublicKey);

            // Verify assertion using Fido2 library
            var verificationResult = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = fido2Response,
                OriginalOptions = storedChallenge.Options,
                StoredPublicKey = storedPublicKey,
                StoredSignatureCounter = credential.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = IsUserHandleOwnerOfCredentialIdAsync
            }, cancellationToken);

            // Update sign count and check for cloned authenticators
            if (!credential.UpdateSignCount(verificationResult.SignCount))
            {
                SecurityEvent.Threat(logger, "webauthn-auth",
                    $"Cloned authenticator detected for user: {credential.UserId}",
                    reason: $"Sign count regression: previous={credential.SignCount}, received={verificationResult.SignCount}");
                return ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Security error: potential cloned authenticator");
            }

            credential.RecordUsage();

            logger.LogInformation("WebAuthn authentication completed for user {UserId}, credential {CredentialId}",
                credential.UserId, credential.Id);

            return ServiceResponseFactory.Success(new WebAuthnAuthenticationResultDto
            {
                UserId = credential.UserId,
                CredentialId = credential.Id
            }, "WebAuthn authentication successful");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error completing WebAuthn authentication for credential {CredentialId}", credentialId);
            return ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Failed to complete authentication");
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<IReadOnlyList<WebAuthnCredentialInfo>>> GetUserCredentialsAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var credentials = await credentialRepository.GetActiveByUserIdAsync(userId, cancellationToken);

        var credentialInfos = credentials.Select(c => new WebAuthnCredentialInfo
        {
            Id = c.Id,
            Name = c.Name ?? "WebAuthn Credential",
            AuthenticatorType = c.AuthenticatorType.ToString(),
            Transports = c.Transports.Select(MapTransportToString).ToArray(),
            CreatedAt = c.CreatedAt,
            LastUsedAt = c.LastUsedAt,
            IsActive = c.IsActive
        }).ToList();

        return ServiceResponseFactory.Success<IReadOnlyList<WebAuthnCredentialInfo>>(credentialInfos);
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<bool>> RemoveCredentialAsync(
        Guid userId,
        Guid credentialId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var credential = await credentialRepository.GetByIdAsync(credentialId, cancellationToken);
            if (credential == null || credential.UserId != userId)
            {
                return ServiceResponseFactory.NotFound<bool>("The specified credential was not found or does not belong to this user");
            }

            credentialRepository.Remove(credential);
            logger.LogInformation("WebAuthn credential {CredentialId} removed for user {UserId}", credentialId, userId);
            return ServiceResponseFactory.Success(true, "Credential removed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error removing WebAuthn credential {CredentialId} for user {UserId}", credentialId, userId);
            return ServiceResponseFactory.Error<bool>("Failed to remove credential");
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<bool>> UpdateCredentialNameAsync(
        Guid userId,
        Guid credentialId,
        string name,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var credential = await credentialRepository.GetByIdAsync(credentialId, cancellationToken);
            if (credential == null || credential.UserId != userId)
            {
                return ServiceResponseFactory.NotFound<bool>("The specified credential was not found or does not belong to this user");
            }

            credential.UpdateName(name);
            logger.LogInformation("WebAuthn credential {CredentialId} name updated for user {UserId}", credentialId, userId);
            return ServiceResponseFactory.Success(true, "Credential name updated successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error updating WebAuthn credential {CredentialId} name for user {UserId}", credentialId, userId);
            return ServiceResponseFactory.Error<bool>("Failed to update credential name");
        }
    }

    #region Private Methods

    /// <summary>
    /// Callback to check if credential ID is unique to user.
    /// </summary>
    private async Task<bool> IsCredentialIdUniqueToUserAsync(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken = default)
    {
        var credentialIdStr = Convert.ToBase64String(args.CredentialId);
        var existingCredential = await credentialRepository.GetByCredentialIdAsync(credentialIdStr, cancellationToken);

        // For now, simplified check - just ensure credential doesn't already exist
        return existingCredential == null;
    }

    /// <summary>
    /// Callback to check if user handle owns credential ID.
    /// </summary>
    private async Task<bool> IsUserHandleOwnerOfCredentialIdAsync(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationToken = default)
    {
        var credentialIdStr = Convert.ToBase64String(args.CredentialId);
        var credential = await credentialRepository.GetByCredentialIdAsync(credentialIdStr, cancellationToken);

        // For now, simplified check - just ensure credential exists
        return credential != null;
    }

    /// <summary>
    /// Maps Fido2 registration options to our format.
    /// </summary>
    private static WebAuthnRegistrationOptions MapToRegistrationOptions(CredentialCreateOptions options)
    {
        return new WebAuthnRegistrationOptions
        {
            Challenge = Convert.ToBase64String(options.Challenge),
            Rp = new WebAuthnRelyingParty
            {
                Name = options.Rp.Name,
                Id = options.Rp.Id
            },
            User = new WebAuthnUser
            {
                Id = Convert.ToBase64String(options.User.Id),
                Name = options.User.Name,
                DisplayName = options.User.DisplayName
            },
            PubKeyCredParams = options.PubKeyCredParams
                .Select(p => new WebAuthnPubKeyCredParam { Type = "public-key", Alg = (int)p.Alg })
                .ToArray(),
            Timeout = 60000, // Default timeout
            AttestationPreference = options.Attestation.ToString().ToLowerInvariant(),
            AuthenticatorSelection = new WebAuthnAuthenticatorSelection
            {
                AuthenticatorAttachment = options.AuthenticatorSelection?.AuthenticatorAttachment?.ToString().ToLowerInvariant(),
                RequireResidentKey = options.AuthenticatorSelection?.ResidentKey == ResidentKeyRequirement.Required,
                UserVerification = "preferred" // Simplified user verification
            },
            ExcludeCredentials = options.ExcludeCredentials?
                .Select(c => new WebAuthnCredentialDescriptor
                {
                    Type = "public-key",
                    Id = Convert.ToBase64String(c.Id),
                    Transports = c.Transports?.Select(t => t.ToString().ToLowerInvariant()).ToArray() ?? Array.Empty<string>()
                })
                .ToArray() ?? Array.Empty<WebAuthnCredentialDescriptor>()
        };
    }

    /// <summary>
    /// Maps Fido2 authentication options to our format.
    /// </summary>
    private static WebAuthnAuthenticationOptions MapToAuthenticationOptions(AssertionOptions options)
    {
        return new WebAuthnAuthenticationOptions
        {
            Challenge = Convert.ToBase64String(options.Challenge),
            Timeout = 60000, // Default timeout
            RpId = options.RpId,
            AllowCredentials = options.AllowCredentials?
                .Select(c => new WebAuthnCredentialDescriptor
                {
                    Type = "public-key",
                    Id = Convert.ToBase64String(c.Id),
                    Transports = c.Transports?.Select(t => t.ToString().ToLowerInvariant()).ToArray() ?? Array.Empty<string>()
                })
                .ToArray() ?? Array.Empty<WebAuthnCredentialDescriptor>(),
            UserVerification = "preferred" // Simplified user verification
        };
    }

    /// <summary>
    /// Determines authenticator type from credential creation result.
    /// </summary>
    private static AuthenticatorType DetermineAuthenticatorType(RegisteredPublicKeyCredential _)
    {
        // This is a simplified determination - in a full implementation you might want to:
        // 1. Check the AAGUID against known platform authenticators
        // 2. Examine attestation format
        // 3. Check authenticator flags

        // For now, default to CrossPlatform - in a real implementation you would:
        // - Check AAGUID against known platform authenticators
        // - Examine attestation format and flags
        return AuthenticatorType.CrossPlatform;
    }

    /// <summary>
    /// Extracts transport information from credential.
    /// </summary>
    private static DomainAuthenticatorTransport[] ExtractTransports(RegisteredPublicKeyCredential _)
    {
        // Default transports - in a full implementation you might extract this from
        // the attestation object or use other heuristics
        // For now, return default transports based on common usage patterns
        return new[] { DomainAuthenticatorTransport.Usb, DomainAuthenticatorTransport.Ble };
    }

    /// <summary>
    /// Gets default credential name based on type.
    /// </summary>
    private static string GetDefaultCredentialName(AuthenticatorType type)
    {
        return type switch
        {
            AuthenticatorType.Platform => "Platform Authenticator",
            AuthenticatorType.CrossPlatform => "Security Key",
            _ => "WebAuthn Credential"
        };
    }

    /// <summary>
    /// Maps transport enum to string.
    /// </summary>
    private static string MapTransportToString(DomainAuthenticatorTransport transport)
    {
        return transport switch
        {
            DomainAuthenticatorTransport.Usb => "usb",
            DomainAuthenticatorTransport.Nfc => "nfc",
            DomainAuthenticatorTransport.Ble => "ble",
            DomainAuthenticatorTransport.Internal => "internal",
            DomainAuthenticatorTransport.Hybrid => "hybrid",
            _ => "unknown"
        };
    }

    #endregion

    #region Challenge Storage Classes

    /// <summary>
    /// Storage for registration challenges.
    /// </summary>
    private class StoredRegistrationChallenge
    {
        public Guid UserId { get; init; }
        public Guid MfaMethodId { get; init; }
        public CredentialCreateOptions Options { get; init; } = null!;
        public DateTimeOffset CreatedAt { get; init; }
    }

    /// <summary>
    /// Storage for authentication challenges.
    /// </summary>
    private class StoredAuthenticationChallenge
    {
        public Guid UserId { get; init; }
        public AssertionOptions Options { get; init; } = null!;
        public DateTimeOffset CreatedAt { get; init; }
    }

    #endregion
}