using Application.Common.Configuration;
using Application.Common.Factories;
using Application.Common.Services;
using Application.DTOs.Auth;
using Application.DTOs.Mfa;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Application.Models;
using Domain.Entities.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Application.Services.Mfa;

/// <summary>
/// Service implementation for MFA authentication operations during login flow.
/// Handles challenge creation, verification, and security controls for the authentication process.
/// </summary>
public class MfaAuthenticationService(
    IMfaMethodRepository mfaMethodRepository,
    IMfaChallengeRepository mfaChallengeRepository,
    MfaRecoveryCodeService mfaRecoveryCodeService,
    ITotpProvider totpProvider,
    IMfaEmailService mfaEmailService,
    IWebAuthnService webAuthnService,
    IUnitOfWork unitOfWork,
    IOptions<MfaOptions> mfaOptions,
    ILogger<MfaAuthenticationService> logger)
    : BaseAppService(unitOfWork), IMfaAuthenticationService
{

    #region Challenge Management

    /// <summary>
    /// Creates an MFA challenge for a user during login.
    /// </summary>
    public async Task<ServiceResponse<MfaChallengeDto>> CreateChallengeAsync(Guid userId, string? ipAddress = null, string? userAgent = null, CancellationToken cancellationToken = default)
    {
        // Check rate limiting
        if (!await CanCreateChallengeAsync(userId, cancellationToken))
        {
            return ServiceResponseFactory.Error<MfaChallengeDto>("Too many MFA challenges. Please wait before requesting another.", 429);
        }

        // Get user's enabled MFA methods
        var enabledMethods = await mfaMethodRepository.GetEnabledByUserIdAsync(userId, cancellationToken);
        if (enabledMethods.Count == 0)
        {
            return ServiceResponseFactory.Error<MfaChallengeDto>("User has no enabled MFA methods");
        }

        return await RunWithCommitAsync(async () =>
        {
            // Get default method or first enabled method
            var defaultMethod = enabledMethods.FirstOrDefault(m => m.IsDefault) ?? enabledMethods.First();

            // Create challenge
            var challenge = MfaChallenge.Create(
                userId,
                defaultMethod.Type,
                defaultMethod.Id,
                ipAddress,
                userAgent);

            await mfaChallengeRepository.AddAsync(challenge, cancellationToken);

            // If the default method is email, send the email code immediately
            if (defaultMethod.Type == MfaType.Email)
            {
                await SendEmailCodeForChallengeAsync(challenge.Id, userId, defaultMethod, ipAddress, cancellationToken);
            }

            // Map available methods to DTOs
            var availableMethods = enabledMethods.Select(MapToAvailableMethodDto).ToArray();

            logger.LogInformation("MFA challenge created for user {UserId}, challenge {ChallengeId}",
                userId, challenge.Id);

            return ServiceResponseFactory.Success(new MfaChallengeDto
            {
                ChallengeToken = challenge.ChallengeToken,
                AvailableMethods = availableMethods,
                ExpiresAt = challenge.ExpiresAt,
                AttemptsRemaining = challenge.GetRemainingAttempts(),
                Instructions = GetInstructionsForMfaType(defaultMethod.Type)
            });
        });
    }

    /// <summary>
    /// Verifies an MFA challenge with the provided code.
    /// </summary>
    public async Task<ServiceResponse<MfaVerificationResultDto>> VerifyMfaAsync(CompleteMfaDto completeMfaDto, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Get and validate challenge
        var challenge = await mfaChallengeRepository.GetByChallengeTokenAsync(completeMfaDto.ChallengeToken, cancellationToken);
        if (challenge == null)
        {
            return ServiceResponseFactory.Error<MfaVerificationResultDto>("Invalid or expired challenge token");
        }

        if (!challenge.IsValid())
        {
            return ServiceResponseFactory.Error(
                "Challenge has expired or been exhausted",
                new MfaVerificationResultDto { AttemptsRemaining = 0, IsExhausted = true });
        }

        // Record attempt
        var canContinue = challenge.RecordFailedAttempt(); // Optimistically record as failed, will update if successful

        if (!canContinue)
        {
            logger.LogWarning("MFA challenge {ChallengeId} exhausted for user {UserId}",
                challenge.Id, challenge.UserId);

            return ServiceResponseFactory.Error(
                "Maximum verification attempts exceeded",
                new MfaVerificationResultDto { AttemptsRemaining = 0, IsExhausted = true });
        }

        // Determine which MFA method to use
        var methodToUse = completeMfaDto.MfaMethodId.HasValue
            ? await mfaMethodRepository.GetByIdAsync(completeMfaDto.MfaMethodId.Value, cancellationToken)
            : challenge.MfaMethodId.HasValue
                ? await mfaMethodRepository.GetByIdAsync(challenge.MfaMethodId.Value, cancellationToken)
                : await mfaMethodRepository.GetDefaultByUserIdAsync(challenge.UserId, cancellationToken);

        if (methodToUse == null || methodToUse.UserId != challenge.UserId || !methodToUse.IsEnabled)
        {
            return ServiceResponseFactory.Error(
                "Invalid MFA method",
                new MfaVerificationResultDto { AttemptsRemaining = challenge.GetRemainingAttempts() });
        }

        // Verify the code
        var verificationResult = await VerifyCodeForMethod(methodToUse, completeMfaDto.Code, completeMfaDto.IsRecoveryCode, cancellationToken);

        if (verificationResult.IsValid)
        {
            // Mark challenge as completed
            challenge.Complete();

            // Record method usage
            methodToUse.RecordUsage();

            // Invalidate other challenges for this user
            await InvalidateUserChallengesAsync(challenge.UserId, cancellationToken);

            logger.LogInformation("MFA verification successful for user {UserId}, method {MethodId}",
                challenge.UserId, methodToUse.Id);

            return ServiceResponseFactory.Success(new MfaVerificationResultDto
            {
                UserId = challenge.UserId,
                MfaMethodId = methodToUse.Id,
                UsedRecoveryCode = completeMfaDto.IsRecoveryCode
            });
        }

        logger.LogWarning("MFA verification failed for user {UserId}, method {MethodId}",
            challenge.UserId, methodToUse.Id);

        return ServiceResponseFactory.Error(
            verificationResult.ErrorMessage ?? "Invalid verification code",
            new MfaVerificationResultDto { AttemptsRemaining = challenge.GetRemainingAttempts() },
            401);
    });

    /// <summary>
    /// Invalidates all active challenges for a user.
    /// </summary>
    public async Task<ServiceResponse<int>> InvalidateUserChallengesAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await RunWithCommitAsync(async () =>
        {
            var invalidatedCount = await mfaChallengeRepository.InvalidateAllUserChallengesAsync(userId, cancellationToken);

            if (invalidatedCount > 0)
            {
                logger.LogInformation("Invalidated {Count} MFA challenges for user {UserId}",
                    invalidatedCount, userId);
            }

            return ServiceResponseFactory.Success(invalidatedCount);
        });
    }

    #endregion

    #region Validation

    /// <summary>
    /// Checks if a user requires MFA for authentication.
    /// </summary>
    public async Task<bool> RequiresMfaAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await mfaMethodRepository.UserHasEnabledMfaAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Gets the default MFA method for a user.
    /// </summary>
    public async Task<MfaMethod?> GetDefaultMfaMethodAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await mfaMethodRepository.GetDefaultByUserIdAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Validates that an MFA challenge is still active and usable.
    /// </summary>
    public async Task<bool> IsChallengeValidAsync(string challengeToken, CancellationToken cancellationToken = default)
    {
        var challenge = await mfaChallengeRepository.GetByChallengeTokenAsync(challengeToken, cancellationToken);
        return challenge?.IsValid() == true;
    }

    #endregion

    #region Rate Limiting

    /// <summary>
    /// Checks if a user can create new MFA challenges based on rate limiting.
    /// </summary>
    public async Task<bool> CanCreateChallengeAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        // Check active challenge count
        var activeChallenges = await GetActiveChallengeCountAsync(userId, cancellationToken);
        var config = mfaOptions.Value;

        if (activeChallenges >= config.MaxActiveChallenges)
        {
            return false;
        }

        // Check recent challenge creation rate
        var rateLimitWindow = TimeSpan.FromMinutes(config.RateLimitWindowMinutes);
        var recentChallenges = await mfaChallengeRepository.GetChallengeCountSinceAsync(
            userId,
            DateTimeOffset.UtcNow.Subtract(rateLimitWindow),
            cancellationToken);

        return recentChallenges < config.MaxChallengesPerWindow;
    }

    /// <summary>
    /// Gets the number of active challenges for a user.
    /// </summary>
    public async Task<int> GetActiveChallengeCountAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await mfaChallengeRepository.GetActiveChallengeCountAsync(userId, cancellationToken);
    }

    #endregion

    #region Administrative

    /// <summary>
    /// Cleans up expired MFA challenges.
    /// </summary>
    public async Task<int> CleanupExpiredChallengesAsync(DateTimeOffset? expiredBefore = null, CancellationToken cancellationToken = default)
    {
        return await RunWithCommitAsync(async () =>
        {
            var cutoffTime = expiredBefore ?? DateTimeOffset.UtcNow.AddHours(-1); // Default cleanup after 1 hour
            var cleanedUpCount = await mfaChallengeRepository.DeleteExpiredChallengesAsync(cutoffTime, cancellationToken);

            if (cleanedUpCount > 0)
            {
                logger.LogInformation("Cleaned up {Count} expired MFA challenges", cleanedUpCount);
            }

            return cleanedUpCount;
        });
    }

    #endregion

    #region Private Methods

    /// <summary>
    /// Internal result for code verification.
    /// </summary>
    private record VerificationResult(bool IsValid, string? ErrorMessage = null);

    /// <summary>
    /// Verifies a code against a specific MFA method.
    /// </summary>
    private async Task<VerificationResult> VerifyCodeForMethod(MfaMethod method, string code, bool isRecoveryCode, CancellationToken cancellationToken)
    {
        if (isRecoveryCode)
        {
            // Get unused recovery codes for this method
            var unusedCodes = method.GetUnusedRecoveryCodes();

            // Try to validate the code against each unused recovery code
            foreach (var recoveryCode in unusedCodes)
            {
                if (mfaRecoveryCodeService.ValidateAndUseRecoveryCode(recoveryCode, code))
                {
                    return new VerificationResult(true);
                }
            }

            return new VerificationResult(false, "Invalid recovery code");
        }

        // Verify based on method type
        return method.Type switch
        {
            MfaType.Totp => VerifyTotpCode(method, code),
            MfaType.Email => await VerifyEmailCode(method, code, cancellationToken),
            MfaType.WebAuthn => await VerifyWebAuthnAssertion(method, cancellationToken),
            _ => new VerificationResult(false, "Unsupported MFA method")
        };
    }

    /// <summary>
    /// Verifies a TOTP code.
    /// </summary>
    private VerificationResult VerifyTotpCode(MfaMethod method, string code)
    {
        if (string.IsNullOrWhiteSpace(method.Secret))
        {
            return new VerificationResult(false, "Method configuration error");
        }

        var isValid = totpProvider.ValidateCode(method.Secret, code);
        return isValid
            ? new VerificationResult(true)
            : new VerificationResult(false, "Invalid authenticator code");
    }

    /// <summary>
    /// Verifies an email code by delegating to the email MFA service.
    /// </summary>
    private async Task<VerificationResult> VerifyEmailCode(MfaMethod method, string code, CancellationToken cancellationToken)
    {
        // Get active challenges and find one for this method type
        var activeChallenges = await mfaChallengeRepository.GetActiveByUserIdAsync(method.UserId, cancellationToken);
        var emailChallenge = activeChallenges.FirstOrDefault(c => c.Type == MfaType.Email);

        if (emailChallenge == null)
        {
            return new VerificationResult(false, "No active email challenge found");
        }

        // Verify the email code using the email service
        var verificationResult = await mfaEmailService.VerifyCodeAsync(emailChallenge.Id, code, cancellationToken);

        return verificationResult.Success
            ? new VerificationResult(true)
            : new VerificationResult(false, verificationResult.ErrorMessage ?? "Invalid email verification code");
    }

    /// <summary>
    /// Verifies a WebAuthn assertion by delegating to the WebAuthn service.
    /// </summary>
    private async Task<VerificationResult> VerifyWebAuthnAssertion(MfaMethod method, CancellationToken cancellationToken)
    {
        try
        {
            // Get active challenges and find one for WebAuthn
            var activeChallenges = await mfaChallengeRepository.GetActiveByUserIdAsync(method.UserId, cancellationToken);
            var webAuthnChallenge = activeChallenges.FirstOrDefault(c => c.Type == MfaType.WebAuthn);

            if (webAuthnChallenge == null)
            {
                return new VerificationResult(false, "No active WebAuthn challenge found");
            }

            // In a real implementation, you would extract these from the client's assertion response
            // For demo purposes, we'll simulate the verification
            var simulatedCredentialId = "simulated-credential-id";
            var simulatedAssertionResponse = new WebAuthnAssertionResponse
            {
                Id = simulatedCredentialId,
                RawId = simulatedCredentialId,
                Response = new WebAuthnAuthenticatorAssertionResponse
                {
                    AuthenticatorData = "simulated-authenticator-data",
                    ClientDataJSON = "simulated-client-data",
                    Signature = "simulated-signature"
                }
            };

            // Use the WebAuthn service to verify the assertion
            var verificationResult = await webAuthnService.CompleteAuthenticationAsync(
                simulatedCredentialId,
                webAuthnChallenge.ChallengeToken,
                simulatedAssertionResponse,
                cancellationToken);

            return verificationResult.Success
                ? new VerificationResult(true)
                : new VerificationResult(false, verificationResult.Message);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error verifying WebAuthn assertion for method {MethodId}", method.Id);
            return new VerificationResult(false, "WebAuthn verification failed");
        }
    }

    /// <summary>
    /// Maps an MFA method to an available method DTO.
    /// </summary>
    private static AvailableMfaMethodDto MapToAvailableMethodDto(MfaMethod method)
    {
        return new AvailableMfaMethodDto
        {
            Id = method.Id,
            Type = method.Type,
            Name = method.Name ?? "Unknown Method",
            IsDefault = method.IsDefault,
            DisplayInfo = GetDisplayInfoForMethod(method),
            Instructions = GetInstructionsForMfaType(method.Type)
        };
    }

    /// <summary>
    /// Gets display information for an MFA method.
    /// </summary>
    private static string GetDisplayInfoForMethod(MfaMethod method)
    {
        return method.Type switch
        {
            MfaType.Totp => "Authenticator App",
            MfaType.Email => "Email Verification",
            MfaType.WebAuthn => "Security Key",
            MfaType.Push => "Push Notification",
            _ => method.Type.ToString()
        };
    }

    /// <summary>
    /// Gets instructions for using a specific MFA type.
    /// </summary>
    private static string GetInstructionsForMfaType(MfaType mfaType)
    {
        return mfaType switch
        {
            MfaType.Totp => "Enter the 6-digit code from your authenticator app",
            MfaType.Email => "Check your email for a verification code",
            MfaType.WebAuthn => "Use your security key or device biometric",
            MfaType.Push => "Approve the notification on your device",
            _ => "Enter your verification code"
        };
    }

    /// <summary>
    /// Sends an email verification code for a challenge.
    /// </summary>
    private async Task SendEmailCodeForChallengeAsync(Guid challengeId, Guid userId, MfaMethod emailMethod, string? ipAddress, CancellationToken cancellationToken)
    {
        // Extract email address from method metadata or user info
        var emailAddress = ExtractEmailFromMfaMethod(emailMethod);
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            logger.LogError("Cannot send email MFA code - no email address found for method {MethodId}", emailMethod.Id);
            return;
        }

        // Send the email code
        var result = await mfaEmailService.SendCodeAsync(challengeId, userId, emailAddress, ipAddress, cancellationToken);
        if (!result.Success)
        {
            logger.LogWarning("Failed to send email MFA code for challenge {ChallengeId}: {Error}",
                challengeId, result.ErrorMessage);
        }
        else
        {
            logger.LogInformation("Email MFA code sent for challenge {ChallengeId}", challengeId);
        }
    }

    /// <summary>
    /// Extracts email address from MFA method metadata or returns fallback.
    /// </summary>
    private static string? ExtractEmailFromMfaMethod(MfaMethod method)
    {
        return method.Metadata;
    }

    #endregion
}