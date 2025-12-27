using System.Buffers.Binary;
using Application.Common.Configuration;
using Application.DTOs.Email;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Domain.Entities.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Application.Services.Mfa;

/// <summary>
/// Service for managing email-based MFA operations.
/// Handles code generation, sending, and verification with rate limiting and security controls.
/// </summary>
public class MfaEmailService(
    IMfaEmailCodeRepository emailCodeRepository,
    IEmailService emailService,
    IPasswordHasher passwordHasher,
    IOptions<EmailMfaOptions> emailMfaOptions,
    ILogger<MfaEmailService> logger) : IMfaEmailService
{
    private readonly EmailMfaOptions _options = emailMfaOptions.Value;

    /// <inheritdoc />
    public async Task<MfaEmailSendResult> SendCodeAsync(
        Guid challengeId,
        Guid userId,
        string emailAddress,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Check rate limits
            var rateLimitResult = await CheckRateLimitAsync(userId, cancellationToken);
            if (!rateLimitResult.IsAllowed)
            {
                logger.LogWarning("Email MFA rate limit exceeded for user {UserId}. Used: {Used}/{Max}",
                    userId, rateLimitResult.CodesUsed, rateLimitResult.MaxCodesAllowed);

                return MfaEmailSendResult.Failed(
                    $"Too many email codes requested. Try again after {rateLimitResult.WindowResetTime:HH:mm}");
            }

            // Generate and store the email code
            var plainCode = GenerateSecureCode();
            var hashedCode = passwordHasher.Hash(plainCode);
            var (emailCode, _) = MfaEmailCode.Create(challengeId, userId, emailAddress, hashedCode, ipAddress);
            await emailCodeRepository.AddAsync(emailCode, cancellationToken);

            // Send the email
            var emailSent = await SendCodeEmailAsync(emailAddress, plainCode, cancellationToken);
            if (!emailSent)
            {
                logger.LogError("Failed to send email MFA code to {Email} for user {UserId}",
                    emailAddress, userId);
                return MfaEmailSendResult.Failed("Failed to send verification email. Please try again.");
            }

            logger.LogInformation("Email MFA code sent successfully to user {UserId}", userId);
            return MfaEmailSendResult.Successful(emailCode.ExpiresAt, emailCode.GetRemainingAttempts());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error sending email MFA code to user {UserId}", userId);
            return MfaEmailSendResult.Failed("An error occurred while sending the verification email.");
        }
    }

    /// <inheritdoc />
    public async Task<MfaEmailVerificationResult> VerifyCodeAsync(
        Guid challengeId,
        string code,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                return MfaEmailVerificationResult.Failed("Verification code is required.", 0);
            }

            // Get the most recent valid code for this challenge
            var emailCode = await emailCodeRepository.GetValidCodeByChallengeIdAsync(challengeId, cancellationToken);
            if (emailCode == null)
            {
                logger.LogWarning("No valid email code found for challenge {ChallengeId}", challengeId);
                return MfaEmailVerificationResult.Failed("Invalid or expired verification code.", 0);
            }

            // Record the attempt
            if (!emailCode.RecordAttempt())
            {
                logger.LogWarning("Maximum attempts exceeded for challenge {ChallengeId}", challengeId);
                return MfaEmailVerificationResult.Failed("Maximum attempts exceeded.", 0);
            }

            // Verify the code using password hasher
            var isValid = passwordHasher.Verify(code, emailCode.HashedCode);
            if (isValid)
            {
                emailCode.MarkAsUsed();
                logger.LogInformation("Email MFA code verified successfully for challenge {ChallengeId}", challengeId);
                return MfaEmailVerificationResult.Successful();
            }

            logger.LogWarning("Invalid email MFA code attempt for challenge {ChallengeId}. Attempts: {Attempts}",
                challengeId, emailCode.AttemptCount);

            var remainingAttempts = emailCode.GetRemainingAttempts();
            var errorMessage = remainingAttempts > 0
                ? $"Invalid verification code. {remainingAttempts} attempt(s) remaining."
                : "Invalid verification code. Maximum attempts exceeded.";

            return MfaEmailVerificationResult.Failed(errorMessage, remainingAttempts);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error verifying email MFA code for challenge {ChallengeId}", challengeId);
            return MfaEmailVerificationResult.Failed("An error occurred while verifying the code.", 0);
        }
    }

    /// <inheritdoc />
    public async Task<MfaRateLimitResult> CheckRateLimitAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var windowStart = DateTimeOffset.UtcNow.AddMinutes(-_options.RateLimitWindowMinutes);

        var codesInWindow = await emailCodeRepository.GetCodeCountSinceAsync(userId, windowStart, cancellationToken);
        var resetTime = windowStart.AddMinutes(_options.RateLimitWindowMinutes);

        if (codesInWindow >= _options.MaxCodesPerWindow)
        {
            return MfaRateLimitResult.Exceeded(codesInWindow, _options.MaxCodesPerWindow, resetTime);
        }

        return MfaRateLimitResult.Allowed(codesInWindow, _options.MaxCodesPerWindow, resetTime);
    }

    /// <inheritdoc />
    public async Task<int> CleanupExpiredCodesAsync(CancellationToken cancellationToken = default)
    {
        var expiredBefore = DateTimeOffset.UtcNow.AddHours(-_options.CleanupAgeHours);

        var deletedCount = await emailCodeRepository.DeleteExpiredCodesAsync(expiredBefore, cancellationToken);

        if (deletedCount > 0)
        {
            logger.LogInformation("Cleaned up {Count} expired email MFA codes", deletedCount);
        }

        return deletedCount;
    }

    /// <summary>
    /// Sends the verification code via email.
    /// </summary>
    private async Task<bool> SendCodeEmailAsync(string emailAddress, string code, CancellationToken cancellationToken)
    {
        try
        {
            var renderedEmail = new RenderedEmail
            {
                Subject = "Your verification code",
                Body = $@"
<html>
<body>
    <h2>Verification Code</h2>
    <p>Your verification code is: <strong>{code}</strong></p>
    <p>This code will expire in {_options.CodeExpiryMinutes} minutes.</p>
    <p>If you didn't request this code, please ignore this email or contact support.</p>
    <hr>
    <small>This is an automated message from {_options.AppName}. Please do not reply.</small>
</body>
</html>",
                IsHtml = true
            };

            await emailService.SendEmailAsync(emailAddress, renderedEmail);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send email MFA code to {Email}", emailAddress);
            return false;
        }
    }

    /// <summary>
    /// Generates a cryptographically secure numeric verification code.
    /// </summary>
    private static string GenerateSecureCode()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);

        // Convert to uint and take modulo to get 8-digit number
        var value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        var code = (value % 90000000) + 10000000; // Ensures 8 digits

        return code.ToString();
    }
}
