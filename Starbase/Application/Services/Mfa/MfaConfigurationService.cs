using System.Buffers.Binary;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Application.Common.Configuration;
using Application.Common.Factories;
using Application.Common.Services;
using Application.DTOs.Mfa;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Models;
using Domain.Entities.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Application.Services.Mfa;

/// <summary>
/// Service implementation for managing MFA configuration and setup operations.
/// Provides comprehensive MFA management including enrollment, verification, and administration.
/// </summary>
public class MfaConfigurationService(
    IMfaMethodRepository mfaMethodRepository,
    IAppUserRepository userRepository,
    ITotpProvider totpProvider,
    MfaRecoveryCodeService mfaRecoveryCodeService,
    IPasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IOptions<AppOptions> appOptions,
    IOptions<MfaOptions> mfaOptions,
    IEmailService emailService,
    ILogger<MfaConfigurationService> logger)
    : BaseAppService(unitOfWork), IMfaConfigurationService
{

    #region Setup and Enrollment

    /// <summary>
    /// Initiates TOTP setup for a user by generating a secret and QR code.
    /// </summary>
    public async Task<ServiceResponse<MfaSetupDto>> StartTotpSetupAsync(Guid userId, string accountName, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Validate user exists
        var user = await userRepository.GetUserByIdAsync(userId);
        if (user == null)
            return ServiceResponseFactory.Error<MfaSetupDto>("User not found");

        // Check if user already has TOTP setup (verified or unverified)
        var existingTotp = await mfaMethodRepository.GetByUserAndTypeAsync(userId, MfaType.Totp, cancellationToken);
        if (existingTotp?.IsEnabled == true)
            return ServiceResponseFactory.Error<MfaSetupDto>("TOTP is already configured for this user");

        // Remove any existing unverified TOTP setup
        if (existingTotp is { IsEnabled: false })
        {
            mfaMethodRepository.Remove(existingTotp);
        }

        // Generate new secret and create unverified method
        var secret = totpProvider.GenerateSecret();
        var issuerName = appOptions.Value.AppName;

        var mfaMethod = MfaMethod.CreateTotp(userId, secret);
        await mfaMethodRepository.AddAsync(mfaMethod, cancellationToken);

        // Generate QR code URI and image
        var uri = totpProvider.GenerateUri(accountName, secret, issuerName);
        var qrCodeImage = await totpProvider.GenerateQrCodeAsync(uri);

        logger.LogInformation("TOTP setup initiated for user {UserId}", userId);

        return ServiceResponseFactory.Success(new MfaSetupDto
        {
            Secret = secret,
            FormattedSecret = totpProvider.FormatSecretForDisplay(secret),
            QrCodeUri = uri,
            QrCodeImage = qrCodeImage,
            IssuerName = issuerName,
            AccountName = accountName,
            Instructions = "Scan the QR code with your authenticator app, then enter the 6-digit code to verify setup."
        });
    });

    /// <summary>
    /// Verifies TOTP setup by validating the user's first code from their authenticator app.
    /// </summary>
    public async Task<ServiceResponse<MfaSetupCompleteDto>> VerifyTotpSetupAsync(Guid userId, VerifyMfaSetupDto verificationDto, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Get the unverified TOTP method
        var mfaMethod = await mfaMethodRepository.GetByUserAndTypeAsync(userId, MfaType.Totp, cancellationToken);
        if (mfaMethod == null)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("No TOTP setup found for this user");

        if (mfaMethod.IsEnabled)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("TOTP is already verified for this user");

        // Get user for notification
        var user = await userRepository.GetUserByIdAsync(userId);
        if (user == null)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("User not found");

        // Validate the TOTP code
        if (!totpProvider.ValidateCode(mfaMethod.Secret!, verificationDto.Code))
        {
            logger.LogWarning("TOTP verification failed for user {UserId}", userId);
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("Invalid verification code");
        }

        // Update method name if provided
        if (!string.IsNullOrWhiteSpace(verificationDto.Name))
        {
            mfaMethod.UpdateName(verificationDto.Name);
        }

        // Verify and enable the method
        mfaMethod.Verify();

        // Generate recovery codes for the newly verified method
        var newRecoveryCodes = mfaRecoveryCodeService.GenerateRecoveryCodes(mfaMethod.Id, 8);
        mfaMethod.SetRecoveryCodes(newRecoveryCodes);

        // If this is the user's first MFA method, make it default
        var existingMethodCount = await mfaMethodRepository.GetEnabledCountByUserIdAsync(userId, cancellationToken);
        var isFirstMethod = existingMethodCount == 0;

        if (isFirstMethod)
        {
            mfaMethod.SetAsDefault();
        }

        // Send security notification about TOTP setup
        await SendMfaSetupNotificationAsync(user, "TOTP", "Authenticator app MFA has been enabled", cancellationToken);

        // Get the recovery codes that were just generated
        var recoveryCodes = mfaMethod.GetNewRecoveryCodes();

        logger.LogInformation("TOTP setup completed for user {UserId}, method {MethodId}",
            userId, mfaMethod.Id);

        return ServiceResponseFactory.Success(new MfaSetupCompleteDto
        {
            MfaMethodId = mfaMethod.Id,
            RecoveryCodes = recoveryCodes.ToArray(),
            IsDefault = mfaMethod.IsDefault,
            VerifiedAt = mfaMethod.VerifiedAt!.Value,
            SecurityMessage = "Save these recovery codes in a safe place. Each code can only be used once and will allow you to access your account if you lose your authenticator device."
        });
    });

    /// <summary>
    /// Initiates email MFA setup for a user.
    /// </summary>
    public async Task<ServiceResponse<EmailSetupDto>> StartEmailSetupAsync(Guid userId, string emailAddress, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Validate user exists
        var user = await userRepository.GetUserByIdAsync(userId);
        if (user == null)
            return ServiceResponseFactory.Error<EmailSetupDto>("User not found");

        // Validate email
        var emailValidator = new EmailAddressAttribute();
        if (string.IsNullOrWhiteSpace(emailAddress) || !emailValidator.IsValid(emailAddress))
            return ServiceResponseFactory.Error<EmailSetupDto>("Invalid email address");

        // Check if user already has Email setup (verified or unverified)
        var existingEmail = await mfaMethodRepository.GetByUserAndTypeAsync(userId, MfaType.Email, cancellationToken);
        if (existingEmail?.IsEnabled == true)
            return ServiceResponseFactory.Error<EmailSetupDto>("Email MFA is already configured for this user");

        // Remove any existing unverified Email setup
        if (existingEmail is { IsEnabled: false })
        {
            mfaMethodRepository.Remove(existingEmail);
        }

        // Create new Email MFA method
        var emailMethod = MfaMethod.CreateEmail(userId, emailAddress);
        await mfaMethodRepository.AddAsync(emailMethod, cancellationToken);

        logger.LogInformation("Email MFA setup initiated for user {UserId}, method {MethodId}",
            userId, emailMethod.Id);

        // Generate and send verification code
        var codeSent = false;
        string message;

        try
        {
            // Generate a secure code
            var plainCode = GenerateSecureVerificationCode();
            var hashedCode = passwordHasher.Hash(plainCode);
            var codeExpiry = DateTimeOffset.UtcNow.AddMinutes(mfaOptions.Value.ChallengeExpiryMinutes);

            // Store the hashed code in the MFA method metadata
            emailMethod.StoreSetupVerificationCode(hashedCode, codeExpiry);

            // Send the verification email
            var emailSent = await SendSetupVerificationEmailAsync(emailAddress, plainCode, cancellationToken);

            if (emailSent)
            {
                codeSent = true;
                message = "A verification code has been sent to your email address.";
                logger.LogInformation("Setup verification code sent to {Email} for user {UserId}", emailAddress, userId);
            }
            else
            {
                message = "Setup initiated but verification email could not be sent. Please try again.";
                logger.LogWarning("Failed to send setup verification code to {Email} for user {UserId}", emailAddress, userId);
            }
        }
        catch (Exception ex)
        {
            message = "Setup initiated but verification email could not be sent. Please try again.";
            logger.LogError(ex, "Exception while sending setup verification code for user {UserId}", userId);
        }
        return ServiceResponseFactory.Success(new EmailSetupDto
        {
            MfaMethodId = emailMethod.Id,
            EmailAddress = emailAddress,
            Instructions = "Enter the verification code sent to your email address to complete setup.",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(mfaOptions.Value.ChallengeExpiryMinutes),
            CodeSent = codeSent,
            Message = message
        });
    });

    /// <summary>
    /// Verifies email MFA setup by validating the code sent to the user's email.
    /// </summary>
    public async Task<ServiceResponse<MfaSetupCompleteDto>> VerifyEmailSetupAsync(Guid userId, VerifyMfaSetupDto verificationDto, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Get unverified email method
        var mfaMethod = await mfaMethodRepository.GetByUserAndTypeAsync(userId, MfaType.Email, cancellationToken);
        if (mfaMethod == null)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("No email MFA setup found");

        if (mfaMethod.IsEnabled)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("Email MFA is already verified");

        // Get user for notification
        var user = await userRepository.GetUserByIdAsync(userId);
        if (user == null)
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("User not found");

        // Validate the setup verification code from metadata
        var storedHashedCode = mfaMethod.GetSetupVerificationCode();
        if (string.IsNullOrWhiteSpace(storedHashedCode))
        {
            logger.LogWarning("No setup verification code found or code expired for user {UserId}", userId);
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("No verification code found or code has expired. Please restart setup.");
        }

        // Verify the provided code against the stored hashed code
        if (!passwordHasher.Verify(verificationDto.Code, storedHashedCode))
        {
            logger.LogWarning("Invalid email setup verification code for user {UserId}", userId);
            return ServiceResponseFactory.Error<MfaSetupCompleteDto>("Invalid verification code");
        }

        // Clear the setup verification code from metadata
        mfaMethod.ClearSetupVerificationCode();

        // Update method name if provided
        if (!string.IsNullOrWhiteSpace(verificationDto.Name))
        {
            mfaMethod.UpdateName(verificationDto.Name);
        }

        // Verify and enable the method
        mfaMethod.Verify();

        // Generate recovery codes for the newly verified method
        var newRecoveryCodes = mfaRecoveryCodeService.GenerateRecoveryCodes(mfaMethod.Id, 8);
        mfaMethod.SetRecoveryCodes(newRecoveryCodes);

        // If this is the user's first MFA method, make it default
        var existingMethodCount = await mfaMethodRepository.GetEnabledCountByUserIdAsync(userId, cancellationToken);
        var isFirstMethod = existingMethodCount == 0;

        if (isFirstMethod)
        {
            mfaMethod.SetAsDefault();
        }

        // Send security notification about email MFA setup
        await SendMfaSetupNotificationAsync(user, "Email", "Email MFA has been enabled", cancellationToken);

        // Get the recovery codes that were just generated
        var recoveryCodes = mfaMethod.GetNewRecoveryCodes();

        logger.LogInformation("Email MFA setup completed for user {UserId}, method {MethodId}",
            userId, mfaMethod.Id);

        return ServiceResponseFactory.Success(new MfaSetupCompleteDto
        {
            MfaMethodId = mfaMethod.Id,
            RecoveryCodes = recoveryCodes.ToArray(),
            IsDefault = mfaMethod.IsDefault,
            VerifiedAt = mfaMethod.VerifiedAt!.Value,
            SecurityMessage = "Save these recovery codes in a safe place. Each code can only be used once and will allow you to access your account if you lose access to your email."
        });
    });

    /// <summary>
    /// Cancels an in-progress MFA setup that hasn't been verified yet.
    /// </summary>
    public async Task<ServiceResponse<bool>> CancelSetupAsync(Guid userId, MfaType mfaType, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var mfaMethod = await mfaMethodRepository.GetByUserAndTypeAsync(userId, mfaType, cancellationToken);
        if (mfaMethod == null || mfaMethod.IsEnabled)
            return ServiceResponseFactory.Success(false);

        mfaMethodRepository.Remove(mfaMethod);

        logger.LogInformation("MFA setup cancelled for user {UserId}, type {MfaType}", userId, mfaType);
        return ServiceResponseFactory.Success(true);
    });

    #endregion

    #region Method Management

    /// <summary>
    /// Gets an overview of the user's MFA configuration.
    /// </summary>
    public async Task<ServiceResponse<MfaOverviewDto>> GetMfaOverviewAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var methods = await mfaMethodRepository.GetByUserIdAsync(userId, cancellationToken);
        var enabledMethods = methods.Where(m => m.IsEnabled).ToList();

        var methodDtos = methods.Select(MapToDto).ToArray();

        // Determine available types (types not already set up)
        var existingTypes = methods.Where(m => m.IsEnabled).Select(m => m.Type).ToHashSet();
        var availableTypes = Enum.GetValues<MfaType>()
            .Where(type => !existingTypes.Contains(type))
            .Select(type => type.ToString())
            .ToArray();

        return ServiceResponseFactory.Success(new MfaOverviewDto
        {
            HasEnabledMfa = enabledMethods.Count > 0,
            TotalMethods = methods.Count,
            EnabledMethods = enabledMethods.Count,
            Methods = methodDtos,
            AvailableTypes = availableTypes,
            ShouldPromptSetup = enabledMethods.Count == 0 && GetMfaPromptPolicy()
        });
    }

    /// <summary>
    /// Gets detailed information about a specific MFA method.
    /// </summary>
    public async Task<ServiceResponse<MfaMethodDto?>> GetMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default)
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId)
            return ServiceResponseFactory.Success<MfaMethodDto?>(string.Empty);

        return ServiceResponseFactory.Success<MfaMethodDto?>(MapToDto(method));
    }

    /// <summary>
    /// Updates an existing MFA method's settings.
    /// </summary>
    public async Task<ServiceResponse<MfaMethodDto>> UpdateMfaMethodAsync(Guid userId, Guid methodId, UpdateMfaMethodDto updateDto, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId)
            return ServiceResponseFactory.Error<MfaMethodDto>("MFA method not found");

        // Update name if provided
        if (!string.IsNullOrWhiteSpace(updateDto.Name))
        {
            method.UpdateName(updateDto.Name);
        }

        // Handle enable/disable
        if (updateDto.IsEnabled.HasValue)
        {
            if (updateDto.IsEnabled.Value && !method.IsEnabled)
            {
                // Enabling - ensure method was verified
                if (method.VerifiedAt == null)
                    return ServiceResponseFactory.Error<MfaMethodDto>("Cannot enable unverified MFA method");
            }
            else if (!updateDto.IsEnabled.Value && method.IsEnabled)
            {
                // Disabling - check if this would leave user with no MFA
                var enabledCount = await mfaMethodRepository.GetEnabledCountByUserIdAsync(userId, cancellationToken);
                if (enabledCount == 1)
                {
                    logger.LogWarning("Last MFA method disabled for user {UserId}", userId);
                }

                method.Disable();
            }
        }

        // Handle default setting
        if (updateDto.IsDefault == true && method.IsEnabled)
        {
            await SetDefaultMfaMethodInternalAsync(userId, methodId, cancellationToken);
        }
        else if (updateDto.IsDefault == false && method.IsDefault)
        {
            method.RemoveDefault();
        }

        logger.LogInformation("MFA method {MethodId} updated for user {UserId}", methodId, userId);

        return ServiceResponseFactory.Success(MapToDto(method));
    });

    /// <summary>
    /// Sets an MFA method as the user's default.
    /// </summary>
    public async Task<ServiceResponse<bool>> SetDefaultMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId || !method.IsEnabled)
            return ServiceResponseFactory.Error<bool>("Cannot set invalid or disabled method as default");

        // Clear existing default flags
        await mfaMethodRepository.ClearDefaultFlagsAsync(userId, cancellationToken);

        // Set new default
        method.SetAsDefault();

        logger.LogInformation("MFA method {MethodId} set as default for user {UserId}", methodId, userId);
        return ServiceResponseFactory.Success(true);
    });

    /// <summary>
    /// Internal method for setting default without returning ServiceResponse (for internal use).
    /// </summary>
    private async Task SetDefaultMfaMethodInternalAsync(Guid userId, Guid methodId, CancellationToken cancellationToken)
    {
        await mfaMethodRepository.ClearDefaultFlagsAsync(userId, cancellationToken);
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        method?.SetAsDefault();
    }

    /// <summary>
    /// Enables or disables an MFA method.
    /// </summary>
    public async Task<ServiceResponse<bool>> SetMfaMethodEnabledAsync(Guid userId, Guid methodId, bool enabled, CancellationToken cancellationToken = default)
    {
        var updateDto = new UpdateMfaMethodDto { IsEnabled = enabled };
        var result = await UpdateMfaMethodAsync(userId, methodId, updateDto, cancellationToken);
        return result.Success
            ? ServiceResponseFactory.Success(true)
            : ServiceResponseFactory.Error<bool>(result.Message);
    }

    /// <summary>
    /// Removes an MFA method from the user's account.
    /// </summary>
    public async Task<ServiceResponse<bool>> RemoveMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId)
            return ServiceResponseFactory.Success(false);

        // Validate removal
        var validation = await ValidateMethodRemovalInternalAsync(userId, methodId, cancellationToken);
        if (!validation.CanRemove)
            return ServiceResponseFactory.Error<bool>("MFA method cannot be safely removed");

        mfaMethodRepository.Remove(method);

        logger.LogInformation("MFA method {MethodId} removed for user {UserId}", methodId, userId);
        return ServiceResponseFactory.Success(true);
    });

    #endregion

    #region Recovery Codes

    /// <summary>
    /// Generates new recovery codes for an MFA method, invalidating old unused codes.
    /// </summary>
    public async Task<ServiceResponse<string[]>> RegenerateRecoveryCodesAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId || !method.IsEnabled)
            return ServiceResponseFactory.Error<string[]>("Cannot regenerate codes for invalid or disabled method");

        // Generate new recovery codes using the secure service
        var newRecoveryCodes = mfaRecoveryCodeService.GenerateRecoveryCodes(methodId, 8);

        // Set the new codes on the method (this replaces unused codes)
        method.SetRecoveryCodes(newRecoveryCodes);

        // Get the plain text codes for return
        var plainTextCodes = method.GetNewRecoveryCodes();

        logger.LogInformation("Recovery codes regenerated for user {UserId}, method {MethodId}", userId, methodId);

        return ServiceResponseFactory.Success(plainTextCodes.ToArray());
    });

    /// <summary>
    /// Gets the count of unused recovery codes for an MFA method.
    /// </summary>
    public async Task<ServiceResponse<int>> GetRecoveryCodeCountAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default)
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId)
            return ServiceResponseFactory.Success(0);

        return ServiceResponseFactory.Success(method.GetUnusedRecoveryCodeCount());
    }

    #endregion

    #region Validation

    /// <summary>
    /// Checks if a user has any enabled MFA methods.
    /// </summary>
    public async Task<ServiceResponse<bool>> UserHasMfaEnabledAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var result = await mfaMethodRepository.UserHasEnabledMfaAsync(userId, cancellationToken);
        return ServiceResponseFactory.Success(result);
    }

    /// <summary>
    /// Validates that a user can safely remove an MFA method.
    /// </summary>
    public async Task<ServiceResponse<MfaRemovalValidationResult>> ValidateMethodRemovalAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default)
    {
        var result = await ValidateMethodRemovalInternalAsync(userId, methodId, cancellationToken);
        return ServiceResponseFactory.Success(result);
    }

    /// <summary>
    /// Internal method for validating removal without ServiceResponse wrapper.
    /// </summary>
    private async Task<MfaRemovalValidationResult> ValidateMethodRemovalInternalAsync(Guid userId, Guid methodId, CancellationToken cancellationToken)
    {
        var method = await mfaMethodRepository.GetByIdAsync(methodId, cancellationToken);
        if (method == null || method.UserId != userId)
        {
            return new MfaRemovalValidationResult { CanRemove = false, Warnings = ["Method not found"] };
        }

        var enabledCount = await mfaMethodRepository.GetEnabledCountByUserIdAsync(userId, cancellationToken);
        var remainingCount = method.IsEnabled ? enabledCount - 1 : enabledCount;

        var warnings = new List<string>();
        var willDisableMfa = remainingCount == 0;

        if (willDisableMfa)
        {
            warnings.Add("This will remove your last MFA method and disable two-factor authentication.");
        }

        if (method.IsDefault && remainingCount > 0)
        {
            warnings.Add("This is your default MFA method. Another method will need to be set as default.");
        }

        return new MfaRemovalValidationResult
        {
            CanRemove = true, // Allow removal but with warnings
            Warnings = warnings.ToArray(),
            WillDisableMfa = willDisableMfa,
            RemainingMethodCount = remainingCount
        };
    }

    /// <summary>
    /// Checks if a user can set up a specific type of MFA.
    /// </summary>
    public async Task<ServiceResponse<bool>> CanSetupMfaTypeAsync(Guid userId, MfaType mfaType, CancellationToken cancellationToken = default)
    {
        // Check if user already has this type configured
        var existing = await mfaMethodRepository.GetByUserAndTypeAsync(userId, mfaType, cancellationToken);
        if (existing?.IsEnabled == true)
            return ServiceResponseFactory.Success(false);

        // Add any type-specific validation here
        // For now, all types are allowed
        return ServiceResponseFactory.Success(true);
    }

    #endregion

    #region Administrative

    /// <summary>
    /// Gets MFA statistics for administrative purposes.
    /// </summary>
    public async Task<ServiceResponse<MfaStatisticsDto>> GetMfaStatisticsAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // Gather statistics from repositories based on scope
        int totalUsers;
        int usersWithMfa;
        Dictionary<MfaType, int> methodsByType;
        int unverifiedSetups;

        if (organizationId.HasValue)
        {
            // Organization-scoped statistics
            totalUsers = await userRepository.GetTotalUserCountForOrganizationAsync(organizationId.Value);
            usersWithMfa = await mfaMethodRepository.GetUsersWithMfaCountForOrganizationAsync(organizationId.Value, cancellationToken);
            methodsByType = await mfaMethodRepository.GetMethodCountByTypeForOrganizationAsync(organizationId.Value, cancellationToken);
            unverifiedSetups = await mfaMethodRepository.GetUnverifiedMethodCountForOrganizationAsync(organizationId.Value, cancellationToken);
        }
        else
        {
            // System-wide statistics
            totalUsers = await userRepository.GetTotalUserCountAsync();
            usersWithMfa = await mfaMethodRepository.GetUsersWithMfaCountAsync(cancellationToken);
            methodsByType = await mfaMethodRepository.GetMethodCountByTypeAsync(cancellationToken);
            unverifiedSetups = await mfaMethodRepository.GetUnverifiedMethodCountAsync(cancellationToken);
        }

        // Calculate adoption rate
        var adoptionRate = totalUsers > 0 ? (decimal)usersWithMfa / totalUsers * 100 : 0;

        var scopeDescription = organizationId.HasValue ? $"organization {organizationId.Value}" : "system-wide";
        logger.LogInformation("MFA statistics generated ({Scope}): {UsersWithMfa}/{TotalUsers} users have MFA enabled ({AdoptionRate:F1}%)",
            scopeDescription, usersWithMfa, totalUsers, adoptionRate);

        return ServiceResponseFactory.Success(new MfaStatisticsDto
        {
            TotalUsers = totalUsers,
            UsersWithMfa = usersWithMfa,
            MfaAdoptionRate = adoptionRate,
            MethodsByType = methodsByType,
            UnverifiedSetups = unverifiedSetups,
            GeneratedAt = now
        });
    }

    /// <summary>
    /// Cleans up unverified MFA methods older than the specified age.
    /// </summary>
    public async Task<ServiceResponse<int>> CleanupUnverifiedMethodsAsync(TimeSpan maxAge, CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var cutoffTime = DateTimeOffset.UtcNow.Subtract(maxAge);
        var unverifiedMethods = await mfaMethodRepository.GetUnverifiedOlderThanAsync(cutoffTime, cancellationToken);

        foreach (var method in unverifiedMethods)
        {
            mfaMethodRepository.Remove(method);
        }

        logger.LogInformation("Cleaned up {Count} unverified MFA methods older than {MaxAge}",
            unverifiedMethods.Count, maxAge);

        return ServiceResponseFactory.Success(unverifiedMethods.Count);
    });

    #endregion

    #region Private Helpers

    /// <summary>
    /// Maps an MFA method entity to a DTO.
    /// </summary>
    private static MfaMethodDto MapToDto(MfaMethod method)
    {
        return new MfaMethodDto
        {
            Id = method.Id,
            Type = method.Type,
            Name = method.Name ?? "Unknown",
            IsEnabled = method.IsEnabled,
            IsDefault = method.IsDefault,
            CreatedAt = method.CreatedAt,
            LastUsedAt = method.LastUsedAt,
            UnusedRecoveryCodeCount = method.GetUnusedRecoveryCodeCount(),
            DisplayInfo = GetDisplayInfo(method)
        };
    }

    /// <summary>
    /// Gets display information for an MFA method.
    /// </summary>
    private static string? GetDisplayInfo(MfaMethod method)
    {
        return method.Type switch
        {
            MfaType.Totp => "Authenticator App",
            MfaType.Email => ExtractEmailFromMetadata(method.Metadata),
            MfaType.WebAuthn => ExtractDeviceFromMetadata(method.Metadata),
            _ => null
        };
    }

    private static string? ExtractEmailFromMetadata(string? metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata))
            return null;

        try
        {
            var json = System.Text.Json.JsonDocument.Parse(metadata);
            if (json.RootElement.TryGetProperty("EmailAddress", out var emailElement))
                return emailElement.GetString();
        }
        catch
        {
            // Invalid JSON
        }
        return null;
    }

    private static string? ExtractDeviceFromMetadata(string? metadata)
    {
        // Parse JSON metadata to extract device name
        // Implementation would depend on metadata structure
        return null;
    }

    /// <summary>
    /// Gets the MFA prompt policy from configuration.
    /// </summary>
    private bool GetMfaPromptPolicy()
    {
        return mfaOptions.Value.PromptSetup;
    }

    /// <summary>
    /// Sends a security notification when MFA is set up.
    /// </summary>
    private async Task SendMfaSetupNotificationAsync(Domain.Entities.Identity.AppUser user, string mfaType, string details, CancellationToken cancellationToken)
    {
        try
        {
            await emailService.SendMfaSecurityNotificationAsync(
                user.Username,
                $"MFA Setup - {mfaType}",
                details,
                DateTimeOffset.UtcNow,
                null, // IP address would come from HttpContext in controller
                appOptions.Value.AppName,
                cancellationToken);
        }
        catch (Exception ex)
        {
            // Don't fail MFA setup if notification fails
            logger.LogWarning(ex, "Failed to send MFA setup notification to {Email}", user.Username);
        }
    }

    /// <summary>
    /// Generates a cryptographically secure verification code for email MFA setup.
    /// </summary>
    private static string GenerateSecureVerificationCode()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);

        // Convert to uint and take modulo to get 8-digit number
        var value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        var code = (value % 90000000) + 10000000; // Ensures 8 digits

        return code.ToString();
    }

    /// <summary>
    /// Sends a setup verification email with the code.
    /// </summary>
    private async Task<bool> SendSetupVerificationEmailAsync(string emailAddress, string code, CancellationToken cancellationToken)
    {
        try
        {
            var emailOptions = mfaOptions.Value;
            var appName = appOptions.Value.AppName;

            await emailService.SendMfaSetupVerificationCodeAsync(
                emailAddress,
                code,
                emailOptions.ChallengeExpiryMinutes,
                appName,
                cancellationToken);

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send setup verification email to {Email}", emailAddress);
            return false;
        }
    }

    #endregion
}
