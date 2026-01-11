using Application.Common.Constants;
using Application.Common.Factories;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Logging;
using Application.Models;
using Domain.Entities.Identity;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace Application.Services.PasswordReset;

public class PasswordResetService(
    IPasswordResetTokenRepository passwordResetTokenRepository,
    IPasswordHasher passwordHasher,
    IAppUserRepository appUserRepository,
    ILogger<PasswordResetService> logger,
    IValidator<string> passwordValidator)
    : IPasswordResetService
{
    public async Task<ServiceResponse<bool>> ResetPasswordWithTokenAsync(string token, string password, string claimedByIpAddress)
    {
        var parsedTokenId = TryParseToken(token);
        if (parsedTokenId is null)
        {
            SecurityEvent.AuthFailure(logger, "password-reset",
                "Password reset failed: invalid token format",
                reason: ServiceResponseConstants.TokenNotFound);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.TokenNotFound);
        }

        var tokenEntity = await passwordResetTokenRepository.GetPasswordResetTokenAsync(parsedTokenId.Value);
        if (tokenEntity is null)
        {
            SecurityEvent.AuthFailure(logger, "password-reset",
                "Password reset failed: token not found",
                reason: ServiceResponseConstants.InvalidPasswordResetToken);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.InvalidPasswordResetToken);
        }

        if (tokenEntity.IsClaimed())
        {
            SecurityEvent.Threat(logger, "password-reset-reuse",
                "Attempted reuse of already claimed password reset token",
                reason: "Token already claimed");
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.InvalidPasswordResetToken);
        }

        var validationResult = await passwordValidator.ValidateAsync(password);
        if (!validationResult.IsValid)
        {
            SecurityEvent.Log(logger,
                SecurityEvent.Category.Authentication,
                SecurityEvent.Type.Change,
                "password-reset",
                SecurityEvent.Outcome.Failure,
                "Password reset failed: password validation failed",
                reason: validationResult.Errors.First().ErrorMessage);
            return ServiceResponseFactory.Error<bool>(validationResult.Errors.First().ErrorMessage);
        }

        tokenEntity.Claim(passwordHasher.Hash(password), claimedByIpAddress);
        var unclaimedTokens = await passwordResetTokenRepository.GetAllUnclaimedResetTokensForUserAsync(tokenEntity.AppUserId);

        foreach (var unclaimedToken in unclaimedTokens.Where(t => t.Id != tokenEntity.Id))
        {
            unclaimedToken.ClaimRedundantToken(claimedByIpAddress);
        }

        SecurityEvent.Log(logger,
            SecurityEvent.Category.Authentication,
            SecurityEvent.Type.Change,
            "password-reset",
            SecurityEvent.Outcome.Success,
            $"Password reset completed for user: {tokenEntity.AppUserId}");

        return ServiceResponseFactory.Success(true);
    }

    public async Task<ServiceResponse<bool>> ForcePasswordResetAsync(Guid userId, string newPassword)
    {
        var thisUser = await appUserRepository.GetUserByIdAsync(userId);

        if (thisUser is null)
        {
            SecurityEvent.Threat(logger, "force-password-reset",
                $"Force password reset attempt for non-existent user: {userId}",
                reason: ServiceResponseConstants.UserNotFound);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserNotFound);
        }

        if (!thisUser.ForceResetPassword)
        {
            SecurityEvent.Threat(logger, "force-password-reset",
                $"Force password reset attempt for user not required to reset: {userId}",
                reason: ServiceResponseConstants.UserNotRequiredToResetPassword);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserUnauthorized);
        }

        var validationResult = await passwordValidator.ValidateAsync(newPassword);

        if (!validationResult.IsValid)
        {
            SecurityEvent.Log(logger,
                SecurityEvent.Category.Authentication,
                SecurityEvent.Type.Change,
                "force-password-reset",
                SecurityEvent.Outcome.Failure,
                "Force password reset failed: password validation failed",
                reason: validationResult.Errors.First().ErrorMessage);
            return ServiceResponseFactory.Error<bool>(validationResult.Errors.First().ErrorMessage);
        }

        if (passwordHasher.Verify(newPassword, thisUser.Password))
        {
            SecurityEvent.Log(logger,
                SecurityEvent.Category.Authentication,
                SecurityEvent.Type.Change,
                "force-password-reset",
                SecurityEvent.Outcome.Failure,
                "Force password reset failed: new password same as current",
                reason: ServiceResponseConstants.PasswordMustBeDifferentFromCurrent);
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.PasswordMustBeDifferentFromCurrent);
        }

        var hashedPassword = new HashedPassword(passwordHasher.Hash(newPassword));

        thisUser.ChangePassword(hashedPassword);

        SecurityEvent.Log(logger,
            SecurityEvent.Category.Authentication,
            SecurityEvent.Type.Change,
            "force-password-reset",
            SecurityEvent.Outcome.Success,
            $"Force password reset completed for user: {thisUser.Username}");

        return ServiceResponseFactory.Success(true);
    }

    /// <summary>
    /// Attempts to parse the provided token into a Guid.
    /// </summary>
    /// <param name="token">The token string to parse.</param>
    /// <returns>The parsed Guid if the token is valid; otherwise, null.</returns>
    private static Guid? TryParseToken(string token) => Guid.TryParse(token, out var guid) ? guid : null;
}
