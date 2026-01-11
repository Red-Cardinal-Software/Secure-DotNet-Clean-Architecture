using Application.Common.Constants;
using Application.Common.Email;
using Application.Interfaces.Services;
using Microsoft.Extensions.Logging;

namespace Application.Services.Email;

/// <summary>
/// Service for sending password reset emails using the templated email system.
/// </summary>
public class PasswordResetEmailService(
    IEmailTemplateRenderer templateRenderer,
    ILogger<PasswordResetEmailService> logger) : IPasswordResetEmailService
{
    public async Task SendPasswordResetEmail(Domain.Entities.Identity.AppUser user, Domain.Entities.Identity.PasswordResetToken token)
    {
        logger.LogInformation("Sending password reset email to user {UserId}", user.Id);

        var model = new PasswordResetEmailModel
        {
            FirstName = user.FirstName,
            ResetLink = $"/reset-password?token={token.Id}", // TODO: Configure base URL
            ExpiresInMinutes = 60 // TODO: Get from configuration
        };

        var result = await templateRenderer.RenderAndSendAsync(
            EmailTemplateKeys.PasswordReset,
            user.Username,
            model);

        if (!result.Success)
        {
            logger.LogError("Failed to send password reset email to user {UserId}: {Error}",
                user.Id, result.ErrorMessage);
            throw new InvalidOperationException($"Failed to send password reset email: {result.ErrorMessage}");
        }

        logger.LogInformation("Password reset email sent successfully to user {UserId}", user.Id);
    }
}
