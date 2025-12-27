using Application.DTOs.Mfa.EmailMfa;
using Application.Models;
using System.Security.Claims;

namespace Application.Interfaces.Services;

/// <summary>
/// Service for handling email-based MFA authentication flows.
/// Provides high-level operations that combine business logic with email MFA operations.
/// </summary>
public interface IMfaEmailAuthenticationService
{
    /// <summary>
    /// Sends an email MFA verification code to the user's email address.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="request">The send code request details</param>
    /// <param name="ipAddress">Client IP address for rate limiting and security</param>
    /// <returns>Information about the sent code</returns>
    Task<ServiceResponse<EmailCodeSentDto>> SendCodeAsync(ClaimsPrincipal user, SendEmailCodeDto request, string? ipAddress);

    /// <summary>
    /// Verifies an email MFA code.
    /// </summary>
    /// <param name="request">The verification request details</param>
    /// <returns>Verification result</returns>
    Task<ServiceResponse<EmailCodeVerificationDto>> VerifyCodeAsync(VerifyEmailCodeDto request);

    /// <summary>
    /// Checks the rate limit status for a user.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <returns>Rate limit information</returns>
    Task<ServiceResponse<EmailRateLimitDto>> CheckRateLimitAsync(ClaimsPrincipal user);
}