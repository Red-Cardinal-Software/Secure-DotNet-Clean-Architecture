using Application.DTOs.Mfa.EmailMfa;
using Application.Interfaces.Services;
using Application.Validators;
using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Starbase.Controllers;

/// <summary>
/// Controller for email-based Multi-Factor Authentication operations.
/// Provides endpoints for sending and verifying email MFA codes.
/// </summary>
[ApiVersion("1.0")]
[ApiController]
[Route("api/v{version:apiVersion}/mfa/email")]
[Authorize]
public class EmailMfaController(
    IMfaEmailAuthenticationService emailAuthService,
    ILogger<EmailMfaController> logger) : BaseAppController(logger)
{
    /// <summary>
    /// Sends an email MFA verification code to the user's email address.
    /// </summary>
    /// <param name="request">The send code request details</param>
    /// <returns>Information about the sent code</returns>
    /// <response code="200">Code sent successfully</response>
    /// <response code="400">Bad request or rate limit exceeded</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("send")]
    [ValidDto]
    [ProducesResponseType(typeof(EmailCodeSentDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> SendCode([FromBody] SendEmailCodeDto request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        return await ResolveAsync(() => emailAuthService.SendCodeAsync(User, request, ipAddress));
    }

    /// <summary>
    /// Verifies an email MFA code.
    /// </summary>
    /// <param name="request">The verification request details</param>
    /// <returns>Verification result</returns>
    /// <response code="200">Code verified successfully</response>
    /// <response code="400">Invalid code or verification failed</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("verify")]
    [ValidDto]
    [ProducesResponseType(typeof(EmailCodeVerificationDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> VerifyCode([FromBody] VerifyEmailCodeDto request) =>
        await ResolveAsync(() => emailAuthService.VerifyCodeAsync(request));

    /// <summary>
    /// Checks the rate limit status for the current user.
    /// </summary>
    /// <returns>Rate limit information</returns>
    /// <response code="200">Rate limit status returned</response>
    /// <response code="401">User not authenticated</response>
    [HttpGet("rate-limit")]
    [ProducesResponseType(typeof(EmailRateLimitDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> CheckRateLimit() =>
        await ResolveAsync(() => emailAuthService.CheckRateLimitAsync(User));
}
