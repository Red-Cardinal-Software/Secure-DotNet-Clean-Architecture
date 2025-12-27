using Application.DTOs.Mfa.WebAuthn;
using Application.Interfaces.Services;
using Application.Validators;
using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Starbase.Controllers;

/// <summary>
/// Controller for WebAuthn/FIDO2 Multi-Factor Authentication operations.
/// Provides endpoints for registering and authenticating with WebAuthn credentials.
/// </summary>
[ApiVersion("1.0")]
[ApiController]
[Route("api/v{version:apiVersion}/mfa/webauthn")]
[Authorize]
public class WebAuthnController(
    IMfaWebAuthnService mfaWebAuthnService,
    ILogger<WebAuthnController> logger) : BaseAppController(logger)
{
    /// <summary>
    /// Starts the WebAuthn credential registration process.
    /// </summary>
    /// <param name="request">Registration start request</param>
    /// <returns>Registration options for the client</returns>
    /// <response code="200">Registration started successfully</response>
    /// <response code="400">Bad request</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("register/start")]
    [ProducesResponseType(typeof(WebAuthnRegistrationOptions), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> StartRegistration([FromBody] StartRegistrationDto request) =>
        await ResolveAsync(() => mfaWebAuthnService.StartRegistrationAsync(User, request));

    /// <summary>
    /// Completes the WebAuthn credential registration process.
    /// </summary>
    /// <param name="request">Registration completion request with attestation</param>
    /// <returns>Registration result</returns>
    /// <response code="200">Registration completed successfully</response>
    /// <response code="400">Bad request or registration failed</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("register/complete")]
    [ProducesResponseType(typeof(WebAuthnRegistrationResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> CompleteRegistration([FromBody] CompleteRegistrationDto request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers["User-Agent"].ToString();
        return await ResolveAsync(() => mfaWebAuthnService.CompleteRegistrationAsync(User, request, ipAddress, userAgent));
    }

    /// <summary>
    /// Starts the WebAuthn authentication process.
    /// </summary>
    /// <returns>Authentication options for the client</returns>
    /// <response code="200">Authentication started successfully</response>
    /// <response code="400">No credentials found</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("authenticate/start")]
    [ProducesResponseType(typeof(WebAuthnAuthenticationOptions), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> StartAuthentication() =>
        await ResolveAsync(() => mfaWebAuthnService.StartAuthenticationAsync(User));

    /// <summary>
    /// Completes the WebAuthn authentication process.
    /// </summary>
    /// <param name="request">Authentication completion request with assertion</param>
    /// <returns>Authentication result</returns>
    /// <response code="200">Authentication completed successfully</response>
    /// <response code="400">Bad request or authentication failed</response>
    /// <response code="401">User not authenticated</response>
    [HttpPost("authenticate/complete")]
    [ProducesResponseType(typeof(WebAuthnAuthenticationResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> CompleteAuthentication([FromBody] CompleteAuthenticationDto request) =>
        await ResolveAsync(() => mfaWebAuthnService.CompleteAuthenticationAsync(request));

    /// <summary>
    /// Gets all WebAuthn credentials for the current user.
    /// </summary>
    /// <returns>List of user's WebAuthn credentials</returns>
    /// <response code="200">Credentials retrieved successfully</response>
    /// <response code="401">User not authenticated</response>
    [HttpGet("credentials")]
    [ProducesResponseType(typeof(IEnumerable<WebAuthnCredentialDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetUserCredentials() =>
        await ResolveAsync(() => mfaWebAuthnService.GetUserCredentialsAsync(User));

    /// <summary>
    /// Removes a WebAuthn credential.
    /// </summary>
    /// <param name="credentialId">The credential ID to remove</param>
    /// <returns>Removal result</returns>
    /// <response code="200">Credential removed successfully</response>
    /// <response code="404">Credential not found</response>
    /// <response code="401">User not authenticated</response>
    [HttpDelete("credentials/{credentialId:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RemoveCredential(Guid credentialId) =>
        await ResolveAsync(() => mfaWebAuthnService.RemoveCredentialAsync(User, credentialId));

    /// <summary>
    /// Updates the name of a WebAuthn credential.
    /// </summary>
    /// <param name="credentialId">The credential ID to update</param>
    /// <param name="request">The update request with new name</param>
    /// <returns>Update result</returns>
    /// <response code="200">Credential updated successfully</response>
    /// <response code="404">Credential not found</response>
    /// <response code="401">User not authenticated</response>
    [HttpPut("credentials/{credentialId:guid}/name")]
    [ValidDto]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> UpdateCredentialName(Guid credentialId, [FromBody] UpdateCredentialNameDto request) =>
        await ResolveAsync(() => mfaWebAuthnService.UpdateCredentialNameAsync(User, credentialId, request));
}
