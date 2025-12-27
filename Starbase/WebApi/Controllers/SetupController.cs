using Application.DTOs.Jwt;
using Application.DTOs.Setup;
using Application.Interfaces.Services;
using Asp.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Starbase.Controllers;

/// <summary>
/// One-time setup endpoint for initial system configuration.
/// This endpoint only works when no users exist in the system.
/// After successful setup, all requests return 404.
/// </summary>
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiController]
public class SetupController(ISetupService setupService, ILogger<SetupController> logger) : BaseAppController(logger)
{
    /// <summary>
    /// Create the initial admin user. Only works when no users exist.
    /// Returns 404 after initial setup is complete.
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    [ProducesResponseType(typeof(JwtResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> InitialSetup(InitialSetupDto request)
    {
        // Quick check using cached state - avoids DB hit after setup
        if (setupService.IsSetupComplete)
        {
            return NotFound();
        }

        var ipAddress = HttpContext.Features.Get<IHttpConnectionFeature>()?.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();

        return await ResolveAsync(() =>
            setupService.CreateInitialAdminAsync(request, ipAddress, userAgent));
    }
}