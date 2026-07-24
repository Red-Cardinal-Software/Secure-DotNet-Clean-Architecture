using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Application.Security;
using Domain.Constants;

namespace Starbase.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("health")]
    // NOTE: [AllowAnonymous] is applied per-action, not on the controller. A
    // controller-level [AllowAnonymous] overrides any action-level [Authorize]
    // (including [RequirePrivilege]) and would expose the privileged endpoints below.
    public class HealthController(HealthCheckService healthCheckService) : ControllerBase
    {
        [HttpGet]
        [Route("")]
        [AllowAnonymous]
        public async Task<IActionResult> GetHealth()
        {
            var report = await healthCheckService.CheckHealthAsync();

            return report.Status == HealthStatus.Healthy
                ? Ok(new { status = "Healthy", timestamp = DateTime.UtcNow })
                : StatusCode(503, new { status = report.Status.ToString(), timestamp = DateTime.UtcNow });
        }

        [HttpGet]
        [Route("detailed")]
        [AllowAnonymous]
        public async Task<IActionResult> GetDetailedHealth()
        {
            var report = await healthCheckService.CheckHealthAsync(
                predicate: check => !check.Tags.Contains("privileged"));

            var response = new
            {
                status = report.Status.ToString(),
                totalDuration = report.TotalDuration.TotalMilliseconds,
                checks = report.Entries.Select(e => new
                {
                    name = e.Key,
                    status = e.Value.Status.ToString(),
                    duration = e.Value.Duration.TotalMilliseconds,
                    description = e.Value.Description
                }),
                timestamp = DateTime.UtcNow
            };

            return report.Status == HealthStatus.Healthy
                ? Ok(response)
                : StatusCode(503, response);
        }

        [HttpGet]
        [Route("system")]
        [RequirePrivilege(PredefinedPrivileges.SystemAdministration.Metrics)]
        public async Task<IActionResult> GetSystemHealth()
        {
            var report = await healthCheckService.CheckHealthAsync();

            var response = new
            {
                status = report.Status.ToString(),
                totalDuration = report.TotalDuration.TotalMilliseconds,
                checks = report.Entries.Select(e => new
                {
                    name = e.Key,
                    status = e.Value.Status.ToString(),
                    duration = e.Value.Duration.TotalMilliseconds,
                    description = e.Value.Description,
                    data = e.Value.Data // Include data for privileged access
                }),
                timestamp = DateTime.UtcNow
            };

            return report.Status == HealthStatus.Healthy
                ? Ok(response)
                : StatusCode(503, response);
        }

        [HttpGet]
        [Route("live")]
        [AllowAnonymous]
        public IActionResult GetLiveness()
        {
            return Ok(new { status = "Alive", timestamp = DateTime.UtcNow });
        }

        [HttpGet]
        [Route("ready")]
        [AllowAnonymous]
        public async Task<IActionResult> GetReadiness()
        {
            var report = await healthCheckService.CheckHealthAsync(
                predicate: check => check.Tags.Contains("ready"));

            return report.Status == HealthStatus.Healthy
                ? Ok(new { status = "Ready", timestamp = DateTime.UtcNow })
                : StatusCode(503, new { status = "NotReady", timestamp = DateTime.UtcNow });
        }
    }
}