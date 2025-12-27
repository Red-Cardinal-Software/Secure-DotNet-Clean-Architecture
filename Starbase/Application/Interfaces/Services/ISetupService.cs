using Application.DTOs.Jwt;
using Application.DTOs.Setup;
using Application.Models;

namespace Application.Interfaces.Services;

/// <summary>
/// Service for initial system setup operations.
/// </summary>
public interface ISetupService
{
    /// <summary>
    /// Returns true if setup has been completed (cached after first check).
    /// Use this for quick checks that don't need to hit the database.
    /// </summary>
    bool IsSetupComplete { get; }

    /// <summary>
    /// Creates the initial admin user. Only works when no users exist in the system.
    /// After successful creation, IsSetupComplete will return true.
    /// </summary>
    Task<ServiceResponse<JwtResponseDto>> CreateInitialAdminAsync(
        InitialSetupDto request,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default);
}