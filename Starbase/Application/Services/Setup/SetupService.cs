using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Common.Configuration;
using Application.Common.Factories;
using Application.Common.Services;
using Application.Common.Utilities;
using Application.DTOs.Jwt;
using Application.DTOs.Setup;
using Application.Interfaces.Persistence;
using Application.Interfaces.Providers;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Models;
using Domain.Constants;
using Domain.Entities.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Application.Services.Setup;

/// <summary>
/// Service for initial system setup operations.
/// Uses IMemoryCache to cache setup state and avoid repeated database checks.
/// </summary>
public class SetupService(
    IAppUserRepository appUserRepository,
    IOrganizationRepository organizationRepository,
    IRoleRepository roleRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IPasswordHasher passwordHasher,
    ISigningKeyProvider signingKeyProvider,
    IUnitOfWork unitOfWork,
    IMemoryCache cache,
    IOptions<AppOptions> appOptions,
    ILogger<SetupService> logger)
    : BaseAppService(unitOfWork), ISetupService
{
    private const string SetupCompleteCacheKey = "SetupService:IsSetupComplete";

    /// <inheritdoc />
    public bool IsSetupComplete
    {
        get
        {
            return cache.GetOrCreate(SetupCompleteCacheKey, entry =>
            {
                // Cache indefinitely - setup state doesn't change after initial setup
                entry.Priority = CacheItemPriority.NeverRemove;
                var userCount = appUserRepository.GetTotalUserCountAsync().GetAwaiter().GetResult();
                return userCount > 0;
            });
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<JwtResponseDto>> CreateInitialAdminAsync(
        InitialSetupDto request,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default)
    {
        return await RunWithCommitAsync(async () =>
        {
            // Double-check setup state (in case of race condition)
            if (IsSetupComplete)
            {
                logger.LogWarning("Setup endpoint called but system is already configured");
                return ServiceResponseFactory.Error<JwtResponseDto>("System is already configured");
            }

            // Get the default organization (created by seeder)
            var organization = await organizationRepository.GetByNameAsync(
                SystemDefaults.DefaultOrganizationName, cancellationToken);

            if (organization is null)
            {
                logger.LogError("Default organization not found - database may not be seeded");
                return ServiceResponseFactory.Error<JwtResponseDto>(
                    "System not initialized. Please run database migrations.");
            }

            // Get the SuperAdmin role
            var roles = await roleRepository.GetRolesAsync();
            var superAdminRole = roles.FirstOrDefault(r => r.Name == PredefinedRoles.SuperAdmin);

            if (superAdminRole is null)
            {
                logger.LogError("SuperAdmin role not found - database may not be seeded");
                return ServiceResponseFactory.Error<JwtResponseDto>(
                    "System not initialized. Please run database migrations.");
            }

            // Check if email already exists (shouldn't happen on fresh install)
            if (await appUserRepository.DoesUserExistWithEmailAsync(request.Email))
            {
                return ServiceResponseFactory.Error<JwtResponseDto>("A user with this email already exists");
            }

            // Create the admin user
            var hashedPassword = passwordHasher.Hash(request.Password);
            var adminUser = new Domain.Entities.Identity.AppUser(
                request.Email,
                hashedPassword,
                request.FirstName,
                request.LastName,
                organization.Id,
                forceResetPassword: false // They just set their password
            );

            adminUser.AddRole(superAdminRole);
            await appUserRepository.CreateUserAsync(adminUser);

            // Mark setup as complete in cache (prevents future setup attempts)
            cache.Set(SetupCompleteCacheKey, true, new MemoryCacheEntryOptions
            {
                Priority = CacheItemPriority.NeverRemove
            });

            logger.LogInformation("Initial admin user created: {Email}", request.Email);

            // Create refresh token
            var refreshToken = new RefreshToken(
                adminUser,
                DateTime.UtcNow.AddHours(appOptions.Value.RefreshTokenExpirationTimeHours),
                ipAddress ?? "");

            await refreshTokenRepository.SaveRefreshTokenAsync(refreshToken);

            // Generate JWT
            var token = await CreateToken(adminUser);

            return ServiceResponseFactory.Success(new JwtResponseDto
            {
                Token = token,
                RefreshToken = refreshToken.Id.ToString(),
                ForceReset = false,
                RequiresMfa = false
            });
        });
    }

    private async Task<string> CreateToken(Domain.Entities.Identity.AppUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new("Organization", user.OrganizationId.ToString())
        };

        // Add privileges as individual claims
        var privilegeNames = user.Roles
            .SelectMany(r => r.Privileges)
            .Select(p => p.Name)
            .Distinct();

        claims.AddRange(privilegeNames.Select(priv => new Claim("priv", priv)));

        var allRoles = await roleRepository.GetRolesAsync();
        var userInfoClaims = ClaimsUtility.BuildClaimsForUser(user, allRoles);
        claims.AddRange(userInfoClaims);

        // Get the current signing key
        var signingKeyInfo = await signingKeyProvider.GetCurrentSigningKeyAsync();
        var credentials = new SigningCredentials(signingKeyInfo.Key, SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(appOptions.Value.JwtExpirationTimeMinutes),
            SigningCredentials = credentials,
            Issuer = appOptions.Value.JwtIssuer,
            Audience = appOptions.Value.JwtAudience
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}