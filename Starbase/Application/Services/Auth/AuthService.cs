using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Common.Configuration;
using Application.Common.Constants;
using Application.Common.Factories;
using Application.Common.Services;
using Application.Common.Utilities;
using Application.DTOs.Auth;
using Application.DTOs.Jwt;
using Application.Events.Auth;
using Application.Interfaces.Persistence;
using Application.Interfaces.Providers;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Logging;
using Application.Models;
using Domain.Entities.Identity;
using MediatR;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Application.Services.Auth;

/// <summary>
/// Handles authentication workflows such as login, logout, password reset, etc.  It also handles the JWT token generation and validation.
/// </summary>
public class AuthService(
    IAppUserRepository appUserRepository,
    IPasswordResetEmailService passwordResetEmailService,
    IPasswordHasher passwordHasher,
    IUnitOfWork unitOfWork,
    IPasswordResetService passwordResetService,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    IPasswordResetTokenRepository passwordResetTokenRepository,
    IAccountLockoutService accountLockoutService,
    IMfaAuthenticationService mfaAuthenticationService,
    ISigningKeyProvider signingKeyProvider,
    IMediator mediator,
    LogContextHelper<AuthService> logger,
    IOptions<AppOptions> appOptions)
    : BaseAppService(unitOfWork), IAuthService
{

    /// <summary>
    /// Performs login flow for a user
    /// </summary>
    /// <param name="username">User supplied username</param>
    /// <param name="password">User supplied password</param>
    /// <param name="ipAddress">The IP address the user is requesting login from</param>
    /// <returns><see cref="JwtResponseDto"/> with token and refresh token to issue to the user</returns>
    public async Task<ServiceResponse<JwtResponseDto>> Login(string username, string password, string ipAddress) => await RunWithCommitAsync(async () =>
    {
        if (!await UserExists(username))
        {
            // Record failed attempt for non-existent user
            await accountLockoutService.RecordFailedAttemptAsync(
                Guid.Empty,
                username,
                ipAddress,
                null,
                ServiceResponseConstants.UserDoesNotExist);

            // Publish domain event for audit
            await mediator.Publish(new LoginAttemptedEvent
            {
                UserId = Guid.Empty,
                Username = username,
                Success = false,
                FailureReason = "User does not exist",
                IpAddress = ipAddress
            });

            logger.Critical(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
            );
            return ServiceResponseFactory.Error<JwtResponseDto>(
                ServiceResponseConstants.UsernameOrPasswordIncorrect);
        }

        var user = await appUserRepository.GetUserByUsernameAsync(username);

        if (user is null)
        {
            // Record failed attempt for null user (should not happen if UserExists worked correctly)
            await accountLockoutService.RecordFailedAttemptAsync(
                Guid.Empty,
                username,
                ipAddress,
                null,
                ServiceResponseConstants.UserNotFoundInDatabase);

            logger.Critical(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetDetail(ServiceResponseConstants.AppUserNotFound));
            return ServiceResponseFactory.Error<JwtResponseDto>(
                ServiceResponseConstants.UsernameOrPasswordIncorrect);
        }

        // Check if account is locked before proceeding with authentication
        var lockout = await accountLockoutService.GetAccountLockoutAsync(user.Id);
        if (lockout is not null && lockout.IsLockedOut)
        {
            var remainingTime = lockout.GetRemainingLockoutDuration();
            var lockoutMessage = remainingTime.HasValue
                ? ServiceResponseConstants.AccountTemporarilyLocked
                : ServiceResponseConstants.AccountLocked;

            // Publish domain event for audit
            await mediator.Publish(new LoginAttemptedEvent
            {
                UserId = user.Id,
                Username = username,
                Success = false,
                FailureReason = "Account locked",
                IpAddress = ipAddress,
                AccountLocked = true
            });

            logger.Warning(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(string.Format(ServiceResponseConstants.AccountLockedDetailTemplate, remainingTime)));

            return ServiceResponseFactory.Error<JwtResponseDto>(lockoutMessage);
        }

        if (string.IsNullOrWhiteSpace(user.Password) || !passwordHasher.Verify(password, user.Password))
        {
            // Record failed login attempt
            var wasLocked = await accountLockoutService.RecordFailedAttemptAsync(
                user.Id,
                username,
                ipAddress,
                null,
                ServiceResponseConstants.InvalidCredentials);

            var errorMessage = wasLocked
                ? ServiceResponseConstants.AccountTemporarilyLocked
                : ServiceResponseConstants.UsernameOrPasswordIncorrect;

            // Publish domain event for audit
            await mediator.Publish(new LoginAttemptedEvent
            {
                UserId = user.Id,
                Username = username,
                Success = false,
                FailureReason = "Invalid credentials",
                IpAddress = ipAddress,
                AccountLocked = wasLocked
            });

            logger.Critical(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(string.Format(ServiceResponseConstants.InvalidCredentialsDetailTemplate, wasLocked)));

            return ServiceResponseFactory.Error<JwtResponseDto>(errorMessage);
        }

        // Record successful login attempt (password phase)
        await accountLockoutService.RecordSuccessfulLoginAsync(user.Id, username, ipAddress, null);

        // Check if MFA is required
        var requiresMfa = await mfaAuthenticationService.RequiresMfaAsync(user.Id);

        if (requiresMfa)
        {
            // Create MFA challenge instead of completing login
            var mfaChallengeResponse = await mfaAuthenticationService.CreateChallengeAsync(
                user.Id,
                ipAddress); // userAgent would come from request headers in controller

            if (!mfaChallengeResponse.Success)
            {
                return ServiceResponseFactory.Error<JwtResponseDto>(mfaChallengeResponse.Message);
            }

            logger.Info(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Success)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail("MFA challenge created"));

            return ServiceResponseFactory.Success(new JwtResponseDto
            {
                RequiresMfa = true,
                MfaChallenge = mfaChallengeResponse.Data,
                ForceReset = user.ForceResetPassword
            });
        }

        // No MFA required - complete login normally
        return await CompleteUserLogin(user, username, ipAddress);
    });

    /// <summary>
    /// Retrieves a new JWT Token using a refresh token
    /// </summary>
    /// <param name="username">Username of the user</param>
    /// <param name="token">The refresh token</param>
    /// <param name="ipAddress">IP Address of the user requesting</param>
    /// <returns>New <see cref="JwtResponseDto"/> with token and refresh token to issue to the user</returns>
    public async Task<ServiceResponse<JwtResponseDto>> Refresh(string username, string token, string ipAddress) => await RunWithCommitAsync(async () =>
    {
        if (!await appUserRepository.UserExistsAsync(username))
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Alert)
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(ServiceResponseConstants.UserNotFound));
            return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.UserUnauthorized);
        }

        var user = await appUserRepository.GetUserByUsernameAsync(username);

        if (user is null)
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Alert)
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(ServiceResponseConstants.UserNotFound));
            return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.UserUnauthorized);
        }

        var thisToken = await refreshTokenRepository.GetRefreshTokenAsync(Guid.Parse(token), user.Id);

        if (thisToken is null)
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Alert)
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(RefreshToken))
                .SetDetail(ServiceResponseConstants.TokenNotFound));
            return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.UserUnauthorized);
        }

        if (!string.IsNullOrWhiteSpace(thisToken.ReplacedBy))
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Threat)
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(RefreshToken))
                .SetDetail(ServiceResponseConstants.RefreshTokenAlreadyClaimed));
            await refreshTokenRepository.RevokeRefreshTokenFamilyAsync(thisToken.TokenFamily);
            return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.UserUnauthorized);
        }

        if (thisToken.Expires < DateTime.UtcNow)
        {
            logger.Info(new StructuredLogBuilder()
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(RefreshToken))
                .SetDetail(ServiceResponseConstants.RefreshTokenExpired));
            await refreshTokenRepository.RevokeRefreshTokenFamilyAsync(thisToken.TokenFamily);
            return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.RefreshTokenExpired);
        }

        var refreshTokenEntity = new RefreshToken(user, DateTime.UtcNow.AddHours(appOptions.Value.RefreshTokenExpirationTimeHours), ipAddress, thisToken.TokenFamily);
        await refreshTokenRepository.SaveRefreshTokenAsync(refreshTokenEntity);

        thisToken.MarkReplaced(refreshTokenEntity.Id.ToString());

        if (!thisToken.IsValid())
        {
            // Publish domain event for successful token refresh audit
            await mediator.Publish(new TokenRefreshedEvent
            {
                UserId = user.Id,
                Username = username,
                Success = true,
                IpAddress = ipAddress
            });

            logger.Info(new StructuredLogBuilder()
                .SetAction(AuthActions.RefreshJwtToken)
                .SetStatus(LogStatuses.Success)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(RefreshToken)));

            return ServiceResponseFactory.Success(new JwtResponseDto
            {
                RefreshToken = refreshTokenEntity.Id.ToString(),
                Token = await CreateToken(user)
            });
        }

        logger.Info(new StructuredLogBuilder()
            .SetAction(AuthActions.RefreshJwtToken)
            .SetStatus(LogStatuses.Failure)
            .SetTarget(AuthTargets.User(username))
            .SetEntity(nameof(RefreshToken))
            .SetDetail(ServiceResponseConstants.UnableToGenerateRefreshToken));
        return ServiceResponseFactory.Error<JwtResponseDto>(ServiceResponseConstants.UnableToGenerateRefreshToken);
    });

    /// <summary>
    /// Performs logout flow for a user
    /// </summary>
    /// <param name="username">Username of the requesting user</param>
    /// <param name="refreshToken">The current refresh token</param>
    /// <returns>Whether logout was successfully completed or not</returns>
    public async Task<ServiceResponse<bool>> Logout(string username, string refreshToken) => await RunWithCommitAsync(async () =>
    {
        var user = await appUserRepository.GetUserByUsernameAsync(username);

        if (user is null)
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Threat)
                .SetAction(AuthActions.Logout)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(ServiceResponseConstants.UserNotFound));
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserUnauthorized);
        }

        var thisRefreshToken = await refreshTokenRepository.GetRefreshTokenAsync(Guid.Parse(refreshToken), user.Id);
        if (thisRefreshToken is null)
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Threat)
                .SetAction(AuthActions.Logout)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(username))
                .SetEntity(nameof(RefreshToken))
                .SetDetail(ServiceResponseConstants.TokenNotFound));
            return ServiceResponseFactory.Error<bool>(ServiceResponseConstants.UserUnauthorized);
        }

        var result = await refreshTokenRepository.RevokeRefreshTokenFamilyAsync(thisRefreshToken.TokenFamily);

        // Publish domain event for logout audit
        await mediator.Publish(new LogoutEvent
        {
            UserId = user.Id,
            Username = username
        });

        logger.Info(new StructuredLogBuilder()
            .SetAction(AuthActions.Logout)
            .SetStatus(LogStatuses.Success)
            .SetTarget(AuthTargets.User(username))
            .SetEntity(nameof(Domain.Entities.Identity.AppUser))
            .SetDetail(ServiceResponseConstants.UserLoggedOut));
        return ServiceResponseFactory.Success(result);
    });

    /// <summary>
    /// Workflow when a user submits a request to change their password.  It generates an email to the user's email address
    /// To avoid giving too much information to a potential attacker, this method will return true whether the email was sent successfully or not.
    /// </summary>
    /// <param name="email">The user's email address</param>
    /// <param name="ipAddress">The IP address of the requestor</param>
    /// <returns>Whether the operation was successful or not, generally only if there's a database error will it return false</returns>
    public async Task<ServiceResponse<bool>> RequestPasswordReset(string email, string ipAddress) => await RunWithCommitAsync(async () =>
    {
        var user = await appUserRepository.GetUserByEmailAsync(email);

        if (user is null)
        {
            logger.Info(new StructuredLogBuilder()
                .SetType(LogTypes.Security.Alert)
                .SetAction(AuthActions.RequestCredentialReset)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(email))
                .SetEntity(nameof(Domain.Entities.Identity.AppUser))
                .SetDetail(ServiceResponseConstants.UserNotFound));
            // Do not give too much information to an attacker that is trying to probe for valid usernames
            return ServiceResponseFactory.Success(true, ServiceResponseConstants.EmailPasswordResetSent);
        }

        var passwordResetExpirationTimeHours = appOptions.Value.PasswordResetExpirationTimeHours;

        var newPasswordResetToken =
            new PasswordResetToken(user, DateTime.Now.AddHours(passwordResetExpirationTimeHours), ipAddress);

        var tokenEntity = await passwordResetTokenRepository.CreateResetPasswordTokenAsync(newPasswordResetToken);

        await passwordResetEmailService.SendPasswordResetEmail(user, tokenEntity);

        // Publish domain event for password reset request audit
        await mediator.Publish(new PasswordResetRequestedEvent
        {
            UserId = user.Id,
            Email = email,
            IpAddress = ipAddress,
            UserExists = true
        });

        logger.Info(new StructuredLogBuilder()
            .SetAction(AuthActions.RequestCredentialReset)
            .SetStatus(LogStatuses.Success)
            .SetTarget(AuthTargets.User(email))
            .SetEntity(nameof(Domain.Entities.Identity.AppUser))
            .SetDetail(ServiceResponseConstants.EmailPasswordResetSent));

        return ServiceResponseFactory.Success(true, ServiceResponseConstants.EmailPasswordResetSent);
    });

    /// <summary>
    /// Applies a password reset with the reset token assigned to the request
    /// </summary>
    /// <param name="token">The Full password request submission including a new password and token</param>
    /// <param name="ipAddress">IP Address of the requestor</param>
    /// <returns>Whether the password reset was successful or not</returns>
    public async Task<ServiceResponse<bool>> ApplyPasswordReset(PasswordResetSubmissionDto token, string ipAddress) =>
        await RunWithCommitAsync(async () =>
            await passwordResetService.ResetPasswordWithTokenAsync(token.Token, token.Password, ipAddress));

    /// <summary>
    /// Workflow for when a user logs in, and they have the Force Reset Password flag set.  This method will force the user to change their password
    /// </summary>
    /// <param name="user">The claims principal of the user trying to log in</param>
    /// <param name="newPassword">The supplied new password</param>
    /// <returns>Whether the operation was successful or not</returns>
    public async Task<ServiceResponse<bool>> ForcePasswordReset(ClaimsPrincipal user, string newPassword) => await RunWithCommitAsync(async () =>
    {
        var userId = RoleUtility.GetUserIdFromClaims(user);
        return await passwordResetService.ForcePasswordResetAsync(userId, newPassword);
    });

    /// <summary>
    /// Generates a new JWT token for a user.  Used when they change a setting that requires regenerating a token
    /// </summary>
    /// <param name="user">The claims principal of the user trying to log in</param>
    /// <returns>New <see cref="JwtResponseDto"/> with token and refresh token to issue to the user</returns>
    public async Task<JwtResponseDto> GenerateJwtToken(ClaimsPrincipal user)
    {
        var appUser = await appUserRepository.GetUserByUsernameAsync(RoleUtility.GetUserNameFromClaim(user));

        // Note: This method generates a new JWT but doesn't create a refresh token entity.
        // If refresh token functionality is needed, consider creating and saving a RefreshToken entity.
        return new JwtResponseDto
        {
            RefreshToken = null, // No refresh token generated as no entity is created
            Token = await CreateToken(appUser!)
        };
    }

    /// <summary>
    /// Completes the MFA verification process and issues authentication tokens.
    /// </summary>
    /// <param name="completeMfaDto">The MFA completion information including challenge token and verification code.</param>
    /// <param name="ipAddress">The IP address of the device completing MFA verification.</param>
    /// <returns>A service response containing JWT tokens upon successful MFA verification.</returns>
    public async Task<ServiceResponse<JwtResponseDto>> CompleteMfaAuthentication(CompleteMfaDto completeMfaDto, string ipAddress) => await RunWithCommitAsync(async () =>
    {
        // Verify the MFA challenge
        var verificationResponse = await mfaAuthenticationService.VerifyMfaAsync(completeMfaDto);

        if (!verificationResponse.Success)
        {
            // Log the failed MFA attempt
            logger.Warning(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User("MFA"))
                .SetEntity("MfaChallenge")
                .SetDetail($"MFA verification failed: {verificationResponse.Message}"));

            if (verificationResponse.Data?.IsExhausted == true)
            {
                logger.Critical(new StructuredLogBuilder()
                    .SetAction(AuthActions.Login)
                    .SetStatus(LogStatuses.Failure)
                    .SetTarget(AuthTargets.User("MFA"))
                    .SetEntity("MfaChallenge")
                    .SetDetail("MFA challenge exhausted - potential brute force attempt"));
            }

            return ServiceResponseFactory.Error<JwtResponseDto>(
                verificationResponse.Message ?? "Invalid MFA verification code");
        }

        // Get the user
        var userId = verificationResponse.Data!.UserId;
        var user = await appUserRepository.GetUserByIdAsync(userId);
        if (user == null)
        {
            logger.Critical(new StructuredLogBuilder()
                .SetAction(AuthActions.Login)
                .SetStatus(LogStatuses.Failure)
                .SetTarget(AuthTargets.User(userId.ToString()))
                .SetEntity(nameof(AppUser))
                .SetDetail("User not found after successful MFA verification"));

            return ServiceResponseFactory.Error<JwtResponseDto>("Authentication failed");
        }

        // Complete the login process
        var loginResult = await CompleteUserLogin(user, user.Username, ipAddress);

        // Log successful MFA completion
        logger.Info(new StructuredLogBuilder()
            .SetAction(AuthActions.Login)
            .SetStatus(LogStatuses.Success)
            .SetTarget(AuthTargets.User(user.Username))
            .SetEntity(nameof(AppUser))
            .SetDetail($"MFA authentication completed successfully. Recovery code used: {verificationResponse.Data.UsedRecoveryCode}"));

        return loginResult;
    });

    /// <summary>
    /// General check if the user actually exists in the system
    /// </summary>
    /// <param name="username">The username of the user</param>
    /// <returns>Whether the user exists or not</returns>
    private async Task<bool> UserExists(string username)
    {
        return await appUserRepository.UserExistsAsync(username);
    }


    /// <summary>
    /// Completes the user login process by creating tokens and logging successful authentication.
    /// Used for both regular login and MFA completion flows.
    /// </summary>
    /// <param name="user">The authenticated user</param>
    /// <param name="username">The username used for login</param>
    /// <param name="ipAddress">The IP address of the login request</param>
    /// <returns>JWT response with tokens</returns>
    private async Task<ServiceResponse<JwtResponseDto>> CompleteUserLogin(Domain.Entities.Identity.AppUser user, string username, string ipAddress)
    {
        var refreshTokenEntity = new RefreshToken(user, DateTime.UtcNow.AddHours(appOptions.Value.RefreshTokenExpirationTimeHours), ipAddress);
        await refreshTokenRepository.SaveRefreshTokenAsync(refreshTokenEntity);

        // Publish domain event for successful login audit
        await mediator.Publish(new LoginAttemptedEvent
        {
            UserId = user.Id,
            Username = username,
            Success = true,
            IpAddress = ipAddress
        });

        logger.Info(new StructuredLogBuilder()
            .SetAction(AuthActions.Login)
            .SetStatus(LogStatuses.Success)
            .SetTarget(AuthTargets.User(username))
            .SetEntity(nameof(Domain.Entities.Identity.AppUser))
            .SetDetail("User authentication completed successfully"));

        return ServiceResponseFactory.Success(new JwtResponseDto
        {
            RefreshToken = refreshTokenEntity.Id.ToString(),
            Token = await CreateToken(user),
            ForceReset = user.ForceResetPassword,
            RequiresMfa = false
        });
    }

    /// <summary>
    /// Logic to construct the JWT Token
    /// </summary>
    /// <param name="user">The App user with all properties</param>
    /// <returns>The string of the JWT token</returns>
    /// <exception cref="Exception">Thrown if there is no config for the token signature key.  It's required to exist and recommended to be unique per environment</exception>
    private async Task<string> CreateToken(Domain.Entities.Identity.AppUser user)
    {
        var claims = new List<Claim>
        {
            new (ClaimTypes.NameIdentifier, user.Id.ToString()),
            new (ClaimTypes.Name, user.Username),
            new ("Organization", user.OrganizationId.ToString())
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

        // Get the current signing key from the provider (supports key rotation)
        var signingKeyInfo = await signingKeyProvider.GetCurrentSigningKeyAsync();
        var credentials = new SigningCredentials(signingKeyInfo.Key, SecurityAlgorithms.HmacSha512Signature);

        var jwtExpirationTimeMinutes = appOptions.Value.JwtExpirationTimeMinutes;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(jwtExpirationTimeMinutes),
            SigningCredentials = credentials,
            Issuer = appOptions.Value.JwtIssuer,
            Audience = appOptions.Value.JwtAudience
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
