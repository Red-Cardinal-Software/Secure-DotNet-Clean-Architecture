using Application.Common.Configuration;
using Application.Common.Constants;
using Application.Interfaces.Persistence;
using Application.Interfaces.Providers;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Services.Auth;
using Domain.Entities.Identity;
using FluentAssertions;
using MediatR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using TestUtils.EntityBuilders;
using TestUtils.Utilities;
using Xunit;

namespace Application.Tests.ServiceTests;

public class AuthServiceTests
{
    private readonly Mock<IAppUserRepository> _userRepo = new();
    private readonly Mock<IPasswordResetEmailService> _emailService = new();
    private readonly Mock<IPasswordHasher> _passwordHasher = new();
    private readonly Mock<IPasswordResetService> _passwordResetService = new();
    private readonly Mock<IRefreshTokenRepository> _refreshTokenRepository = new();
    private readonly Mock<IRoleRepository> _roleRepository = new();
    private readonly Mock<IPasswordResetTokenRepository> _passwordResetTokenRepository = new();
    private readonly Mock<IAccountLockoutService> _accountLockoutService = new();
    private readonly Mock<IMfaAuthenticationService> _mfaAuthenticationService = new();
    private readonly Mock<ISigningKeyProvider> _signingKeyProvider = new();
    private readonly Mock<IMediator> _mediator = new();
    private readonly Mock<ILogger<AuthService>> _mockLogger = new();
    private readonly Mock<IUnitOfWork> _unitOfWork = new();

    private readonly AuthService _authService;

    public AuthServiceTests()
    {
        // Create AppOptions for the test
        var appOptions = new AppOptions
        {
            AppName = "Starbase Template (Test)",
            JwtSigningKey = "k<tS6l6;<{{P#'iI5vW8KZon7o7*_>j&V)b9<:&jB[_#wb[#GSm/$t<<u<=!#&|5@0M()Y",
            JwtIssuer = "https://localhost:5001",
            JwtAudience = "starbase-template-api-users-test",
            JwtExpirationTimeMinutes = 15,
            RefreshTokenExpirationTimeHours = 24,
            PasswordResetExpirationTimeHours = 1,
            PasswordMinimumLength = 8,
            PasswordMaximumLength = 64
        };

        var mockAppOptions = new Mock<IOptions<AppOptions>>();
        mockAppOptions.Setup(x => x.Value).Returns(appOptions);

        // Setup signing key provider mock
        var keyBytes = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(keyBytes);
        var testSigningKey = new SymmetricSecurityKey(keyBytes);
        var signingKeyInfo = new SigningKeyInfo
        {
            KeyId = "test-key",
            Key = testSigningKey,
            CreatedAt = DateTimeOffset.UtcNow,
            IsPrimary = true
        };
        _signingKeyProvider.Setup(x => x.GetCurrentSigningKeyAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(signingKeyInfo);

        _authService = new AuthService(
            _userRepo.Object,
            _emailService.Object,
            _passwordHasher.Object,
            _unitOfWork.Object,
            _passwordResetService.Object,
            _refreshTokenRepository.Object,
            _roleRepository.Object,
            _passwordResetTokenRepository.Object,
            _accountLockoutService.Object,
            _mfaAuthenticationService.Object,
            _signingKeyProvider.Object,
            _mediator.Object,
            _mockLogger.Object,
            mockAppOptions.Object
        );
    }

    [Fact]
    public async Task Login_WithInvalidUser_ReturnsError()
    {
        // Arrange
        _userRepo.Setup(x => x.UserExistsAsync("fakeuser")).ReturnsAsync(false);
        _accountLockoutService.Setup(x => x.RecordFailedAttemptAsync(
            Guid.Empty, "fakeuser", "127.0.0.1", null, ServiceResponseConstants.UserDoesNotExist,
            It.IsAny<CancellationToken>())).ReturnsAsync(false);

        // Act
        var result = await _authService.Login("fakeuser", "wrongpassword", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.UsernameOrPasswordIncorrect);
    }

    [Fact]
    public async Task Login_WithValidUser_ReturnsSuccess()
    {
        // Arrange
        var user = new AppUserBuilder().Build();
        var refreshToken = new RefreshToken(user, DateTime.UtcNow.AddMinutes(5), "10.0.0.1");

        _userRepo.Setup(x => x.UserExistsAsync("testuser")).ReturnsAsync(true);
        _userRepo.Setup(x => x.GetUserByUsernameAsync("testuser")).ReturnsAsync(user);
        _passwordHasher.Setup(x => x.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(true);
        _refreshTokenRepository.Setup(x =>
            x.SaveRefreshTokenAsync(It.IsAny<RefreshToken>())
        ).ReturnsAsync(refreshToken);

        // Account lockout service mocks
        _accountLockoutService.Setup(x => x.GetAccountLockoutAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Domain.Entities.Security.AccountLockout?)null);
        _accountLockoutService.Setup(x => x.RecordSuccessfulLoginAsync(
            user.Id, "testuser", "127.0.0.1", null, It.IsAny<CancellationToken>()));

        // MFA service mocks
        _mfaAuthenticationService.Setup(x => x.RequiresMfaAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        var result = await _authService.Login("testuser", TestConstants.Passwords.Default, "127.0.0.1");

        // Assert
        result.Success.Should().BeTrue();
        result.Data?.Token.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Login_WithWrongPassword_ReturnsError()
    {
        // Arrange
        var user = new AppUserBuilder().Build();

        _userRepo.Setup(x => x.UserExistsAsync("testuser")).ReturnsAsync(true);
        _userRepo.Setup(x => x.GetUserByUsernameAsync("testuser")).ReturnsAsync(user);
        _passwordHasher.Setup(x => x.Verify("wrongpass", "hashedpass")).Returns(false);

        // Account lockout service mocks
        _accountLockoutService.Setup(x => x.GetAccountLockoutAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Domain.Entities.Security.AccountLockout?)null);
        _accountLockoutService.Setup(x => x.RecordFailedAttemptAsync(
            user.Id, "testuser", "127.0.0.1", null, ServiceResponseConstants.InvalidCredentials, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        var result = await _authService.Login("testuser", "wrongpass", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.UsernameOrPasswordIncorrect);
    }

    [Fact]
    public async Task RequestPasswordReset_WithUnknownEmail_ReturnsSuccessWithNoLeak()
    {
        // Arrange
        _userRepo.Setup(x => x.GetUserByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((AppUser?)null);

        // Act
        var result = await _authService.RequestPasswordReset("unknown@example.com", "127.0.0.1");

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
        result.Message.Should().Be(ServiceResponseConstants.EmailPasswordResetSent);
    }

    [Fact]
    public async Task Logout_WithValidToken_RevokesFamily()
    {
        // Arrange
        var refreshTokenId = Guid.NewGuid();
        var tokenFamilyId = Guid.NewGuid();

        var user = new AppUserBuilder().Build();
        var refreshToken = new RefreshToken(user, DateTime.UtcNow.AddMinutes(1), "10.0.0.1", tokenFamilyId);

        _userRepo.Setup(x => x.GetUserByUsernameAsync(user.Username)).ReturnsAsync(user);
        _refreshTokenRepository.Setup(x => x.GetRefreshTokenAsync(refreshTokenId, user.Id)).ReturnsAsync(refreshToken);
        _refreshTokenRepository.Setup(x => x.RevokeRefreshTokenFamilyAsync(tokenFamilyId)).ReturnsAsync(true);

        // Act
        var result = await _authService.Logout(user.Username, refreshTokenId.ToString());

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
    }

    [Fact]
    public async Task Logout_WithInvalidUser_ReturnsUnauthorized()
    {
        // Arrange
        _userRepo.Setup(x => x.GetUserByUsernameAsync("unknown")).ReturnsAsync((AppUser?)null);

        // Act
        var result = await _authService.Logout("unknown", Guid.NewGuid().ToString());

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.UserUnauthorized);
    }

    [Fact]
    public async Task Logout_WithInvalidToken_ReturnsUnauthorized()
    {
        // Arrange
        var user = new AppUserBuilder().Build();

        _userRepo.Setup(x => x.GetUserByUsernameAsync(user.Username)).ReturnsAsync(user);
        _refreshTokenRepository.Setup(x => x.GetRefreshTokenAsync(It.IsAny<Guid>(), user.Id)).ReturnsAsync((RefreshToken?)null);

        // Act
        var result = await _authService.Logout(user.Username, Guid.NewGuid().ToString());

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.UserUnauthorized);
    }

    [Fact]
    public async Task Refresh_WithReusedToken_RevokesFamilyAndFails()
    {
        // Arrange
        var appUser = new AppUserBuilder().Build();
        var tokenFamilyId = Guid.NewGuid();

        var usedToken = new RefreshToken(appUser, DateTime.UtcNow.AddMinutes(10), "127.0.0.1", tokenFamilyId, "already-used");

        _userRepo.Setup(x => x.UserExistsAsync(appUser.Username)).ReturnsAsync(true);
        _userRepo.Setup(x => x.GetUserByUsernameAsync(appUser.Username)).ReturnsAsync(appUser);
        _refreshTokenRepository.Setup(x => x.GetRefreshTokenAsync(It.IsAny<Guid>(), appUser.Id)).ReturnsAsync(usedToken);
        _refreshTokenRepository.Setup(x => x.RevokeRefreshTokenFamilyAsync(tokenFamilyId)).ReturnsAsync(true);

        // Act
        var result = await _authService.Refresh(appUser.Username, usedToken.Id.ToString(), "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.UserUnauthorized);
    }

    [Fact]
    public async Task Login_WithLockedAccount_ReturnsAccountLocked()
    {
        // Arrange
        var user = new AppUserBuilder().Build();
        var lockedAccount = Domain.Entities.Security.AccountLockout.CreateForUser(user.Id);

        // Manually lock the account to simulate a locked state
        lockedAccount.LockAccount(TimeSpan.FromMinutes(30), "Too many failed attempts", null);

        _userRepo.Setup(x => x.UserExistsAsync("testuser")).ReturnsAsync(true);
        _userRepo.Setup(x => x.GetUserByUsernameAsync("testuser")).ReturnsAsync(user);
        _accountLockoutService.Setup(x => x.GetAccountLockoutAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(lockedAccount);

        // Act
        var result = await _authService.Login("testuser", "validpassword", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.AccountTemporarilyLocked);
    }

    [Fact]
    public async Task Login_WrongPasswordTriggersLockout_ReturnsAccountLocked()
    {
        // Arrange
        var user = new AppUserBuilder().Build();

        _userRepo.Setup(x => x.UserExistsAsync("testuser")).ReturnsAsync(true);
        _userRepo.Setup(x => x.GetUserByUsernameAsync("testuser")).ReturnsAsync(user);
        _passwordHasher.Setup(x => x.Verify("wrongpass", It.IsAny<string>())).Returns(false);

        // Account lockout service mocks
        _accountLockoutService.Setup(x => x.GetAccountLockoutAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Domain.Entities.Security.AccountLockout?)null);
        _accountLockoutService.Setup(x => x.RecordFailedAttemptAsync(
            user.Id, "testuser", "127.0.0.1", null, ServiceResponseConstants.InvalidCredentials, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true); // This attempt triggers lockout

        // Act
        var result = await _authService.Login("testuser", "wrongpass", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.AccountTemporarilyLocked);
    }

}
