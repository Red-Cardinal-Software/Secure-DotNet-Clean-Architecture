using Application.Common.Configuration;
using Application.Common.Factories;
using Application.DTOs.Auth;
using Application.DTOs.Mfa.WebAuthn;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Services.Mfa;
using Domain.Entities.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Application.Tests.ServiceTests;

public class MfaAuthenticationServiceTests
{
    private readonly Mock<IMfaMethodRepository> _mfaMethodRepository;
    private readonly Mock<IMfaChallengeRepository> _mfaChallengeRepository;
    private readonly Mock<ITotpProvider> _totpProvider;
    private readonly Mock<IMfaEmailService> _mfaEmailService;
    private readonly Mock<IWebAuthnService> _webAuthnService;
    private readonly Mock<IUnitOfWork> _unitOfWork;
    private readonly MfaAuthenticationService _service;

    private readonly Guid _userId = Guid.NewGuid();
    private readonly Guid _methodId = Guid.NewGuid();
    private const string ChallengeToken = "challenge-token-12345";

    public MfaAuthenticationServiceTests()
    {
        _mfaMethodRepository = new Mock<IMfaMethodRepository>();
        _mfaChallengeRepository = new Mock<IMfaChallengeRepository>();
        var mfaRecoveryCodeService = new Mock<MfaRecoveryCodeService>(Mock.Of<IPasswordHasher>());
        _totpProvider = new Mock<ITotpProvider>();
        _mfaEmailService = new Mock<IMfaEmailService>();
        _webAuthnService = new Mock<IWebAuthnService>();
        _unitOfWork = new Mock<IUnitOfWork>();
        var logger = new Mock<ILogger<MfaAuthenticationService>>();

        var mfaOptions = new MfaOptions
        {
            MaxActiveChallenges = 3,
            MaxChallengesPerWindow = 5,
            RateLimitWindowMinutes = 5,
            ChallengeExpiryMinutes = 10
        };

        _service = new MfaAuthenticationService(
            _mfaMethodRepository.Object,
            _mfaChallengeRepository.Object,
            mfaRecoveryCodeService.Object,
            _totpProvider.Object,
            _mfaEmailService.Object,
            _webAuthnService.Object,
            _unitOfWork.Object,
            Options.Create(mfaOptions),
            logger.Object);
    }

    #region Helper Methods

    private MfaMethod CreateTotpMethod(Guid userId, bool isDefault = true, bool isEnabled = true)
    {
        var method = MfaMethod.CreateTotp(userId, "JBSWY3DPEHPK3PXP");
        method.UpdateName("My Authenticator");
        if (isEnabled)
        {
            method.Verify();
        }
        if (isDefault)
        {
            method.SetAsDefault();
        }
        return method;
    }

    private MfaMethod CreateEmailMethod(Guid userId, bool isDefault = false, bool isEnabled = true)
    {
        var method = MfaMethod.CreateEmail(userId, "test@example.com");
        method.UpdateName("My Email");
        if (isEnabled)
        {
            method.Verify();
        }
        if (isDefault)
        {
            method.SetAsDefault();
        }
        return method;
    }

    private MfaChallenge CreateChallenge(Guid userId, MfaType type = MfaType.Totp, Guid? methodId = null)
    {
        return MfaChallenge.Create(userId, type, methodId ?? _methodId, "192.168.1.1", "Test Browser");
    }

    #endregion

    #region CreateChallengeAsync Tests

    [Fact]
    public async Task CreateChallengeAsync_ShouldCreateChallenge_WhenUserHasEnabledMethods()
    {
        // Arrange
        var totpMethod = CreateTotpMethod(_userId);
        var enabledMethods = new List<MfaMethod> { totpMethod };

        _mfaMethodRepository.Setup(x => x.GetEnabledByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(enabledMethods);
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.CreateChallengeAsync(_userId, "192.168.1.1", "Test Browser");

        // Assert
        result.Should().NotBeNull();
        result.Data!.ChallengeToken.Should().NotBeNullOrEmpty();
        result.Data!.AvailableMethods.Should().HaveCount(1);
        result.Data!.AvailableMethods[0].Type.Should().Be(MfaType.Totp);
        result.Data!.AvailableMethods[0].IsDefault.Should().BeTrue();
        result.Data!.Instructions.Should().Contain("authenticator app");

        _mfaChallengeRepository.Verify(x => x.AddAsync(It.IsAny<MfaChallenge>(), It.IsAny<CancellationToken>()), Times.Once);
        _unitOfWork.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CreateChallengeAsync_ShouldReturnError_WhenUserHasNoEnabledMethods()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.GetEnabledByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaMethod>());
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.CreateChallengeAsync(_userId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("no enabled MFA methods");
    }

    [Fact]
    public async Task CreateChallengeAsync_ShouldReturnError_WhenRateLimited()
    {
        // Arrange
        var enabledMethods = new List<MfaMethod> { CreateTotpMethod(_userId) };

        _mfaMethodRepository.Setup(x => x.GetEnabledByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(enabledMethods);
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(5); // Exceeds max of 3

        // Act
        var result = await _service.CreateChallengeAsync(_userId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Too many MFA challenges");
    }

    [Fact]
    public async Task CreateChallengeAsync_ShouldSendEmailCode_WhenDefaultMethodIsEmail()
    {
        // Arrange
        var emailMethod = CreateEmailMethod(_userId, isDefault: true);
        var enabledMethods = new List<MfaMethod> { emailMethod };

        _mfaMethodRepository.Setup(x => x.GetEnabledByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(enabledMethods);
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _mfaEmailService.Setup(x => x.SendCodeAsync(
                It.IsAny<Guid>(),
                It.IsAny<Guid>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaEmailSendResult { Success = true });

        // Act
        var result = await _service.CreateChallengeAsync(_userId, "192.168.1.1");

        // Assert
        result.Data!.Instructions.Should().Contain("email");
        _mfaEmailService.Verify(x => x.SendCodeAsync(
            It.IsAny<Guid>(),
            _userId,
            It.IsAny<string>(),
            "192.168.1.1",
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CreateChallengeAsync_ShouldUseFirstMethod_WhenNoDefaultSet()
    {
        // Arrange
        var totpMethod = CreateTotpMethod(_userId, isDefault: false);
        var emailMethod = CreateEmailMethod(_userId, isDefault: false);
        var enabledMethods = new List<MfaMethod> { totpMethod, emailMethod };

        _mfaMethodRepository.Setup(x => x.GetEnabledByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(enabledMethods);
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.CreateChallengeAsync(_userId);

        // Assert
        result.Data!.AvailableMethods.Should().HaveCount(2);
        result.Data!.Instructions.Should().Contain("authenticator app"); // First method (TOTP)
    }

    #endregion

    #region VerifyMfaAsync Tests

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnSuccess_WhenValidTotpCode()
    {
        // Arrange
        var method = CreateTotpMethod(_userId);
        var challenge = CreateChallenge(_userId, MfaType.Totp, method.Id);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(method.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _totpProvider.Setup(x => x.ValidateCode("JBSWY3DPEHPK3PXP", "123456", It.IsAny<int>(), It.IsAny<int>(), It.IsAny<int>()))
            .Returns(true);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data!.UserId.Should().Be(_userId);
        result.Data!.MfaMethodId.Should().Be(method.Id);
        result.Data!.UsedRecoveryCode.Should().BeFalse();

        _mfaChallengeRepository.Verify(x => x.InvalidateAllUserChallengesAsync(_userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenInvalidChallengeToken()
    {
        // Arrange
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = "invalid-token",
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync("invalid-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaChallenge?)null);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid or expired challenge token");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenChallengeExpired()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        // Simulate an expired challenge by setting expiration time to past
        var expiredDate = DateTimeOffset.UtcNow.AddMinutes(-1); // 1 minute ago, expired
        typeof(MfaChallenge).GetProperty("ExpiresAt")?.SetValue(challenge, expiredDate);

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Challenge has expired or been exhausted");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenMaxAttemptsExceeded()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        // Simulate a challenge that will be exhausted on this attempt (2 failed attempts already)
        for (var i = 0; i < 2; i++)
        {
            challenge.RecordFailedAttempt();
        }

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Data!.IsExhausted.Should().BeTrue();
        result.Message.Should().Be("Maximum verification attempts exceeded");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenInvalidTotpCode()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var method = CreateTotpMethod(_userId);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "000000"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _totpProvider.Setup(x => x.ValidateCode("JBSWY3DPEHPK3PXP", "000000", It.IsAny<int>(), It.IsAny<int>(), It.IsAny<int>()))
            .Returns(false);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid authenticator code");
    }

    // NOTE: Recovery code testing is skipped because MfaRecoveryCodeService is a concrete class
    // without an interface, making it difficult to mock properly. This would require refactoring
    // the service to use dependency injection properly.
    // Recovery code validation is tested through integration tests instead.

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnSuccess_WhenValidEmailCode()
    {
        // Arrange
        var method = CreateEmailMethod(_userId);
        var challenge = CreateChallenge(_userId, MfaType.Email, method.Id);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(method.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge> { challenge });
        _mfaEmailService.Setup(x => x.VerifyCodeAsync(challenge.Id, "123456", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaEmailVerificationResult { Success = true });

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeTrue();
        result.Data!.UserId.Should().Be(_userId);
        result.Data!.MfaMethodId.Should().Be(method.Id);
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenMethodNotFound()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid MFA method");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenMethodDisabled()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var method = CreateTotpMethod(_userId, isEnabled: false);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid MFA method");
    }

    #endregion

    #region InvalidateUserChallengesAsync Tests

    [Fact]
    public async Task InvalidateUserChallengesAsync_ShouldReturnCount_WhenChallengesInvalidated()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.InvalidateAllUserChallengesAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        // Act
        var result = await _service.InvalidateUserChallengesAsync(_userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().Be(3);
        _unitOfWork.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task InvalidateUserChallengesAsync_ShouldReturnZero_WhenNoChallenges()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.InvalidateAllUserChallengesAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.InvalidateUserChallengesAsync(_userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().Be(0);
        _unitOfWork.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region RequiresMfaAsync Tests

    [Fact]
    public async Task RequiresMfaAsync_ShouldReturnTrue_WhenUserHasEnabledMfa()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.UserHasEnabledMfaAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _service.RequiresMfaAsync(_userId);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task RequiresMfaAsync_ShouldReturnFalse_WhenUserHasNoEnabledMfa()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.UserHasEnabledMfaAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        // Act
        var result = await _service.RequiresMfaAsync(_userId);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region GetDefaultMfaMethodAsync Tests

    [Fact]
    public async Task GetDefaultMfaMethodAsync_ShouldReturnMethod_WhenDefaultExists()
    {
        // Arrange
        var defaultMethod = CreateTotpMethod(_userId);
        _mfaMethodRepository.Setup(x => x.GetDefaultByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(defaultMethod);

        // Act
        var result = await _service.GetDefaultMfaMethodAsync(_userId);

        // Assert
        result.Should().NotBeNull();
        result.Type.Should().Be(MfaType.Totp);
        result.IsDefault.Should().BeTrue();
    }

    [Fact]
    public async Task GetDefaultMfaMethodAsync_ShouldReturnNull_WhenNoDefault()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.GetDefaultByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        // Act
        var result = await _service.GetDefaultMfaMethodAsync(_userId);

        // Assert
        result.Should().BeNull();
    }

    #endregion

    #region IsChallengeValidAsync Tests

    [Fact]
    public async Task IsChallengeValidAsync_ShouldReturnTrue_WhenChallengeValid()
    {
        // Arrange
        var challenge = CreateChallenge(_userId);
        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.IsChallengeValidAsync(ChallengeToken);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsChallengeValidAsync_ShouldReturnFalse_WhenChallengeNotFound()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaChallenge?)null);

        // Act
        var result = await _service.IsChallengeValidAsync(ChallengeToken);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region CanCreateChallengeAsync Tests

    [Fact]
    public async Task CanCreateChallengeAsync_ShouldReturnTrue_WhenWithinLimits()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1); // Below max of 3
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(2); // Below max of 5

        // Act
        var result = await _service.CanCreateChallengeAsync(_userId);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanCreateChallengeAsync_ShouldReturnFalse_WhenTooManyActiveChallenges()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(3); // Equals max of 3

        // Act
        var result = await _service.CanCreateChallengeAsync(_userId);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanCreateChallengeAsync_ShouldReturnFalse_WhenTooManyChallengesInWindow()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);
        _mfaChallengeRepository.Setup(x => x.GetChallengeCountSinceAsync(_userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(5); // Equals max of 5

        // Act
        var result = await _service.CanCreateChallengeAsync(_userId);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region GetActiveChallengeCountAsync Tests

    [Fact]
    public async Task GetActiveChallengeCountAsync_ShouldReturnRepositoryResult()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.GetActiveChallengeCountAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(2);

        // Act
        var result = await _service.GetActiveChallengeCountAsync(_userId);

        // Assert
        result.Should().Be(2);
    }

    #endregion

    #region CleanupExpiredChallengesAsync Tests

    [Fact]
    public async Task CleanupExpiredChallengesAsync_ShouldReturnCount_WhenChallengesCleaned()
    {
        // Arrange
        var cutoffTime = DateTimeOffset.UtcNow.AddHours(-2);
        _mfaChallengeRepository.Setup(x => x.DeleteExpiredChallengesAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(5);

        // Act
        var result = await _service.CleanupExpiredChallengesAsync(cutoffTime);

        // Assert
        result.Should().Be(5);
        _unitOfWork.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CleanupExpiredChallengesAsync_ShouldUseDefaultCutoff_WhenNoneProvided()
    {
        // Arrange
        _mfaChallengeRepository.Setup(x => x.DeleteExpiredChallengesAsync(
                It.Is<DateTimeOffset>(dt => dt <= DateTimeOffset.UtcNow.AddHours(-1)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        // Act
        var result = await _service.CleanupExpiredChallengesAsync();

        // Assert
        result.Should().Be(3);
    }

    #endregion

    #region Edge Cases and Error Scenarios

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenTotpSecretMissing()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var method = CreateTotpMethod(_userId);
        // Clear the secret to simulate configuration error
        typeof(MfaMethod).GetProperty("Secret")?.SetValue(method, null);

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Method configuration error");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenEmailChallengeNotFound()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Email, _methodId);
        var method = CreateEmailMethod(_userId);
        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge>()); // No email challenges

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("No active email challenge found");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenRecoveryCodeNotFound()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var method = CreateTotpMethod(_userId);
        // No recovery codes set

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "INVALID-RECOVERY",
            IsRecoveryCode = true
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid recovery code");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldUseSpecifiedMethod_WhenMfaMethodIdProvided()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.Totp, _methodId);
        var specificMethodId = Guid.NewGuid();
        var specificMethod = CreateEmailMethod(_userId);

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "123456",
            MfaMethodId = specificMethodId
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(specificMethodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(specificMethod);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge> { CreateChallenge(_userId, MfaType.Email, specificMethodId) });
        _mfaEmailService.Setup(x => x.VerifyCodeAsync(It.IsAny<Guid>(), "123456", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaEmailVerificationResult { Success = true });

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeTrue();
        _mfaMethodRepository.Verify(x => x.GetByIdAsync(specificMethodId, It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region WebAuthn Tests

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnSuccess_WhenValidWebAuthnAssertion()
    {
        // Arrange
        var method = MfaMethod.CreateWebAuthn(_userId, "credential-id", "public-key", "device");
        method.SetAsDefault();
        var challenge = CreateChallenge(_userId, MfaType.WebAuthn, method.Id);

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "webauthn-assertion-data"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(method.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge> { challenge });
        _webAuthnService.Setup(x => x.CompleteAuthenticationAsync(
                "simulated-credential-id",
                challenge.ChallengeToken,
                It.IsAny<WebAuthnAssertionResponse>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ServiceResponseFactory.Success(new WebAuthnAuthenticationResultDto { UserId = _userId, CredentialId = Guid.NewGuid() }));

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeTrue();
        result.Data!.UserId.Should().Be(_userId);
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenWebAuthnVerificationFails()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.WebAuthn, _methodId);
        var method = MfaMethod.CreateWebAuthn(_userId, "credential-id", "public-key", "device");

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "invalid-assertion"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge> { challenge });
        _webAuthnService.Setup(x => x.CompleteAuthenticationAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<WebAuthnAssertionResponse>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ServiceResponseFactory.Error<WebAuthnAuthenticationResultDto>("Invalid assertion"));

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid assertion");
    }

    [Fact]
    public async Task VerifyMfaAsync_ShouldReturnFailure_WhenWebAuthnChallengeNotFound()
    {
        // Arrange
        var challenge = CreateChallenge(_userId, MfaType.WebAuthn, _methodId);
        var method = MfaMethod.CreateWebAuthn(_userId, "credential-id", "public-key", "device");

        var completeMfaDto = new CompleteMfaDto
        {
            ChallengeToken = ChallengeToken,
            Code = "webauthn-data"
        };

        _mfaChallengeRepository.Setup(x => x.GetByChallengeTokenAsync(ChallengeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);
        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaChallengeRepository.Setup(x => x.GetActiveByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaChallenge>()); // No WebAuthn challenges

        // Act
        var result = await _service.VerifyMfaAsync(completeMfaDto);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("No active WebAuthn challenge found");
    }

    #endregion
}