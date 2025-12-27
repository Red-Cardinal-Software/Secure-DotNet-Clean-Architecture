using Application.Common.Configuration;
using Application.DTOs.Mfa;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Interfaces.Services;
using Application.Services.Mfa;
using Domain.Entities.Identity;
using Domain.Entities.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using TestUtils.EntityBuilders;
using Xunit;

namespace Application.Tests.ServiceTests;

public class MfaConfigurationServiceTests
{
    private readonly Mock<IMfaMethodRepository> _mfaMethodRepository;
    private readonly Mock<IAppUserRepository> _userRepository;
    private readonly Mock<ITotpProvider> _totpProvider;
    private readonly Mock<IPasswordHasher> _passwordHasher;
    private readonly Mock<IUnitOfWork> _unitOfWork;
    private readonly Mock<IEmailService> _emailService;
    private readonly MfaConfigurationService _service;

    private readonly Guid _userId = Guid.NewGuid();
    private readonly Guid _methodId = Guid.NewGuid();

    public MfaConfigurationServiceTests()
    {
        _mfaMethodRepository = new Mock<IMfaMethodRepository>();
        _userRepository = new Mock<IAppUserRepository>();
        _totpProvider = new Mock<ITotpProvider>();
        _passwordHasher = new Mock<IPasswordHasher>();

        // Setup password hasher to return a non-empty hash for any input
        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns((string input) => $"hashed_{input}");

        var recoveryCodeService = new MfaRecoveryCodeService(_passwordHasher.Object);
        _unitOfWork = new Mock<IUnitOfWork>();
        _emailService = new Mock<IEmailService>();
        var logger = new Mock<ILogger<MfaConfigurationService>>();

        var appOptions = new AppOptions { AppName = "TestApp" };
        var mfaOptions = new MfaOptions { ChallengeExpiryMinutes = 10, PromptSetup = true };

        _service = new MfaConfigurationService(
            _mfaMethodRepository.Object,
            _userRepository.Object,
            _totpProvider.Object,
            recoveryCodeService,
            _passwordHasher.Object,
            _unitOfWork.Object,
            Options.Create(appOptions),
            Options.Create(mfaOptions),
            _emailService.Object,
            logger.Object);
    }

    #region TOTP Setup Tests

    [Fact]
    public async Task StartTotpSetupAsync_ShouldReturnSetupDto_WhenValidUser()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var secret = "ABCD1234567890";
        var uri = "otpauth://totp/TestApp:testuser?secret=ABCD1234567890&issuer=TestApp";
        var qrCodeImage = "base64QRCode";

        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);
        _totpProvider.Setup(x => x.GenerateSecret(It.IsAny<int>()))
            .Returns(secret);
        _totpProvider.Setup(x => x.GenerateUri("testuser", secret, "TestApp", It.IsAny<int>(), It.IsAny<int>()))
            .Returns(uri);
        _totpProvider.Setup(x => x.GenerateQrCodeAsync(uri, It.IsAny<int>()))
            .ReturnsAsync(qrCodeImage);
        _totpProvider.Setup(x => x.FormatSecretForDisplay(secret))
            .Returns("ABCD 1234 5678 90");

        // Act
        var result = await _service.StartTotpSetupAsync(userId, "testuser", CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Secret.Should().Be(secret);
        result.Data.FormattedSecret.Should().Be("ABCD 1234 5678 90");
        result.Data.QrCodeUri.Should().Be(uri);
        result.Data.QrCodeImage.Should().Be(qrCodeImage);
        result.Data.IssuerName.Should().Be("TestApp");
        result.Data.AccountName.Should().Be("testuser");

        _mfaMethodRepository.Verify(x => x.AddAsync(It.IsAny<MfaMethod>(), It.IsAny<CancellationToken>()), Times.Once);
        _unitOfWork.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task StartTotpSetupAsync_ShouldReturnError_WhenUserNotFound()
    {
        // Arrange
        _userRepository.Setup(x => x.GetUserByIdAsync(_userId))
            .ReturnsAsync((AppUser?)null);

        // Act
        var result = await _service.StartTotpSetupAsync(_userId, "testuser", CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("User not found");
    }

    [Fact]
    public async Task StartTotpSetupAsync_ShouldReturnError_WhenTotpAlreadyEnabled()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var existingMethod = MfaMethod.CreateTotp(userId, "secret");
        existingMethod.Verify();

        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingMethod);

        // Act
        var result = await _service.StartTotpSetupAsync(userId, "testuser", CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("already configured");
    }

    [Fact]
    public async Task StartTotpSetupAsync_ShouldRemoveExistingUnverified_ThenCreateNew()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var existingUnverified = MfaMethod.CreateTotp(userId, "oldsecret");
        var secret = "ABCD1234567890";

        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingUnverified);
        _totpProvider.Setup(x => x.GenerateSecret(It.IsAny<int>()))
            .Returns(secret);
        _totpProvider.Setup(x => x.GenerateUri(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<int>()))
            .Returns("uri");
        _totpProvider.Setup(x => x.GenerateQrCodeAsync(It.IsAny<string>(), It.IsAny<int>()))
            .ReturnsAsync("qr");

        // Act
        await _service.StartTotpSetupAsync(userId, "testuser", CancellationToken.None);

        // Assert
        _mfaMethodRepository.Verify(x => x.Remove(existingUnverified), Times.Once);
        _mfaMethodRepository.Verify(x => x.AddAsync(It.IsAny<MfaMethod>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task VerifyTotpSetupAsync_ShouldCompleteSetup_WhenValidCode()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var method = MfaMethod.CreateTotp(userId, "secret");
        var verifyDto = new VerifyMfaSetupDto { Code = "123456", Name = "My Authenticator" };

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _totpProvider.Setup(x => x.ValidateCode("secret", "123456", It.IsAny<int>(), It.IsAny<int>(), It.IsAny<int>()))
            .Returns(true);
        _mfaMethodRepository.Setup(x => x.GetEnabledCountByUserIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.VerifyTotpSetupAsync(userId, verifyDto, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.MfaMethodId.Should().Be(method.Id);
        result.Data.RecoveryCodes.Should().HaveCount(8); // Real service generates 8 codes
        result.Data.IsDefault.Should().BeTrue(); // First method becomes default
        result.Data.SecurityMessage.Should().Contain("Save these recovery codes");

        _emailService.Verify(x => x.SendMfaSecurityNotificationAsync(
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task VerifyTotpSetupAsync_ShouldReturnError_WhenInvalidCode()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        var verifyDto = new VerifyMfaSetupDto { Code = "000000" };
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _userRepository.Setup(x => x.GetUserByIdAsync(_userId))
            .ReturnsAsync(user);
        _totpProvider.Setup(x => x.ValidateCode("secret", "000000", It.IsAny<int>(), It.IsAny<int>(), It.IsAny<int>()))
            .Returns(false);

        // Act
        var result = await _service.VerifyTotpSetupAsync(_userId, verifyDto, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Invalid verification code");
    }

    #endregion

    #region Email Setup Tests

    [Fact]
    public async Task StartEmailSetupAsync_ShouldReturnSetupDto_WhenValidEmail()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var email = "test@example.com";

        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);
        _emailService.Setup(x => x.SendMfaSetupVerificationCodeAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _service.StartEmailSetupAsync(userId, email, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.EmailAddress.Should().Be(email);
        result.Data.CodeSent.Should().BeTrue();
        result.Data.Instructions.Should().Contain("verification code");
        result.Data.ExpiresAt.Should().BeCloseTo(DateTimeOffset.UtcNow.AddMinutes(10), TimeSpan.FromMinutes(1));

        _mfaMethodRepository.Verify(x => x.AddAsync(It.IsAny<MfaMethod>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task StartEmailSetupAsync_ShouldReturnError_WhenInvalidEmail()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;

        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);

        // Act
        var result = await _service.StartEmailSetupAsync(userId, "invalid-email", CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Invalid email");
    }

    [Fact]
    public async Task VerifyEmailSetupAsync_ShouldCompleteSetup_WhenValidCode()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var userId = user.Id;
        var method = MfaMethod.CreateEmail(userId, "test@example.com");
        method.StoreSetupVerificationCode("hashedcode", DateTimeOffset.UtcNow.AddMinutes(10));

        var verifyDto = new VerifyMfaSetupDto { Code = "123456", Name = "My Email" };

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _userRepository.Setup(x => x.GetUserByIdAsync(userId))
            .ReturnsAsync(user);
        _passwordHasher.Setup(x => x.Verify("123456", "hashedcode"))
            .Returns(true);
        _mfaMethodRepository.Setup(x => x.GetEnabledCountByUserIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.VerifyEmailSetupAsync(userId, verifyDto, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.MfaMethodId.Should().Be(method.Id);
        result.Data.IsDefault.Should().BeTrue();
        result.Data.SecurityMessage.Should().Contain("email");
    }

    #endregion

    #region Method Management Tests

    [Fact]
    public async Task GetMfaOverviewAsync_ShouldReturnCorrectOverview()
    {
        // Arrange
        var methods = new List<MfaMethod>
        {
            MfaMethod.CreateTotp(_userId, "secret1"),
            MfaMethod.CreateEmail(_userId, "test@example.com")
        };
        methods[0].Verify(); // Enable first method

        _mfaMethodRepository.Setup(x => x.GetByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(methods);

        // Act
        var result = await _service.GetMfaOverviewAsync(_userId, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.HasEnabledMfa.Should().BeTrue();
        result.Data.TotalMethods.Should().Be(2);
        result.Data.EnabledMethods.Should().Be(1);
        result.Data.Methods.Should().HaveCount(2);
        result.Data.AvailableTypes.Should().Contain(nameof(MfaType.WebAuthn));
        result.Data.AvailableTypes.Should().Contain(nameof(MfaType.Push));
    }

    [Fact]
    public async Task GetMfaMethodAsync_ShouldReturnMethod_WhenUserOwnsMethod()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        method.Verify();

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.GetMfaMethodAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Type.Should().Be(MfaType.Totp);
        result.Data.IsEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task GetMfaMethodAsync_ShouldReturnNull_WhenUserDoesNotOwnMethod()
    {
        // Arrange
        var otherUserId = Guid.NewGuid();
        var method = MfaMethod.CreateTotp(otherUserId, "secret");

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.GetMfaMethodAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeNull();
    }

    [Fact]
    public async Task UpdateMfaMethodAsync_ShouldUpdateName_WhenProvided()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        var updateDto = new UpdateMfaMethodDto { Name = "New Name" };

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.UpdateMfaMethodAsync(_userId, _methodId, updateDto, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Name.Should().Be("New Name");
    }

    [Fact]
    public async Task SetDefaultMfaMethodAsync_ShouldSetMethodAsDefault_WhenEnabledMethod()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        method.Verify(); // Enable the method

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.SetDefaultMfaMethodAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        _mfaMethodRepository.Verify(x => x.ClearDefaultFlagsAsync(_userId, It.IsAny<CancellationToken>()), Times.Once);
        method.IsDefault.Should().BeTrue();
    }

    [Fact]
    public async Task SetDefaultMfaMethodAsync_ShouldReturnError_WhenMethodNotEnabled()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        // Don't verify - leave disabled

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.SetDefaultMfaMethodAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task RemoveMfaMethodAsync_ShouldRemoveMethod_WhenValidConditions()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaMethodRepository.Setup(x => x.GetEnabledCountByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(2); // More than one enabled method

        // Act
        var result = await _service.RemoveMfaMethodAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
        _mfaMethodRepository.Verify(x => x.Remove(method), Times.Once);
    }

    #endregion

    #region Recovery Code Tests

    [Fact]
    public async Task RegenerateRecoveryCodesAsync_ShouldGenerateNewCodes_WhenValidMethod()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        method.Verify();

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.RegenerateRecoveryCodesAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Should().HaveCount(8); // Real service generates 8 codes
        result.Data.Should().OnlyContain(code => !string.IsNullOrWhiteSpace(code));
        result.Data.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public async Task RegenerateRecoveryCodesAsync_ShouldReturnError_WhenMethodNotEnabled()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        // Don't verify - leave disabled

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.RegenerateRecoveryCodesAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task GetRecoveryCodeCountAsync_ShouldReturnCount_WhenMethodExists()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        var recoveryCodes = new List<MfaRecoveryCode>
        {
            MfaRecoveryCode.Create(method.Id, "hash1", "CODE1"),
            MfaRecoveryCode.Create(method.Id, "hash2", "CODE2")
        };
        method.SetRecoveryCodes(recoveryCodes);

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.GetRecoveryCodeCountAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().Be(2);
    }

    #endregion

    #region Validation Tests

    [Fact]
    public async Task UserHasMfaEnabledAsync_ShouldReturnRepositoryResult()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.UserHasEnabledMfaAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _service.UserHasMfaEnabledAsync(_userId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateMethodRemovalAsync_ShouldReturnWarning_WhenLastMethod()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        method.Verify();

        _mfaMethodRepository.Setup(x => x.GetByIdAsync(_methodId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);
        _mfaMethodRepository.Setup(x => x.GetEnabledCountByUserIdAsync(_userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        // Act
        var result = await _service.ValidateMethodRemovalAsync(_userId, _methodId, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.CanRemove.Should().BeTrue();
        result.Data.WillDisableMfa.Should().BeTrue();
        result.Data.RemainingMethodCount.Should().Be(0);
        result.Data.Warnings.Should().Contain("This will remove your last MFA method and disable two-factor authentication.");
    }

    [Fact]
    public async Task CanSetupMfaTypeAsync_ShouldReturnFalse_WhenTypeAlreadyEnabled()
    {
        // Arrange
        var existingMethod = MfaMethod.CreateTotp(_userId, "secret");
        existingMethod.Verify();

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingMethod);

        // Act
        var result = await _service.CanSetupMfaTypeAsync(_userId, MfaType.Totp, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeFalse();
    }

    [Fact]
    public async Task CanSetupMfaTypeAsync_ShouldReturnTrue_WhenTypeNotSetup()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        // Act
        var result = await _service.CanSetupMfaTypeAsync(_userId, MfaType.Totp, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
    }

    #endregion

    #region Administrative Tests

    [Fact]
    public async Task GetMfaStatisticsAsync_ShouldReturnSystemWideStats_WhenNoOrganization()
    {
        // Arrange
        var methodsByType = new Dictionary<MfaType, int>
        {
            { MfaType.Totp, 100 },
            { MfaType.Email, 50 }
        };

        _userRepository.Setup(x => x.GetTotalUserCountAsync())
            .ReturnsAsync(200);
        _mfaMethodRepository.Setup(x => x.GetUsersWithMfaCountAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(120);
        _mfaMethodRepository.Setup(x => x.GetMethodCountByTypeAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(methodsByType);
        _mfaMethodRepository.Setup(x => x.GetUnverifiedMethodCountAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(10);

        // Act
        var result = await _service.GetMfaStatisticsAsync(null, CancellationToken.None);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.TotalUsers.Should().Be(200);
        result.Data.UsersWithMfa.Should().Be(120);
        result.Data.MfaAdoptionRate.Should().Be(60.0m);
        result.Data.MethodsByType.Should().BeEquivalentTo(methodsByType);
        result.Data.UnverifiedSetups.Should().Be(10);
    }

    [Fact]
    public async Task CleanupUnverifiedMethodsAsync_ShouldRemoveOldMethods()
    {
        // Arrange
        var oldMethods = new List<MfaMethod>
        {
            MfaMethod.CreateTotp(_userId, "secret1"),
            MfaMethod.CreateEmail(_userId, "test@example.com")
        };
        var maxAge = TimeSpan.FromDays(1);

        _mfaMethodRepository.Setup(x => x.GetUnverifiedOlderThanAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(oldMethods);

        // Act
        var result = await _service.CleanupUnverifiedMethodsAsync(maxAge, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().Be(2);
        _mfaMethodRepository.Verify(x => x.Remove(It.IsAny<MfaMethod>()), Times.Exactly(2));
    }

    #endregion

    #region Cancel Setup Tests

    [Fact]
    public async Task CancelSetupAsync_ShouldReturnTrue_WhenUnverifiedMethodExists()
    {
        // Arrange
        var unverifiedMethod = MfaMethod.CreateTotp(_userId, "secret");

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(unverifiedMethod);

        // Act
        var result = await _service.CancelSetupAsync(_userId, MfaType.Totp, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
        _mfaMethodRepository.Verify(x => x.Remove(unverifiedMethod), Times.Once);
    }

    [Fact]
    public async Task CancelSetupAsync_ShouldReturnFalse_WhenMethodNotFound()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        // Act
        var result = await _service.CancelSetupAsync(_userId, MfaType.Totp, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeFalse();
    }

    [Fact]
    public async Task CancelSetupAsync_ShouldReturnFalse_WhenMethodIsAlreadyEnabled()
    {
        // Arrange
        var verifiedMethod = MfaMethod.CreateTotp(_userId, "secret");
        verifiedMethod.Verify();

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(verifiedMethod);

        // Act
        var result = await _service.CancelSetupAsync(_userId, MfaType.Totp, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeFalse();
    }

    #endregion

    #region Edge Cases and Error Scenarios

    [Fact]
    public async Task VerifyTotpSetupAsync_ShouldReturnError_WhenNoSetupFound()
    {
        // Arrange
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        // Act
        var result = await _service.VerifyTotpSetupAsync(_userId, new VerifyMfaSetupDto { Code = "123456" }, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("setup");
    }

    [Fact]
    public async Task VerifyTotpSetupAsync_ShouldReturnError_WhenAlreadyVerified()
    {
        // Arrange
        var method = MfaMethod.CreateTotp(_userId, "secret");
        method.Verify(); // Already verified

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Totp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(method);

        // Act
        var result = await _service.VerifyTotpSetupAsync(_userId, new VerifyMfaSetupDto { Code = "123456" }, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task StartEmailSetupAsync_ShouldHandleEmailServiceFailure()
    {
        // Arrange
        var user = new AppUserBuilder().WithEmail("test@user.org").Build();
        var email = "test@example.com";

        _userRepository.Setup(x => x.GetUserByIdAsync(_userId))
            .ReturnsAsync(user);
        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(_userId, MfaType.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);
        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns("hashedcode");
        _emailService.Setup(x => x.SendMfaSetupVerificationCodeAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Email service failed"));

        // Act
        var result = await _service.StartEmailSetupAsync(_userId, email, CancellationToken.None);

        // Assert
        result.Success.Should().BeTrue(); // Setup succeeds but code not sent
        result.Data.Should().NotBeNull();
        result.Data!.CodeSent.Should().BeFalse();
        result.Data.Message.Should().Contain("could not be sent");
    }

    #endregion
}
