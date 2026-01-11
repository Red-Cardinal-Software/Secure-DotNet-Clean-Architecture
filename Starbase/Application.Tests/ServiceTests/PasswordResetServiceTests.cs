using Application.Common.Constants;
using Application.Interfaces.Repositories;
using Application.Interfaces.Security;
using Application.Services.PasswordReset;
using Domain.Entities.Identity;
using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.Extensions.Logging;
using Moq;
using TestUtils.EntityBuilders;
using TestUtils.Utilities;
using Xunit;

namespace Application.Tests.ServiceTests;

public class PasswordResetServiceTests
{
    private readonly Mock<IAppUserRepository> _appUserRepository = new();
    private readonly Mock<IPasswordHasher> _passwordHasher = new();
    private readonly Mock<IPasswordResetTokenRepository> _passwordResetTokenRepository = new();
    private readonly Mock<IValidator<string>> _passwordValidator = new();
    private readonly Mock<ILogger<PasswordResetService>> _mockLogger = new();

    private readonly PasswordResetService _passwordResetService;
    public PasswordResetServiceTests()
    {
        _passwordResetService = new PasswordResetService(
            _passwordResetTokenRepository.Object,
            _passwordHasher.Object,
            _appUserRepository.Object,
            _mockLogger.Object,
            _passwordValidator.Object
        );
    }

    [Fact]
    public async Task ApplyPasswordReset_WithValidToken_ChangesPassword()
    {
        // Arrange
        var appUser = new AppUserBuilder().Build();
        var updatedAppUser = new AppUserBuilder().WithPassword("newhash").Build();
        var token = new PasswordResetToken(appUser, DateTime.UtcNow.AddHours(1), "127.0.0.1");

        var newPassword = "newpassword12345";

        var positiveValidationResult = new ValidationResult
        {
            Errors = []
        };

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>())).ReturnsAsync(token);

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>()))
            .ReturnsAsync(token);

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns(updatedAppUser.Password);

        _passwordResetTokenRepository.Setup(x => x.GetAllUnclaimedResetTokensForUserAsync(It.IsAny<Guid>()))
            .ReturnsAsync([]);

        _passwordValidator.Setup(x => x.ValidateAsync(newPassword, CancellationToken.None)).ReturnsAsync(positiveValidationResult);

        // Act
        var result = await _passwordResetService.ResetPasswordWithTokenAsync(
            token.Id.ToString(), "newpassword12345", "127.0.0.1");

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
    }

    [Fact]
    public async Task ApplyPasswordReset_WithValidToken_WithUnclaimedTokens_ChangesPassword()
    {
        // Arrange
        var appUser = new AppUserBuilder().Build();
        var updatedAppUser = new AppUserBuilder().WithPassword("newhash").Build();
        var token = new PasswordResetToken(appUser, DateTime.UtcNow.AddHours(1), "127.0.0.1");
        var unclaimedToken = new PasswordResetToken(appUser, DateTime.UtcNow.AddHours(1), "127.0.0.1");

        var positiveValidationResult = new ValidationResult
        {
            Errors = []
        };

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>()))
            .ReturnsAsync(token);

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns(updatedAppUser.Password);

        _passwordResetTokenRepository.Setup(x => x.GetAllUnclaimedResetTokensForUserAsync(It.IsAny<Guid>()))
            .ReturnsAsync([unclaimedToken]);

        _passwordValidator.Setup(x => x.ValidateAsync(It.IsAny<string>(), CancellationToken.None)).ReturnsAsync(positiveValidationResult);

        // Act
        var result = await _passwordResetService.ResetPasswordWithTokenAsync(
            token.Id.ToString(), "newpassword", "127.0.0.1");

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
    }

    [Fact]
    public async Task ApplyPasswordReset_WithInvalidToken_DoesNotChangePassword()
    {
        // Arrange
        var appUser = new AppUserBuilder().Build();
        var token = new PasswordResetToken(appUser, DateTime.UtcNow.AddHours(1), "127.0.0.1");

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>()))
            .ReturnsAsync((PasswordResetToken)null!);

        // Act
        var result = await _passwordResetService.ResetPasswordWithTokenAsync(
            token.Id.ToString(), "newpassword", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Data.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.InvalidPasswordResetToken);
    }

    [Fact]
    public async Task ApplyPasswordReset_WithValidToken_WithBlankPassword_DoesNotChangePassword()
    {
        // Arrange
        var appUser = new AppUserBuilder().Build();
        var token = new PasswordResetToken(appUser, DateTime.UtcNow.AddHours(1), "127.0.0.1");

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>())).ReturnsAsync(token);

        var invalidResult = new ValidationResult
        {
            Errors = [
                new ValidationFailure("Password", ServiceResponseConstants.PasswordMustNotBeEmpty)
            ]
        };

        _passwordResetTokenRepository.Setup(x => x.GetPasswordResetTokenAsync(It.IsAny<Guid>()))
            .ReturnsAsync(token);

        _passwordValidator.Setup(x => x.ValidateAsync("", CancellationToken.None)).ReturnsAsync(invalidResult);

        // Act
        var result = await _passwordResetService.ResetPasswordWithTokenAsync(
            token.Id.ToString(), "", "127.0.0.1");

        // Assert
        result.Success.Should().BeFalse();
        result.Data.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.PasswordMustNotBeEmpty);
    }

    [Fact]
    public async Task ForcePasswordReset_WithSamePassword_Fails()
    {
        // Arrange
        var user = new AppUserBuilder().Build();

        var positiveValidationResult = new ValidationResult
        {
            Errors = []
        };

        _appUserRepository.Setup(x => x.GetUserByIdAsync(user.Id)).ReturnsAsync(user);
        _passwordHasher.Setup(x => x.Verify(TestConstants.Passwords.Default, user.Password)).Returns(true);
        _passwordValidator.Setup(x => x.ValidateAsync(It.IsAny<string>(), CancellationToken.None)).ReturnsAsync(positiveValidationResult);

        // Act
        var result = await _passwordResetService.ForcePasswordResetAsync(user.Id, TestConstants.Passwords.Default);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be(ServiceResponseConstants.PasswordMustBeDifferentFromCurrent);
    }
}
