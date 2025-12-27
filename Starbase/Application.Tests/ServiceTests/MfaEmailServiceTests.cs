using Application.Common.Configuration;
using Application.DTOs.Email;
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

/// <summary>
/// Unit tests for MfaEmailService covering email MFA operations including
/// code generation, sending, verification, rate limiting, and cleanup.
/// </summary>
public class MfaEmailServiceTests
{
    private readonly Mock<IMfaEmailCodeRepository> _emailCodeRepository;
    private readonly Mock<IEmailService> _emailService;
    private readonly Mock<IPasswordHasher> _passwordHasher;
    private readonly MfaEmailService _service;

    public MfaEmailServiceTests()
    {
        _emailCodeRepository = new Mock<IMfaEmailCodeRepository>();
        _emailService = new Mock<IEmailService>();
        _passwordHasher = new Mock<IPasswordHasher>();
        var logger = new Mock<ILogger<MfaEmailService>>();

        var options = new EmailMfaOptions
        {
            MaxCodesPerWindow = 3,
            RateLimitWindowMinutes = 15,
            CodeExpiryMinutes = 5,
            CleanupAgeHours = 24,
            AppName = "TestApp",
            EnableSecurityWarnings = true
        };
        var emailMfaOptions = Options.Create(options);

        _service = new MfaEmailService(
            _emailCodeRepository.Object,
            _emailService.Object,
            _passwordHasher.Object,
            emailMfaOptions,
            logger.Object);
    }

    #region SendCodeAsync Tests

    [Fact]
    public async Task SendCodeAsync_WhenRateLimitExceeded_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(3); // Equal to MaxCodesPerWindow

        // Act
        var result = await _service.SendCodeAsync(challengeId, userId, email);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Too many email codes requested");
        _emailService.Verify(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<RenderedEmail>()), Times.Never);
        _emailCodeRepository.Verify(x => x.AddAsync(It.IsAny<MfaEmailCode>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task SendCodeAsync_WhenEmailFails_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var ipAddress = "192.168.1.1";

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(1); // Below limit

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns("hashed_code");

        _emailService.Setup(x => x.SendEmailAsync(email, It.IsAny<RenderedEmail>()))
            .ThrowsAsync(new Exception("Email service error"));

        // Act
        var result = await _service.SendCodeAsync(challengeId, userId, email, ipAddress);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Failed to send verification email. Please try again.");
        _emailCodeRepository.Verify(x => x.AddAsync(It.IsAny<MfaEmailCode>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SendCodeAsync_WhenSuccessful_ReturnsSuccessWithDetails()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var ipAddress = "192.168.1.1";

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Returns("hashed_code");

        _emailService.Setup(x => x.SendEmailAsync(email, It.IsAny<RenderedEmail>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _service.SendCodeAsync(challengeId, userId, email, ipAddress);

        // Assert
        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
        result.ExpiresAt.Should().BeCloseTo(DateTimeOffset.UtcNow.AddMinutes(5), TimeSpan.FromSeconds(1));
        result.RemainingAttempts.Should().Be(3); // MaxAttempts from domain entity

        _emailCodeRepository.Verify(x => x.AddAsync(
            It.Is<MfaEmailCode>(code =>
                code.MfaChallengeId == challengeId &&
                code.UserId == userId &&
                code.EmailAddress == email &&
                code.IpAddress == ipAddress &&
                code.HashedCode == "hashed_code"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SendCodeAsync_GeneratesSecureCode()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        string capturedPlainCode = null!;

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Callback<string>(code => capturedPlainCode = code)
            .Returns("hashed_code");

        _emailService.Setup(x => x.SendEmailAsync(email, It.IsAny<RenderedEmail>()))
            .Returns(Task.CompletedTask);

        // Act
        await _service.SendCodeAsync(challengeId, userId, email);

        // Assert
        capturedPlainCode.Should().NotBeNull();
        capturedPlainCode.Should().HaveLength(8);
        capturedPlainCode.Should().MatchRegex(@"^\d{8}$"); // 8 digits
        int.Parse(capturedPlainCode).Should().BeGreaterThanOrEqualTo(10000000);
    }

    [Fact]
    public async Task SendCodeAsync_WhenExceptionThrown_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _service.SendCodeAsync(challengeId, userId, email);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("An error occurred while sending the verification email.");
    }

    #endregion

    #region VerifyCodeAsync Tests

    [Fact]
    public async Task VerifyCodeAsync_WithEmptyCode_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, "");

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Verification code is required.");
        result.RemainingAttempts.Should().Be(0);
        _emailCodeRepository.Verify(x => x.GetValidCodeByChallengeIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_WithNoValidCode_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var code = "12345678";

        _emailCodeRepository.Setup(x => x.GetValidCodeByChallengeIdAsync(
                challengeId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaEmailCode?)null);

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, code);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid or expired verification code.");
        result.RemainingAttempts.Should().Be(0);
    }

    [Fact]
    public async Task VerifyCodeAsync_WhenMaxAttemptsExceeded_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var code = "12345678";
        var (emailCode, _) = MfaEmailCode.Create(challengeId, Guid.NewGuid(), "test@example.com", "hashed");

        // Simulate max attempts reached (MaxAttempts = 3)
        for (int i = 0; i < 3; i++)
        {
            emailCode.RecordAttempt();
        }

        _emailCodeRepository.Setup(x => x.GetValidCodeByChallengeIdAsync(
                challengeId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(emailCode);

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, code);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Maximum attempts exceeded.");
        result.RemainingAttempts.Should().Be(0);
        _passwordHasher.Verify(x => x.Verify(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task VerifyCodeAsync_WithInvalidCode_ReturnsFailureWithRemainingAttempts()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var code = "12345678";
        var (emailCode, _) = MfaEmailCode.Create(challengeId, Guid.NewGuid(), "test@example.com", "hashed");

        _emailCodeRepository.Setup(x => x.GetValidCodeByChallengeIdAsync(
                challengeId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(emailCode);

        _passwordHasher.Setup(x => x.Verify(code, "hashed"))
            .Returns(false);

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, code);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid verification code. 2 attempt(s) remaining.");
        result.RemainingAttempts.Should().Be(2);
        emailCode.AttemptCount.Should().Be(1);
    }

    [Fact]
    public async Task VerifyCodeAsync_WithValidCode_ReturnsSuccessAndMarksAsUsed()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var code = "12345678";
        var (emailCode, _) = MfaEmailCode.Create(challengeId, Guid.NewGuid(), "test@example.com", "hashed");

        _emailCodeRepository.Setup(x => x.GetValidCodeByChallengeIdAsync(
                challengeId,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(emailCode);

        _passwordHasher.Setup(x => x.Verify(code, "hashed"))
            .Returns(true);

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, code);

        // Assert
        result.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();
        emailCode.IsUsed.Should().BeTrue();
        emailCode.UsedAt.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task VerifyCodeAsync_WhenExceptionThrown_ReturnsFailure()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var code = "12345678";

        _emailCodeRepository.Setup(x => x.GetValidCodeByChallengeIdAsync(
                challengeId,
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _service.VerifyCodeAsync(challengeId, code);

        // Assert
        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("An error occurred while verifying the code.");
        result.RemainingAttempts.Should().Be(0);
    }

    #endregion

    #region CheckRateLimitAsync Tests

    [Fact]
    public async Task CheckRateLimitAsync_WhenUnderLimit_ReturnsAllowed()
    {
        // Arrange
        var userId = Guid.NewGuid();

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(2); // Under limit of 3

        // Act
        var result = await _service.CheckRateLimitAsync(userId);

        // Assert
        result.IsAllowed.Should().BeTrue();
        result.CodesUsed.Should().Be(2);
        result.MaxCodesAllowed.Should().Be(3);
        result.WindowResetTime.Should().BeCloseTo(
            DateTimeOffset.UtcNow.AddMinutes(-15).AddMinutes(15),
            TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CheckRateLimitAsync_WhenAtLimit_ReturnsExceeded()
    {
        // Arrange
        var userId = Guid.NewGuid();

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(3); // At limit

        // Act
        var result = await _service.CheckRateLimitAsync(userId);

        // Assert
        result.IsAllowed.Should().BeFalse();
        result.CodesUsed.Should().Be(3);
        result.MaxCodesAllowed.Should().Be(3);
    }

    [Fact]
    public async Task CheckRateLimitAsync_UsesCorrectTimeWindow()
    {
        // Arrange
        var userId = Guid.NewGuid();
        DateTimeOffset capturedWindowStart = default;

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Callback<Guid, DateTimeOffset, CancellationToken>((_, windowStart, _) => capturedWindowStart = windowStart)
            .ReturnsAsync(1);

        // Act
        await _service.CheckRateLimitAsync(userId);

        // Assert
        capturedWindowStart.Should().BeCloseTo(
            DateTimeOffset.UtcNow.AddMinutes(-15), // RateLimitWindowMinutes = 15
            TimeSpan.FromSeconds(1));
    }

    #endregion

    #region CleanupExpiredCodesAsync Tests

    [Fact]
    public async Task CleanupExpiredCodesAsync_CallsRepositoryWithCorrectTime()
    {
        // Arrange
        DateTimeOffset capturedExpiredBefore = default;

        _emailCodeRepository.Setup(x => x.DeleteExpiredCodesAsync(
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((expiredBefore, _) => capturedExpiredBefore = expiredBefore)
            .ReturnsAsync(10);

        // Act
        var result = await _service.CleanupExpiredCodesAsync();

        // Assert
        result.Should().Be(10);
        capturedExpiredBefore.Should().BeCloseTo(
            DateTimeOffset.UtcNow.AddHours(-24), // CleanupAgeHours = 24
            TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CleanupExpiredCodesAsync_WhenNoCodesDeleted_ReturnsZero()
    {
        // Arrange
        _emailCodeRepository.Setup(x => x.DeleteExpiredCodesAsync(
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        // Act
        var result = await _service.CleanupExpiredCodesAsync();

        // Assert
        result.Should().Be(0);
    }

    #endregion

    #region Email Content Tests

    [Fact]
    public async Task SendCodeAsync_SendsCorrectEmailContent()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        RenderedEmail capturedEmail = null!;
        string capturedCode = null!;

        _emailCodeRepository.Setup(x => x.GetCodeCountSinceAsync(
                userId,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _passwordHasher.Setup(x => x.Hash(It.IsAny<string>()))
            .Callback<string>(code => capturedCode = code)
            .Returns("hashed_code");

        _emailService.Setup(x => x.SendEmailAsync(email, It.IsAny<RenderedEmail>()))
            .Callback<string, RenderedEmail>((_, renderedEmail) => capturedEmail = renderedEmail)
            .Returns(Task.CompletedTask);

        // Act
        await _service.SendCodeAsync(challengeId, userId, email);

        // Assert
        capturedEmail.Should().NotBeNull();
        capturedEmail.Subject.Should().Be("Your verification code");
        capturedEmail.IsHtml.Should().BeTrue();
        capturedEmail.Body.Should().Contain($"<strong>{capturedCode}</strong>");
        capturedEmail.Body.Should().Contain("This code will expire in 5 minutes");
        capturedEmail.Body.Should().Contain("TestApp"); // AppName from options
    }

    #endregion
}