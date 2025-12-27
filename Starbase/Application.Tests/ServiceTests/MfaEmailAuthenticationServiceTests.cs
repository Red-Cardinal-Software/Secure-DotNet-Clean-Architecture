using Application.DTOs.Mfa.EmailMfa;
using Application.Interfaces.Services;
using Application.Services.Mfa;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Application.Tests.ServiceTests;

/// <summary>
/// Unit tests for MfaEmailAuthenticationService focusing on core business logic
/// and user extraction from claims.
/// </summary>
public class MfaEmailAuthenticationServiceTests
{
    private readonly Mock<IMfaEmailService> _emailMfaService = new();
    private readonly Mock<ILogger<MfaEmailAuthenticationService>> _mockLogger = new();
    private readonly MfaEmailAuthenticationService _service;

    public MfaEmailAuthenticationServiceTests()
    {
        _service = new MfaEmailAuthenticationService(_emailMfaService.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task SendCodeAsync_WithoutEmailInRequestOrClaims_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var challengeId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
            // No email claim
        ]));

        var request = new SendEmailCodeDto
        {
            ChallengeId = challengeId,
            EmailAddress = null
        };

        // Act
        var result = await _service.SendCodeAsync(user, request, null);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("No email address provided and no email found in user profile");
    }

    [Fact]
    public async Task SendCodeAsync_UsesEmailFromClaims_WhenNotInRequest()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var challengeId = Guid.NewGuid();
        var email = "user@domain.com";

        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Email, email)
        ]));

        var request = new SendEmailCodeDto
        {
            ChallengeId = challengeId,
            EmailAddress = null // No email in request
        };

        // Mock the service to return success
        var mockResult = new MfaEmailSendResult { Success = true, ExpiresAt = DateTime.UtcNow.AddMinutes(10), RemainingAttempts = 5 };
        _emailMfaService.Setup(x => x.SendCodeAsync(challengeId, userId, email, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.SendCodeAsync(user, request, null);

        // Assert - Verify the service was called with the email from claims
        _emailMfaService.Verify(x => x.SendCodeAsync(challengeId, userId, email, null, It.IsAny<CancellationToken>()), Times.Once);
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data!.MaskedEmail.Should().Be("u**r@domain.com");
    }

    [Theory]
    [InlineData("test@example.com")]
    [InlineData("user.name@domain.org")]
    [InlineData("a@b.co")]
    public async Task SendCodeAsync_ExtractsUserIdFromClaims(string email)
    {
        // Arrange
        var userId = Guid.NewGuid();
        var challengeId = Guid.NewGuid();

        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Email, email)
        ]));

        var request = new SendEmailCodeDto
        {
            ChallengeId = challengeId,
            EmailAddress = email
        };

        // Mock the service to return success
        var mockResult = new MfaEmailSendResult { Success = true, ExpiresAt = DateTime.UtcNow.AddMinutes(10), RemainingAttempts = 5 };
        _emailMfaService.Setup(x => x.SendCodeAsync(challengeId, userId, email, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        await _service.SendCodeAsync(user, request, "127.0.0.1");

        // Assert - Verify the correct user ID was extracted and passed
        _emailMfaService.Verify(x => x.SendCodeAsync(challengeId, userId, email, "127.0.0.1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task VerifyCodeAsync_PassesCorrectParameters()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var request = new VerifyEmailCodeDto
        {
            ChallengeId = challengeId,
            Code = "12345678"
        };

        // Mock the service to return success
        var mockResult = new MfaEmailVerificationResult { Success = true };
        _emailMfaService.Setup(x => x.VerifyCodeAsync(challengeId, "12345678", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.VerifyCodeAsync(request);

        // Assert
        _emailMfaService.Verify(x => x.VerifyCodeAsync(challengeId, "12345678", It.IsAny<CancellationToken>()), Times.Once);
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
    }

    [Fact]
    public async Task CheckRateLimitAsync_ExtractsUserIdFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));

        // Mock the service to return success
        var mockResult = new MfaRateLimitResult
        {
            IsAllowed = true,
            CodesUsed = 2,
            MaxCodesAllowed = 5,
            WindowResetTime = DateTime.UtcNow.AddMinutes(30)
        };
        _emailMfaService.Setup(x => x.CheckRateLimitAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.CheckRateLimitAsync(user);

        // Assert
        _emailMfaService.Verify(x => x.CheckRateLimitAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Data!.IsAllowed.Should().BeTrue();
        result.Data.CodesUsed.Should().Be(2);
        result.Data.MaxCodes.Should().Be(5);
    }
}