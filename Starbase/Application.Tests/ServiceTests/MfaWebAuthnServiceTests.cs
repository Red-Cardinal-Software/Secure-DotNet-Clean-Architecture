using Application.Common.Factories;
using Application.DTOs.Mfa.WebAuthn;
using Application.Interfaces.Services;
using Application.Services.Mfa;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Application.Tests.ServiceTests;

/// <summary>
/// Unit tests for MfaWebAuthnService focusing on core business logic
/// and user extraction from claims.
/// </summary>
public class MfaWebAuthnServiceTests
{
    private readonly Mock<IWebAuthnService> _webAuthnService = new();
    private readonly Mock<ILogger<MfaWebAuthnService>> _mockLogger = new();
    private readonly MfaWebAuthnService _service;

    public MfaWebAuthnServiceTests()
    {
        _service = new MfaWebAuthnService(_webAuthnService.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task StartRegistrationAsync_ExtractsUserInfoFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var mfaMethodId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim("DisplayName", "Test User Display")
        ]));
        var request = new StartRegistrationDto { MfaMethodId = mfaMethodId };

        var mockResult = ServiceResponseFactory.Success(new WebAuthnRegistrationOptions());
        _webAuthnService.Setup(x => x.StartRegistrationAsync(userId, mfaMethodId, "testuser", "Test User Display", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.StartRegistrationAsync(user, request);

        // Assert
        result.Success.Should().BeTrue();
        _webAuthnService.Verify(x => x.StartRegistrationAsync(userId, mfaMethodId, "testuser", "Test User Display", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task StartRegistrationAsync_WithoutDisplayNameClaim_UsesUserName()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var mfaMethodId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
            // No DisplayName claim
        ]));
        var request = new StartRegistrationDto { MfaMethodId = mfaMethodId };

        var mockResult = ServiceResponseFactory.Success(new WebAuthnRegistrationOptions());
        _webAuthnService.Setup(x => x.StartRegistrationAsync(userId, mfaMethodId, "testuser", "testuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.StartRegistrationAsync(user, request);

        // Assert
        result.Success.Should().BeTrue();
        _webAuthnService.Verify(x => x.StartRegistrationAsync(userId, mfaMethodId, "testuser", "testuser", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task StartRegistrationAsync_WhenServiceFails_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var mfaMethodId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));
        var request = new StartRegistrationDto { MfaMethodId = mfaMethodId };

        var mockResult = ServiceResponseFactory.Error<WebAuthnRegistrationOptions>("Registration failed");
        _webAuthnService.Setup(x => x.StartRegistrationAsync(userId, mfaMethodId, "testuser", "testuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.StartRegistrationAsync(user, request);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Registration failed");
    }

    [Fact]
    public async Task StartAuthenticationAsync_ExtractsUserIdFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));

        var mockResult = ServiceResponseFactory.Success(new WebAuthnAuthenticationOptions());
        _webAuthnService.Setup(x => x.StartAuthenticationAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.StartAuthenticationAsync(user);

        // Assert
        result.Success.Should().BeTrue();
        _webAuthnService.Verify(x => x.StartAuthenticationAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetUserCredentialsAsync_ExtractsUserIdFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));

        var mockCredentials = new List<WebAuthnCredentialInfo>
        {
            new() { Id = Guid.NewGuid(), Name = "Security Key", AuthenticatorType = "CrossPlatform", Transports = Array.Empty<string>(), CreatedAt = DateTimeOffset.UtcNow, IsActive = true }
        };
        var mockResult = ServiceResponseFactory.Success<IReadOnlyList<WebAuthnCredentialInfo>>(mockCredentials);
        _webAuthnService.Setup(x => x.GetUserCredentialsAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.GetUserCredentialsAsync(user);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().HaveCount(1);
        _webAuthnService.Verify(x => x.GetUserCredentialsAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RemoveCredentialAsync_ExtractsUserIdFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));

        var mockResult = ServiceResponseFactory.Success<bool>(null!);
        _webAuthnService.Setup(x => x.RemoveCredentialAsync(userId, credentialId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.RemoveCredentialAsync(user, credentialId);

        // Assert
        result.Success.Should().BeTrue();
        _webAuthnService.Verify(x => x.RemoveCredentialAsync(userId, credentialId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RemoveCredentialAsync_WhenNotFound_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));

        var mockResult = ServiceResponseFactory.NotFound<bool>("Credential not found");
        _webAuthnService.Setup(x => x.RemoveCredentialAsync(userId, credentialId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.RemoveCredentialAsync(user, credentialId);

        // Assert
        result.Success.Should().BeFalse();
        result.Status.Should().Be(404);
    }

    [Fact]
    public async Task UpdateCredentialNameAsync_ExtractsUserIdFromClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));
        var request = new UpdateCredentialNameDto { Name = "Updated Security Key" };

        var mockResult = ServiceResponseFactory.Success<bool>(null!);
        _webAuthnService.Setup(x => x.UpdateCredentialNameAsync(userId, credentialId, "Updated Security Key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.UpdateCredentialNameAsync(user, credentialId, request);

        // Assert
        result.Success.Should().BeTrue();
        _webAuthnService.Verify(x => x.UpdateCredentialNameAsync(userId, credentialId, "Updated Security Key", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateCredentialNameAsync_WhenNotFound_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Name, "testuser")
        ]));
        var request = new UpdateCredentialNameDto { Name = "Updated Security Key" };

        var mockResult = ServiceResponseFactory.NotFound<bool>("Credential not found");
        _webAuthnService.Setup(x => x.UpdateCredentialNameAsync(userId, credentialId, "Updated Security Key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(mockResult);

        // Act
        var result = await _service.UpdateCredentialNameAsync(user, credentialId, request);

        // Assert
        result.Success.Should().BeFalse();
        result.Status.Should().Be(404);
    }
}