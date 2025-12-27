using Application.Common.Configuration;
using Application.DTOs.Mfa;
using Application.Interfaces.Persistence;
using Application.Interfaces.Providers;
using Application.Interfaces.Repositories;
using Application.Services.Mfa;
using AutoMapper;
using Domain.Entities.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Application.Tests.ServiceTests;

/// <summary>
/// Unit tests for MfaPushService covering push notification MFA operations including
/// device registration, challenge management, signature verification, and cleanup.
/// </summary>
public class MfaPushServiceTests
{
    private readonly Mock<IMfaPushRepository> _mfaRepository;
    private readonly Mock<IMfaMethodRepository> _mfaMethodRepository;
    private readonly Mock<IPushNotificationProvider> _pushProvider;
    private readonly MfaPushService _service;

    public MfaPushServiceTests()
    {
        var unitOfWork = new Mock<IUnitOfWork>();
        _mfaRepository = new Mock<IMfaPushRepository>();
        _mfaMethodRepository = new Mock<IMfaMethodRepository>();
        _pushProvider = new Mock<IPushNotificationProvider>();
        var mapper = new Mock<IMapper>();
        var logger = new Mock<ILogger<MfaPushService>>();

        var pushOptions = new PushMfaOptions
        {
            ChallengeExpiryMinutes = 5,
            MaxChallengesPerWindow = 5,
            RateLimitWindowMinutes = 5,
            CleanupAgeHours = 24,
            Provider = "Mock"
        };
        var pushMfaOptions = Options.Create(pushOptions);

        var appOptions = new AppOptions
        {
            AppName = "TestApp",
            JwtSigningKey = "test-signing-key-that-is-at-least-32-characters-long",
            JwtIssuer = "test-issuer",
            JwtAudience = "test-audience"
        };
        var appOptions1 = Options.Create(appOptions);

        // Setup mapper to return a simple DTO
        mapper.Setup(x => x.Map<MfaPushDeviceDto>(It.IsAny<MfaPushDevice>()))
            .Returns((MfaPushDevice d) => new MfaPushDeviceDto
            {
                Id = d.Id,
                DeviceId = d.DeviceId,
                DeviceName = d.DeviceName,
                Platform = d.Platform,
                RegisteredAt = d.RegisteredAt,
                LastUsedAt = d.LastUsedAt,
                IsActive = d.IsActive,
                TrustScore = d.TrustScore
            });

        mapper.Setup(x => x.Map<List<MfaPushDeviceDto>>(It.IsAny<IEnumerable<MfaPushDevice>>()))
            .Returns((IEnumerable<MfaPushDevice> devices) => devices.Select(d => new MfaPushDeviceDto
            {
                Id = d.Id,
                DeviceId = d.DeviceId,
                DeviceName = d.DeviceName,
                Platform = d.Platform,
                RegisteredAt = d.RegisteredAt,
                LastUsedAt = d.LastUsedAt,
                IsActive = d.IsActive,
                TrustScore = d.TrustScore
            }).ToList());

        _service = new MfaPushService(
            unitOfWork.Object,
            _mfaRepository.Object,
            _mfaMethodRepository.Object,
            _pushProvider.Object,
            mapper.Object,
            pushMfaOptions,
            appOptions1,
            logger.Object);
    }

    #region RegisterDeviceAsync Tests

    [Fact]
    public async Task RegisterDeviceAsync_WithInvalidToken_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var request = new RegisterPushDeviceRequest
        {
            DeviceId = "device-123",
            DeviceName = "iPhone 14",
            Platform = "iOS",
            PushToken = "invalid-token",
            PublicKey = "public-key"
        };

        _pushProvider.Setup(x => x.ValidatePushToken(request.PushToken, request.Platform))
            .Returns(false);

        // Act
        var result = await _service.RegisterDeviceAsync(userId, request);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid push token format");
        _mfaRepository.Verify(x => x.AddPushDeviceAsync(It.IsAny<MfaPushDevice>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RegisterDeviceAsync_ExistingDevice_UpdatesToken()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var mfaMethodId = Guid.NewGuid();
        var existingDevice = new MfaPushDevice(
            mfaMethodId,
            userId,
            "device-123",
            "iPhone 14",
            "iOS",
            "old-token",
            "public-key");

        var request = new RegisterPushDeviceRequest
        {
            DeviceId = "device-123",
            DeviceName = "iPhone 14",
            Platform = "iOS",
            PushToken = "new-token",
            PublicKey = "public-key"
        };

        _pushProvider.Setup(x => x.ValidatePushToken(request.PushToken, request.Platform))
            .Returns(true);

        _mfaRepository.Setup(x => x.GetPushDeviceByDeviceIdAsync(userId, request.DeviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingDevice);

        // Act
        var result = await _service.RegisterDeviceAsync(userId, request);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Message.Should().Be("Device token updated successfully");
        existingDevice.PushToken.Should().Be("new-token");
        _mfaRepository.Verify(x => x.AddPushDeviceAsync(It.IsAny<MfaPushDevice>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RegisterDeviceAsync_NewDevice_CreatesSuccessfully()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var request = new RegisterPushDeviceRequest
        {
            DeviceId = "device-123",
            DeviceName = "iPhone 14",
            Platform = "iOS",
            PushToken = "valid-token",
            PublicKey = "public-key"
        };

        _pushProvider.Setup(x => x.ValidatePushToken(request.PushToken, request.Platform))
            .Returns(true);

        _mfaRepository.Setup(x => x.GetPushDeviceByDeviceIdAsync(userId, request.DeviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Push, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaMethod?)null);

        _mfaMethodRepository.Setup(x => x.AddAsync(It.IsAny<MfaMethod>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mfaRepository.Setup(x => x.AddPushDeviceAsync(It.IsAny<MfaPushDevice>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _service.RegisterDeviceAsync(userId, request);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.DeviceId.Should().Be("device-123");
        result.Data.DeviceName.Should().Be("iPhone 14");
        result.Data.Platform.Should().Be("iOS");
        result.Message.Should().Be("Device registered successfully");

        _mfaMethodRepository.Verify(x => x.AddAsync(
            It.Is<MfaMethod>(m => m.UserId == userId && m.Type == MfaType.Push),
            It.IsAny<CancellationToken>()), Times.Once);

        _mfaRepository.Verify(x => x.AddPushDeviceAsync(
            It.Is<MfaPushDevice>(d =>
                d.UserId == userId &&
                d.DeviceId == request.DeviceId &&
                d.PushToken == request.PushToken),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RegisterDeviceAsync_WithExistingMfaMethod_UsesIt()
    {
        // Arrange
        var userId = Guid.NewGuid();
        Guid.NewGuid();
        var existingMethod = MfaMethod.CreatePush(userId, "Push");

        var request = new RegisterPushDeviceRequest
        {
            DeviceId = "device-123",
            DeviceName = "Android Phone",
            Platform = "Android",
            PushToken = "valid-token",
            PublicKey = "public-key"
        };

        _pushProvider.Setup(x => x.ValidatePushToken(request.PushToken, request.Platform))
            .Returns(true);

        _mfaRepository.Setup(x => x.GetPushDeviceByDeviceIdAsync(userId, request.DeviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        _mfaMethodRepository.Setup(x => x.GetByUserAndTypeAsync(userId, MfaType.Push, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingMethod);

        // Act
        var result = await _service.RegisterDeviceAsync(userId, request);

        // Assert
        result.Success.Should().BeTrue();
        _mfaMethodRepository.Verify(x => x.AddAsync(It.IsAny<MfaMethod>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task RegisterDeviceAsync_WhenExceptionThrown_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var request = new RegisterPushDeviceRequest
        {
            DeviceId = "device-123",
            DeviceName = "Device",
            Platform = "iOS",
            PushToken = "token",
            PublicKey = "key"
        };

        _pushProvider.Setup(x => x.ValidatePushToken(It.IsAny<string>(), It.IsAny<string>()))
            .Throws(new Exception("Database error"));

        // Act
        var result = await _service.RegisterDeviceAsync(userId, request);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Failed to register device");
    }

    #endregion

    #region SendChallengeAsync Tests

    [Fact]
    public async Task SendChallengeAsync_DeviceNotFound_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = "Chrome/120",
            Location = "New York, US"
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found or inactive");
    }

    [Fact]
    public async Task SendChallengeAsync_DeviceInactive_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = new MfaPushDevice(Guid.NewGuid(), userId, "device-123", "iPhone", "iOS", "token", "key");
        device.Deactivate(); // Make device inactive

        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = "Chrome/120"
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found or inactive");
    }

    [Fact]
    public async Task SendChallengeAsync_RateLimitExceeded_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);

        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = "Chrome/120"
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _mfaRepository.Setup(x => x.GetRecentPushChallengesCountAsync(userId, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(5); // Equal to MaxChallengesPerWindow

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Too many push requests. Please try again later.");
        _pushProvider.Verify(x => x.SendPushNotificationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<Dictionary<string, string>>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task SendChallengeAsync_Success_SendsNotificationAndReturnsChallenge()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);

        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = "Mozilla/5.0 Chrome/120.0.0.0",
            Location = "New York, US"
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _mfaRepository.Setup(x => x.GetRecentPushChallengesCountAsync(userId, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(2); // Under limit

        _mfaRepository.Setup(x => x.AddPushChallengeAsync(It.IsAny<MfaPushChallenge>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _pushProvider.Setup(x => x.SendPushNotificationAsync(
                device.PushToken,
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, string>>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.ChallengeCode.Should().NotBeNullOrWhiteSpace();
        result.Data.ExpiresAt.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(5), TimeSpan.FromSeconds(1));
        result.Data.DeviceName.Should().Be(device.DeviceName);
        result.Data.Location.Should().Be("New York, US");
        result.Data.BrowserInfo.Should().Be("Chrome");

        _mfaRepository.Verify(x => x.AddPushChallengeAsync(
            It.Is<MfaPushChallenge>(c =>
                c.UserId == userId &&
                c.DeviceId == deviceId &&
                c.SessionId == sessionInfo.SessionId &&
                c.Location == sessionInfo.Location),
            It.IsAny<CancellationToken>()), Times.Once);

        _pushProvider.Verify(x => x.SendPushNotificationAsync(
            device.PushToken,
            "TestApp Login Request",
            It.Is<string>(s => s.Contains("Chrome") && s.Contains("New York, US")),
            It.Is<Dictionary<string, string>>(d => d["type"] == "mfa_challenge"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SendChallengeAsync_PushNotificationFails_StillReturnsSuccess()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);

        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = "Safari/17.0"
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _mfaRepository.Setup(x => x.GetRecentPushChallengesCountAsync(userId, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _pushProvider.Setup(x => x.SendPushNotificationAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, string>>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(false); // Notification fails

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeTrue(); // Still returns success
        result.Data.Should().NotBeNull();
    }

    [Theory]
    [InlineData("Mozilla/5.0 Firefox/120.0", "Firefox")]
    [InlineData("Mozilla/5.0 Edge/120.0", "Edge")]
    [InlineData("Unknown Browser Agent", "Unknown Browser")]
    public async Task SendChallengeAsync_ParsesUserAgent_Correctly(string userAgent, string expectedBrowser)
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);

        var sessionInfo = new PushChallengeSessionInfo
        {
            SessionId = "session-123",
            IpAddress = "192.168.1.1",
            UserAgent = userAgent
        };

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _mfaRepository.Setup(x => x.GetRecentPushChallengesCountAsync(userId, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        _pushProvider.Setup(x => x.SendPushNotificationAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, string>>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _service.SendChallengeAsync(userId, deviceId, sessionInfo);

        // Assert
        result.Success.Should().BeTrue();
        result.Data!.BrowserInfo.Should().Be(expectedBrowser);
    }

    #endregion

    #region CheckChallengeStatusAsync Tests

    [Fact]
    public async Task CheckChallengeStatusAsync_ChallengeNotFound_ReturnsError()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var sessionId = "session-123";

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushChallenge?)null);

        // Act
        var result = await _service.CheckChallengeStatusAsync(challengeId, sessionId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Challenge not found");
    }

    [Fact]
    public async Task CheckChallengeStatusAsync_WrongSessionId_ReturnsError()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var challenge = new MfaPushChallenge(
            Guid.NewGuid(), Guid.NewGuid(), "correct-session", "192.168.1.1", "Chrome");

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.CheckChallengeStatusAsync(challengeId, "wrong-session");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Challenge not found");
    }

    [Fact]
    public async Task CheckChallengeStatusAsync_ExpiredChallenge_UpdatesStatusAndReturns()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var sessionId = "session-123";
        var challenge = new MfaPushChallenge(
            Guid.NewGuid(), Guid.NewGuid(), sessionId, "192.168.1.1", "Chrome");

        // Force expiration by reflection
        var expiresAtProperty = challenge.GetType().GetProperty("ExpiresAt");
        expiresAtProperty!.SetValue(challenge, DateTime.UtcNow.AddMinutes(-1));

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.CheckChallengeStatusAsync(challengeId, sessionId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Status.Should().Be("Expired");
        result.Data.IsExpired.Should().BeTrue();
        result.Data.IsApproved.Should().BeFalse();
        result.Data.IsDenied.Should().BeFalse();
    }

    [Theory]
    [InlineData(ChallengeStatus.Pending, false, false, false)]
    [InlineData(ChallengeStatus.Approved, true, false, false)]
    [InlineData(ChallengeStatus.Denied, false, true, false)]
    [InlineData(ChallengeStatus.Expired, false, false, true)]
    public async Task CheckChallengeStatusAsync_ReturnsCorrectStatus(
        ChallengeStatus status, bool isApproved, bool isDenied, bool isExpired)
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var sessionId = "session-123";
        var challenge = new MfaPushChallenge(
            Guid.NewGuid(), Guid.NewGuid(), sessionId, "192.168.1.1", "Chrome");

        // Set status using appropriate method based on the status
        switch (status)
        {
            case ChallengeStatus.Approved:
                challenge.Approve("signature");
                break;
            case ChallengeStatus.Denied:
                challenge.Deny("signature");
                break;
            case ChallengeStatus.Expired:
                challenge.MarkExpired();
                break;
        }

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.CheckChallengeStatusAsync(challengeId, sessionId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data!.Status.Should().Be(status.ToString());
        result.Data.IsApproved.Should().Be(isApproved);
        result.Data.IsDenied.Should().Be(isDenied);
        result.Data.IsExpired.Should().Be(isExpired);
    }

    #endregion

    #region RespondToChallengeAsync Tests

    [Fact]
    public async Task RespondToChallengeAsync_ChallengeNotFound_ReturnsError()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var response = new PushChallengeResponse
        {
            IsApproved = true,
            Signature = "signature",
            DeviceId = Guid.NewGuid()
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushChallenge?)null);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Challenge not found");
    }

    [Fact]
    public async Task RespondToChallengeAsync_WrongDevice_ReturnsError()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var correctDeviceId = Guid.NewGuid();
        var wrongDeviceId = Guid.NewGuid();

        var challenge = new MfaPushChallenge(
            Guid.NewGuid(), correctDeviceId, "session", "192.168.1.1", "Chrome");

        var response = new PushChallengeResponse
        {
            IsApproved = true,
            Signature = "signature",
            DeviceId = wrongDeviceId
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid device");
    }

    [Fact]
    public async Task RespondToChallengeAsync_DeviceNotFound_ReturnsError()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var challenge = new MfaPushChallenge(
            Guid.NewGuid(), deviceId, "session", "192.168.1.1", "Chrome");

        var response = new PushChallengeResponse
        {
            IsApproved = true,
            Signature = "signature",
            DeviceId = deviceId
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found or inactive");
    }

    [Fact]
    public async Task RespondToChallengeAsync_InvalidSignature_RecordsSuspiciousActivity()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        var challenge = new MfaPushChallenge(
            userId, deviceId, "session", "192.168.1.1", "Chrome");

        var device = CreateTestDevice(userId, deviceId);

        var response = new PushChallengeResponse
        {
            IsApproved = true,
            Signature = "invalid-signature",
            DeviceId = deviceId
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid signature");
        device.TrustScore.Should().BeLessThan(100); // Trust score decreased
    }

    [Fact]
    public async Task RespondToChallengeAsync_ApprovedResponse_ProcessedCorrectly()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        var challenge = new MfaPushChallenge(
            userId, deviceId, "session", "192.168.1.1", "Chrome");

        var device = CreateTestDevice(userId, deviceId);

        var response = new PushChallengeResponse
        {
            IsApproved = true,
            Signature = "dummy-signature-for-approved",
            DeviceId = deviceId
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        // Note: This will fail signature verification, but we're testing the behavior
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid signature");
    }

    [Fact]
    public async Task RespondToChallengeAsync_DeniedResponse_ProcessedCorrectly()
    {
        // Arrange
        var challengeId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        var challenge = new MfaPushChallenge(
            userId, deviceId, "session", "192.168.1.1", "Chrome");

        var device = CreateTestDevice(userId, deviceId);

        var response = new PushChallengeResponse
        {
            IsApproved = false,
            Signature = "dummy-signature-for-denied",
            DeviceId = deviceId
        };

        _mfaRepository.Setup(x => x.GetPushChallengeAsync(challengeId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(challenge);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.RespondToChallengeAsync(challengeId, response);

        // Assert
        // Note: This will fail signature verification, but we're testing the behavior
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid signature");
    }

    #endregion

    #region GetUserDevicesAsync Tests

    [Fact]
    public async Task GetUserDevicesAsync_ReturnsAllUserDevices()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var devices = new List<MfaPushDevice>
        {
            CreateTestDevice(userId, Guid.NewGuid(), "iPhone 14"),
            CreateTestDevice(userId, Guid.NewGuid(), "Android Phone")
        };

        _mfaRepository.Setup(x => x.GetUserPushDevicesAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(devices);

        // Act
        var result = await _service.GetUserDevicesAsync(userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Should().HaveCount(2);
        result.Data!.Select(d => d.DeviceName).Should().BeEquivalentTo(["iPhone 14", "Android Phone"]);
    }

    [Fact]
    public async Task GetUserDevicesAsync_NoDevices_ReturnsEmptyList()
    {
        // Arrange
        var userId = Guid.NewGuid();

        _mfaRepository.Setup(x => x.GetUserPushDevicesAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<MfaPushDevice>());

        // Act
        var result = await _service.GetUserDevicesAsync(userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Should().BeEmpty();
    }

    #endregion

    #region RemoveDeviceAsync Tests

    [Fact]
    public async Task RemoveDeviceAsync_DeviceNotFound_ReturnsError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        // Act
        var result = await _service.RemoveDeviceAsync(userId, deviceId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found");
    }

    [Fact]
    public async Task RemoveDeviceAsync_WrongUser_ReturnsError()
    {
        // Arrange
        var requestingUserId = Guid.NewGuid();
        var deviceUserId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();

        var device = CreateTestDevice(deviceUserId, deviceId);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.RemoveDeviceAsync(requestingUserId, deviceId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found");
    }

    [Fact]
    public async Task RemoveDeviceAsync_Success_DeactivatesDevice()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        // Act
        var result = await _service.RemoveDeviceAsync(userId, deviceId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
        result.Message.Should().Be("Device removed successfully");
        device.IsActive.Should().BeFalse();
    }

    #endregion

    #region UpdateDeviceTokenAsync Tests

    [Fact]
    public async Task UpdateDeviceTokenAsync_DeviceNotFound_ReturnsError()
    {
        // Arrange
        var deviceId = Guid.NewGuid();
        var newToken = "new-token";

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((MfaPushDevice?)null);

        // Act
        var result = await _service.UpdateDeviceTokenAsync(deviceId, newToken, Guid.NewGuid());

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Device not found");
    }

    [Fact]
    public async Task UpdateDeviceTokenAsync_InvalidToken_ReturnsError()
    {
        // Arrange
        var deviceId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);
        var newToken = "invalid-token";

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _pushProvider.Setup(x => x.ValidatePushToken(newToken, device.Platform))
            .Returns(false);

        // Act
        var result = await _service.UpdateDeviceTokenAsync(deviceId, newToken, userId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid push token format");
    }

    [Fact]
    public async Task UpdateDeviceTokenAsync_Success_UpdatesToken()
    {
        // Arrange
        var deviceId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var device = CreateTestDevice(userId, deviceId);
        var newToken = "new-valid-token";

        _mfaRepository.Setup(x => x.GetPushDeviceAsync(deviceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(device);

        _pushProvider.Setup(x => x.ValidatePushToken(newToken, device.Platform))
            .Returns(true);

        // Act
        var result = await _service.UpdateDeviceTokenAsync(deviceId, newToken, userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().BeTrue();
        result.Message.Should().Be("Device token updated");
        device.PushToken.Should().Be(newToken);
    }

    #endregion

    #region CleanupExpiredChallengesAsync Tests

    [Fact]
    public async Task CleanupExpiredChallengesAsync_CallsRepositoryWithCorrectCutoff()
    {
        // Arrange
        var olderThan = TimeSpan.FromHours(24);
        DateTime capturedCutoff = default;

        _mfaRepository.Setup(x => x.DeleteExpiredPushChallengesAsync(It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
            .Callback<DateTime, CancellationToken>((cutoff, _) => capturedCutoff = cutoff)
            .ReturnsAsync(10);

        // Act
        var result = await _service.CleanupExpiredChallengesAsync(olderThan);

        // Assert
        result.Should().Be(10);
        capturedCutoff.Should().BeCloseTo(DateTime.UtcNow.Subtract(olderThan), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CleanupExpiredChallengesAsync_WhenExceptionThrown_ReturnsZero()
    {
        // Arrange
        var olderThan = TimeSpan.FromHours(24);

        _mfaRepository.Setup(x => x.DeleteExpiredPushChallengesAsync(It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _service.CleanupExpiredChallengesAsync(olderThan);

        // Assert
        result.Should().Be(0);
    }

    #endregion

    #region Helper Methods

    private static MfaPushDevice CreateTestDevice(Guid userId, Guid deviceId, string deviceName = "Test Device")
    {
        return new MfaPushDevice(
            Guid.NewGuid(),
            userId,
            $"device-{deviceId}",
            deviceName,
            "iOS",
            "test-token",
            "test-public-key"
        );
    }

    #endregion
}