using Application.DTOs.Mfa;
using Application.Validators;
using FluentValidation.TestHelper;
using Xunit;

namespace Application.Tests.ValidatorTests;

public class SendPushChallengeValidatorTests
{
    private readonly SendPushChallengeValidator _validator = new();

    [Fact]
    public void Should_Have_Error_When_DeviceId_Is_Empty()
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.Empty,
            SessionId = "valid-session-123"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.DeviceId)
            .WithErrorMessage("Device ID cannot be empty GUID");
    }

    [Fact]
    public void Should_Not_Have_Error_When_DeviceId_Is_Valid()
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = "valid-session-123"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.DeviceId);
    }

    [Theory]
    [InlineData("")]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    [InlineData("   ")]
    public void Should_Have_Error_When_SessionId_Is_Empty_Or_Whitespace(string? sessionId)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
#pragma warning disable CS8601
            SessionId = sessionId
#pragma warning restore CS8601
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.SessionId)
            .WithErrorMessage("Session ID is required");
    }

    [Theory]
    [InlineData("short")]     // 5 characters - too short
    [InlineData("123456789")] // 9 characters - too short
    public void Should_Have_Error_When_SessionId_Is_Too_Short(string sessionId)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = sessionId
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.SessionId)
            .WithErrorMessage("Session ID must be between 10 and 128 characters");
    }

    [Fact]
    public void Should_Have_Error_When_SessionId_Is_Too_Long()
    {
        // Arrange
        var longSessionId = new string('a', 129); // 129 characters - too long
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = longSessionId
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.SessionId)
            .WithErrorMessage("Session ID must be between 10 and 128 characters");
    }

    [Theory]
    [InlineData("session@#$%")]    // Contains special characters
    [InlineData("session space")] // Contains space
    [InlineData("session.dot")]   // Contains dot
    [InlineData("session+plus")]  // Contains plus
    public void Should_Have_Error_When_SessionId_Contains_Invalid_Characters(string sessionId)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = sessionId
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.SessionId)
            .WithErrorMessage("Session ID format is invalid");
    }

    [Theory]
    [InlineData("session-123")]      // Valid with hyphen
    [InlineData("session_456")]      // Valid with underscore
    [InlineData("sessionABC123")]    // Valid alphanumeric
    [InlineData("1234567890")]       // Valid numbers only
    [InlineData("abcdefghij")]       // Valid letters only
    [InlineData("session-id_123")]   // Valid mixed
    public void Should_Not_Have_Error_When_SessionId_Is_Valid(string sessionId)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = sessionId
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.SessionId);
    }

    [Theory]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    [InlineData("")]
    [InlineData("New York")]
    [InlineData("San Francisco, CA")]
    public void Should_Not_Have_Error_When_Location_Is_Valid_Or_Empty(string? location)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = "valid-session-123",
#pragma warning disable CS8601
            Location = location
#pragma warning restore CS8601
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.Location);
    }

    [Fact]
    public void Should_Have_Error_When_Location_Is_Too_Long()
    {
        // Arrange
        var longLocation = new string('a', 101); // 101 characters - too long
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = "valid-session-123",
            Location = longLocation
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Location)
            .WithErrorMessage("Location must not exceed 100 characters");
    }

    [Theory]
    [InlineData("Location<script>")]  // Contains <
    [InlineData("Location>Test")]     // Contains >
    [InlineData("Test\"Location")]    // Contains "
    [InlineData("Location'Test")]     // Contains '
    [InlineData("Test&Location")]     // Contains &
    [InlineData("Location\nTest")]    // Contains newline
    public void Should_Have_Error_When_Location_Contains_Invalid_Characters(string location)
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = "valid-session-123",
            Location = location
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Location)
            .WithErrorMessage("Location contains invalid characters");
    }

    [Fact]
    public void Should_Pass_Validation_When_All_Fields_Are_Valid()
    {
        // Arrange
        var dto = new SendPushChallengeDto
        {
            DeviceId = Guid.NewGuid(),
            SessionId = "valid-session-123",
            Location = "New York, NY"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }
}
