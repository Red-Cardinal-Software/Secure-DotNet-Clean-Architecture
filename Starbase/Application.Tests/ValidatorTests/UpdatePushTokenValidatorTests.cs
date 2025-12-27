using Application.DTOs.Mfa;
using Application.Validators;
using FluentValidation.TestHelper;
using Xunit;

namespace Application.Tests.ValidatorTests;

public class UpdatePushTokenValidatorTests
{
    private readonly UpdatePushTokenValidator _validator = new();

    [Theory]
    [InlineData("")]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    [InlineData("   ")]
    public void Should_Have_Error_When_NewToken_Is_Empty_Or_Whitespace(string? token)
    {
        // Arrange
#pragma warning disable CS8601
        var dto = new UpdatePushTokenDto { NewToken = token };
#pragma warning restore CS8601

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.NewToken)
            .WithErrorMessage("Push token is required");
    }

    [Theory]
    [InlineData("short")]     // 5 characters - too short
    [InlineData("123456789")] // 9 characters - too short
    public void Should_Have_Error_When_NewToken_Is_Too_Short(string token)
    {
        // Arrange
        var dto = new UpdatePushTokenDto { NewToken = token };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.NewToken)
            .WithErrorMessage("Push token must be between 10 and 4000 characters");
    }

    [Fact]
    public void Should_Have_Error_When_NewToken_Is_Too_Long()
    {
        // Arrange
        var longToken = new string('a', 4001); // 4001 characters - too long
        var dto = new UpdatePushTokenDto { NewToken = longToken };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.NewToken)
            .WithErrorMessage("Push token must be between 10 and 4000 characters");
    }

    [Theory]
    [InlineData("token@#$%")]     // Contains @ # $ %
    [InlineData("token space")]   // Contains space
    [InlineData("token+plus")]    // Contains plus
    [InlineData("token/slash")]   // Contains slash
    [InlineData("token=equals")]  // Contains equals
    public void Should_Have_Error_When_NewToken_Contains_Invalid_Characters(string token)
    {
        // Arrange
        var dto = new UpdatePushTokenDto { NewToken = token };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.NewToken)
            .WithErrorMessage("Push token format is invalid");
    }

    [Theory]
    [InlineData("passwordToken123")]     // Contains "password"
    [InlineData("MySecretToken")]        // Contains "secret"
    [InlineData("APIKeyToken")]          // Contains "key"
    [InlineData("PrivateTokenData")]     // Contains "private"
    [InlineData("CredentialToken")]      // Contains "credential"
    [InlineData("BearerToken123")]       // Contains "bearer"
    [InlineData("AuthorizationToken")]   // Contains "authorization"
    [InlineData("SessionToken")]         // Contains "session"
    [InlineData("CookieToken")]          // Contains "cookie"
    [InlineData("JWTToken123")]          // Contains "jwt"
    [InlineData("token=bearer")]         // Contains "token="
    public void Should_Have_Error_When_NewToken_Contains_Sensitive_Patterns(string token)
    {
        // Arrange
        var dto = new UpdatePushTokenDto { NewToken = token };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.NewToken)
            .WithErrorMessage("Push token appears to contain sensitive information");
    }

    [Theory]
    [InlineData("abcdefghij")]                    // Valid letters only
    [InlineData("1234567890")]                    // Valid numbers only  
    [InlineData("ABC123DEF456")]                  // Valid mixed case
    [InlineData("token-with-hyphens")]            // Valid with hyphens
    [InlineData("token_with_underscores")]        // Valid with underscores
    [InlineData("token.with.dots")]               // Valid with dots
    [InlineData("token:with:colons")]             // Valid with colons
    [InlineData("validPushNotificationToken123")] // Realistic token
    public void Should_Not_Have_Error_When_NewToken_Is_Valid(string token)
    {
        // Arrange
        var dto = new UpdatePushTokenDto { NewToken = token };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.NewToken);
    }

    [Fact]
    public void Should_Pass_Validation_When_Token_Is_Exactly_Minimum_Length()
    {
        // Arrange
        var minToken = "abcdefghij"; // Exactly 10 characters
        var dto = new UpdatePushTokenDto { NewToken = minToken };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Should_Pass_Validation_When_Token_Is_Exactly_Maximum_Length()
    {
        // Arrange
        var maxToken = new string('a', 4000); // Exactly 4000 characters
        var dto = new UpdatePushTokenDto { NewToken = maxToken };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Should_Pass_Validation_When_Token_Is_Realistic_Firebase_Token()
    {
        // Arrange
        var firebaseToken = "fGcI8vZ2QR-K7yE4mNpXjL:APA91bHsG8vZ2QR-K7yE4mNpXjL9sK1mZ3vY7bE5nD2wR8qF4tH6uI0pL1mN3vY7bE5nD2wR8qF4tH6uI0pL";
        var dto = new UpdatePushTokenDto { NewToken = firebaseToken };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Should_Pass_Validation_When_All_Rules_Are_Satisfied()
    {
        // Arrange
        var dto = new UpdatePushTokenDto { NewToken = "validPushNotificationToken12345" };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }
}
