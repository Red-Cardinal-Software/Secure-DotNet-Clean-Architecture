using Application.DTOs.Mfa.EmailMfa;
using Application.Validators;
using FluentValidation.TestHelper;
using Xunit;

namespace Application.Tests.ValidatorTests;

public class VerifyEmailCodeValidatorTests
{
    private readonly VerifyEmailCodeValidator _validator = new();

    [Fact]
    public void Should_Have_Error_When_ChallengeId_Is_Empty()
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.Empty,
            Code = "12345678"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.ChallengeId)
            .WithErrorMessage("Challenge ID cannot be empty GUID");
    }

    [Fact]
    public void Should_Not_Have_Error_When_ChallengeId_Is_Valid()
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = "12345678"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.ChallengeId);
    }

    [Theory]
    [InlineData("")]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    [InlineData("   ")]
    public void Should_Have_Error_When_Code_Is_Empty_Or_Whitespace(string? code)
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
#pragma warning disable CS8601
            Code = code
#pragma warning restore CS8601
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Code)
            .WithErrorMessage("Verification code is required");
    }

    [Theory]
    [InlineData("1234567")]   // 7 digits - too short
    [InlineData("123456789")] // 9 digits - too long
    public void Should_Have_Error_When_Code_Length_Is_Invalid(string code)
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = code
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Code)
            .WithErrorMessage("Verification code must be exactly 8 characters");
    }

    [Theory]
    [InlineData("1234567a")]  // Contains letter
    [InlineData("123 5678")]  // Contains space
    [InlineData("1234-678")]  // Contains hyphen
    [InlineData("123456.8")]  // Contains dot
    public void Should_Have_Error_When_Code_Contains_Non_Digits(string code)
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = code
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Code)
            .WithErrorMessage("Verification code must contain only 8 digits");
    }

    [Theory]
    [InlineData("00000000")]  // All zeros
    [InlineData("11111111")]  // All ones
    [InlineData("22222222")]  // All twos
    [InlineData("99999999")]  // All nines
    public void Should_Have_Error_When_Code_Is_All_Same_Digits(string code)
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = code
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Code)
            .WithErrorMessage("Invalid verification code format");
    }

    [Theory]
    [InlineData("12345678")]  // Mixed digits
    [InlineData("87654321")]  // Reverse order
    [InlineData("13579246")]  // Random valid pattern
    [InlineData("24681357")]  // Another valid pattern
    public void Should_Not_Have_Error_When_Code_Is_Valid(string code)
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = code
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.Code);
    }

    [Fact]
    public void Should_Pass_Validation_When_All_Fields_Are_Valid()
    {
        // Arrange
        var dto = new VerifyEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            Code = "12345678"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }
}
