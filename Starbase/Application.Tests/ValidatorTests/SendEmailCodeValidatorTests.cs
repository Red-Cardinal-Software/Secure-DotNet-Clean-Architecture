using Application.DTOs.Mfa.EmailMfa;
using Application.Validators;
using FluentValidation.TestHelper;
using Xunit;

namespace Application.Tests.ValidatorTests;

public class SendEmailCodeValidatorTests
{
    private readonly SendEmailCodeValidator _validator = new();

    [Fact]
    public void Should_Have_Error_When_ChallengeId_Is_Empty()
    {
        // Arrange
        var dto = new SendEmailCodeDto { ChallengeId = Guid.Empty };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.ChallengeId)
            .WithErrorMessage("Challenge ID cannot be empty GUID");
    }

    [Fact]
    public void Should_Have_Error_When_ChallengeId_Is_Default_Guid()
    {
        // Arrange
        var dto = new SendEmailCodeDto { ChallengeId = default };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.ChallengeId)
            .WithErrorMessage("Challenge ID is required");
    }

    [Fact]
    public void Should_Not_Have_Error_When_ChallengeId_Is_Valid()
    {
        // Arrange
        var dto = new SendEmailCodeDto { ChallengeId = Guid.NewGuid() };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.ChallengeId);
    }

    [Theory]
    [InlineData("")]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    public void Should_Not_Have_Error_When_EmailAddress_Is_Null_Or_Empty(string? emailAddress)
    {
        // Arrange
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
#pragma warning disable CS8601
            EmailAddress = emailAddress
#pragma warning restore CS8601
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.EmailAddress);
    }

    [Fact]
    public void Should_Have_Error_When_EmailAddress_Is_Invalid_Format()
    {
        // Arrange
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            EmailAddress = "invalid-email"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.EmailAddress)
            .WithErrorMessage("Invalid email address format");
    }

    [Fact]
    public void Should_Have_Error_When_EmailAddress_Is_Too_Short()
    {
        // Arrange
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            EmailAddress = "a@b" // 3 characters, below minimum 5
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.EmailAddress)
            .WithErrorMessage("Email address must be between 5 and 254 characters");
    }

    [Fact]
    public void Should_Have_Error_When_EmailAddress_Is_Too_Long()
    {
        // Arrange
        var longEmail = new string('a', 250) + "@test.com"; // Over 254 characters
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            EmailAddress = longEmail
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.EmailAddress)
            .WithErrorMessage("Email address must be between 5 and 254 characters");
    }

    [Theory]
    [InlineData("test@example.com")]
    [InlineData("user.name@domain.co.uk")]
    [InlineData("a@b.co")]
    public void Should_Not_Have_Error_When_EmailAddress_Is_Valid(string emailAddress)
    {
        // Arrange
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            EmailAddress = emailAddress
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.EmailAddress);
    }

    [Fact]
    public void Should_Pass_Validation_When_All_Fields_Are_Valid()
    {
        // Arrange
        var dto = new SendEmailCodeDto
        {
            ChallengeId = Guid.NewGuid(),
            EmailAddress = "test@example.com"
        };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }
}
