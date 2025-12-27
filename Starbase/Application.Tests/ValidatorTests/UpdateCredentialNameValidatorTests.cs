using Application.DTOs.Mfa.WebAuthn;
using Application.Validators;
using FluentValidation.TestHelper;
using Xunit;

namespace Application.Tests.ValidatorTests;

public class UpdateCredentialNameValidatorTests
{
    private readonly UpdateCredentialNameValidator _validator = new();

    [Theory]
    [InlineData("")]
#pragma warning disable xUnit1012
    [InlineData(null)]
#pragma warning restore xUnit1012
    [InlineData("   ")]
    [InlineData("\t")]
    public void Should_Have_Error_When_Name_Is_Empty_Or_Whitespace(string? name)
    {
        // Arrange
#pragma warning disable CS8601
        var dto = new UpdateCredentialNameDto { Name = name };
#pragma warning restore CS8601

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Name);
    }

    [Fact]
    public void Should_Have_Error_When_Name_Is_Too_Long()
    {
        // Arrange
        var longName = new string('a', 101); // 101 characters, over limit
        var dto = new UpdateCredentialNameDto { Name = longName };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Name)
            .WithErrorMessage("Credential name must be between 1 and 100 characters");
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("ADMIN")]
    [InlineData("Administrator")]
    [InlineData("system")]
    [InlineData("test")]
    [InlineData("default")]
    [InlineData("password")]
    [InlineData("secret")]
    [InlineData("key")]
    [InlineData("token")]
    [InlineData("credential")]
    public void Should_Have_Error_When_Name_Is_Forbidden(string name)
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = name };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Name)
            .WithErrorMessage("Credential name is not allowed");
    }

    [Theory]
    [InlineData("My<script>")]     // Contains <
    [InlineData("Name>Test")]      // Contains >
    [InlineData("Test\"Name")]     // Contains "
    [InlineData("Name'Test")]      // Contains '
    [InlineData("Test&Name")]      // Contains &
    [InlineData("Name\0Test")]     // Contains null character
    [InlineData("Test\rName")]     // Contains carriage return
    [InlineData("Name\nTest")]     // Contains newline
    [InlineData("Test\tName")]     // Contains tab
    public void Should_Have_Error_When_Name_Contains_Invalid_Characters(string name)
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = name };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Name)
            .WithErrorMessage("Credential name contains invalid characters");
    }

    [Fact]
    public void Should_Have_Error_When_Name_Is_Only_Whitespace_After_Trim()
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = "   \t   " };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldHaveValidationErrorFor(x => x.Name)
            .WithErrorMessage("Credential name cannot contain only whitespace");
    }

    [Theory]
    [InlineData("My Phone")]
    [InlineData("Laptop Authenticator")]
    [InlineData("Work Device")]
    [InlineData("Personal Key")]
    [InlineData("iPhone 15")]
    [InlineData("a")]                    // Minimum length
    [InlineData("iPhone Security Key")] // Normal case
    public void Should_Not_Have_Error_When_Name_Is_Valid(string name)
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = name };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.Name);
    }

    [Fact]
    public void Should_Pass_Validation_When_Name_Is_Exactly_100_Characters()
    {
        // Arrange
        var exactLength = new string('a', 100); // Exactly 100 characters
        var dto = new UpdateCredentialNameDto { Name = exactLength };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void Should_Allow_Numbers_And_Special_Safe_Characters()
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = "Device-123_v2.0 (Main)" };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveValidationErrorFor(x => x.Name);
    }

    [Fact]
    public void Should_Pass_Validation_When_All_Rules_Are_Satisfied()
    {
        // Arrange
        var dto = new UpdateCredentialNameDto { Name = "My Secure Device" };

        // Act & Assert
        var result = _validator.TestValidate(dto);
        result.ShouldNotHaveAnyValidationErrors();
    }
}
