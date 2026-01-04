using Domain.Entities.Configuration;
using FluentAssertions;
using Xunit;

namespace Domain.Tests.Entities;

public class EmailTemplateTests
{
    [Fact]
    public void Constructor_WithValidInputs_ShouldSetProperties()
    {
        // Arrange
        var key = "welcome_email";
        var subject = "Welcome!";
        var htmlBody = "<p>Thanks for joining us!</p>";

        // Act
        var template = new EmailTemplate(key, subject, htmlBody);

        // Assert
        template.Key.Should().Be(key);
        template.Subject.Should().Be(subject);
        template.HtmlBody.Should().Be(htmlBody);
        template.IsActive.Should().BeTrue();
        template.OrganizationId.Should().BeNull();
        template.Id.Should().NotBeEmpty();
    }

    [Fact]
    public void Constructor_WithOrganizationId_ShouldSetOrganization()
    {
        // Arrange
        var organizationId = Guid.NewGuid();

        // Act
        var template = new EmailTemplate("key", "subject", "body", organizationId);

        // Assert
        template.OrganizationId.Should().Be(organizationId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_WithInvalidKey_ShouldThrow(string? invalidKey)
    {
        // Act
        var act = () => new EmailTemplate(invalidKey!, "subject", "body");

        // Assert
        act.Should().Throw<ArgumentNullException>().WithMessage("*key*");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_WithInvalidSubject_ShouldThrow(string? invalidSubject)
    {
        // Act
        var act = () => new EmailTemplate("key", invalidSubject!, "body");

        // Assert
        act.Should().Throw<ArgumentNullException>().WithMessage("*subject*");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_WithInvalidHtmlBody_ShouldThrow(string? invalidBody)
    {
        // Act
        var act = () => new EmailTemplate("key", "subject", invalidBody!);

        // Assert
        act.Should().Throw<ArgumentNullException>().WithMessage("*htmlBody*");
    }

    [Fact]
    public void UpdateContent_WithValidInputs_ShouldUpdateSubjectAndBody()
    {
        // Arrange
        var template = new EmailTemplate("key", "Old Subject", "Old Body");

        // Act
        template.UpdateContent("New Subject", "New Body");

        // Assert
        template.Subject.Should().Be("New Subject");
        template.HtmlBody.Should().Be("New Body");
        template.ModifiedAt.Should().NotBeNull();
    }

    [Theory]
    [InlineData(null, "Body")]
    [InlineData("", "Body")]
    [InlineData(" ", "Body")]
    [InlineData("Subject", null)]
    [InlineData("Subject", "")]
    [InlineData("Subject", " ")]
    public void UpdateContent_WithInvalidInputs_ShouldThrow(string? subject, string? body)
    {
        // Arrange
        var template = new EmailTemplate("key", "subject", "body");

        // Act
        var act = () => template.UpdateContent(subject!, body!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void SetActive_ShouldUpdateActiveState()
    {
        // Arrange
        var template = new EmailTemplate("key", "subject", "body");
        template.IsActive.Should().BeTrue();

        // Act
        template.SetActive(false);

        // Assert
        template.IsActive.Should().BeFalse();
        template.ModifiedAt.Should().NotBeNull();
    }

    [Fact]
    public void SetLayout_ShouldUpdateLayoutKey()
    {
        // Arrange
        var template = new EmailTemplate("key", "subject", "body");

        // Act
        template.SetLayout("custom-layout");

        // Assert
        template.LayoutKey.Should().Be("custom-layout");
        template.ModifiedAt.Should().NotBeNull();
    }
}