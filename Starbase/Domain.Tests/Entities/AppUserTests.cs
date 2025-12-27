using Domain.Entities.Identity;
using Domain.Exceptions;
using FluentAssertions;
using TestUtils.EntityBuilders;
using TestUtils.Utilities;
using Xunit;

namespace Domain.Tests.Entities;

public class AppUserTests
{
    [Fact]
    public void Constructor_ShouldSetPropertiesCorrectly()
    {
        var user = new AppUserBuilder().Build();

        user.Username.Should().Be(TestConstants.Emails.Default);
        user.Password.Should().NotBeNull();
        user.FirstName.Should().Be(TestConstants.Names.DefaultFirstName);
        user.LastName.Should().Be(TestConstants.Names.DefaultLastName);
        user.OrganizationId.Should().NotBeEmpty();
        user.ForceResetPassword.Should().BeTrue();
        user.Active.Should().BeTrue();
        user.Roles.Should().BeEmpty();
    }

    [Theory]
    [InlineData("")]
    [InlineData("     ")]
    public void Constructor_ShouldThrow_ForInvalidUsername(string username)
    {
        Action act = () => new AppUserBuilder().WithEmail(username).Build();
        act.Should().Throw<InvalidUsernameException>();
    }

    [Fact]
    public void ChangeFirstName_ShouldUpdateName()
    {
        var user = new AppUserBuilder().Build();
        user.ChangeFirstName("Jane");
        user.FirstName.Should().Be("Jane");
    }

    [Fact]
    public void ChangeFirstName_ShouldThrow_WhenInvalid()
    {
        var user = new AppUserBuilder().Build();
        Action act = () => user.ChangeFirstName(" ");
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddRole_ShouldAddNewRole()
    {
        var user = new AppUserBuilder().Build();
        var role = new Role("Admin");
        user.AddRole(role);
        user.Roles.Should().Contain(role);
    }

    [Fact]
    public void AddRole_ShouldThrow_WhenDuplicate()
    {
        var user = new AppUserBuilder().Build();
        var role = new Role("Admin");
        user.AddRole(role);
        Action act = () => user.AddRole(role);
        act.Should().Throw<DuplicateRoleException>();
    }

    [Fact]
    public void RemoveRole_ShouldRemove()
    {
        var user = new AppUserBuilder().Build();
        var role = new Role("Admin");
        user.AddRole(role);
        user.RemoveRole(role);
        user.Roles.Should().BeEmpty();
    }

    [Fact]
    public void RemoveRole_ShouldThrow_IfNotPresent()
    {
        var user = new AppUserBuilder().Build();
        var role = new Role("Admin");
        Action act = () => user.RemoveRole(role);
        act.Should().Throw<InvalidStateTransitionException>();
    }

    [Fact]
    public void ChangePassword_ShouldUpdateAndClearReset()
    {
        var user = new AppUserBuilder().WithForceResetPassword(true).Build();
        user.ChangePassword("newHashed1234567890abc");
        user.Password.Value.Should().Be("newHashed1234567890abc");
        user.ForceResetPassword.Should().BeFalse();
    }

    [Fact]
    public void LoggedIn_ShouldSetUtcNow()
    {
        var user = new AppUserBuilder().Build();
        user.LoggedIn();
        user.LastLoginTime.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void ChangeOrganization_ShouldUpdateIfDifferent()
    {
        var originalOrgId = Guid.NewGuid();
        var user = new AppUserBuilder().WithOrganizationId(originalOrgId).Build();

        var newOrg = new Organization("Other Org");
        user.ChangeOrganization(newOrg);

        user.OrganizationId.Should().Be(newOrg.Id);
        user.Organization.Should().Be(newOrg);
    }

    [Fact]
    public void ChangeOrganization_ShouldDoNothingIfSame()
    {
        var org = new Organization("Same Org");
        var user = new AppUserBuilder().WithOrganizationId(org.Id).Build();

        user.ChangeOrganization(org);
        user.OrganizationId.Should().Be(org.Id);
    }

    [Theory]
    [InlineData(" ")]
    public void ChangePassword_ShouldThrow_WhenInvalid(string password)
    {
        var user = new AppUserBuilder().Build();
        var act = () => user.ChangePassword(password);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_ShouldInitializeWithEmptyRoles()
    {
        var user = new AppUserBuilder().Build();
        user.Roles.Should().BeEmpty();
    }

    [Fact]
    public void AddRole_ShouldThrow_WhenRoleIsNull()
    {
        var user = new AppUserBuilder().Build();
        var act = () => user.AddRole(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void RemoveRole_ShouldThrow_WhenRoleIsNull()
    {
        var user = new AppUserBuilder().Build();
        var act = () => user.RemoveRole(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ChangeLastName_Successful()
    {
        var user = new AppUserBuilder().Build();
        user.ChangeLastName("newLastName");
        user.LastName.Should().Be("newLastName");
    }

    [Fact]
    public void ChangeLastName_Blank_ShouldFail()
    {
        var user = new AppUserBuilder().Build();
        var act = () => user.ChangeLastName("");
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstructUser_WithBlankFirstName_ShouldFail()
    {
        var act = () => new AppUserBuilder().WithFirstName("").Build();
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstructUser_WithBlankLastName_ShouldFail()
    {
        var act = () => new AppUserBuilder().WithLastName("").Build();
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstructUser_WithBlankHashedPassword_ShouldFail()
    {
        var act = () => new AppUser("username", "", "first", "last", Guid.NewGuid());
        act.Should().Throw<ArgumentNullException>();
    }
}
