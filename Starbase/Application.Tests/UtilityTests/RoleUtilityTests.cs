using System.Security.Claims;
using Application.Common.Utilities;
using Domain.Constants;
using Domain.Entities.Identity;
using Xunit;

namespace Application.Tests.UtilityTests;

public class RoleUtilityTests
{
    [Fact]
    public void GetRoleNamesFromClaims_WithMatchingClaims_ReturnsRoles()
    {
        // Arrange
        var roles = new List<Role>
        {
            new("Admin"),
            new("User"),
            new("SuperAdmin")
        };

        var claims = new List<Claim>
        {
            new(ClaimTypes.Role, "Admin"),
            new(ClaimTypes.Role, "SuperAdmin")
        };

        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = RoleUtility.GetRoleNamesFromClaims(principal, roles).ToList();

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Contains(result, r => r.Name == "Admin");
        Assert.Contains(result, r => r.Name == "SuperAdmin");
    }

    [Fact]
    public void GetRoleNamesFromClaims_WithUnmatchedClaims_ReturnsOnlyMatching()
    {
        var roles = new List<Role> { new("User") };
        var claims = new List<Claim> { new(ClaimTypes.Role, "Admin") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var result = RoleUtility.GetRoleNamesFromClaims(principal, roles);

        Assert.Empty(result);
    }

    [Fact]
    public void GetRoleNamesFromClaims_WithNoClaims_ReturnsEmpty()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var roles = new List<Role> { new("Admin") };

        var result = RoleUtility.GetRoleNamesFromClaims(principal, roles);

        Assert.Empty(result);
    }

    [Fact]
    public void GetRoleNamesFromClaims_WithEmptyRoles_ReturnsEmpty()
    {
        var claims = new List<Claim> { new(ClaimTypes.Role, "Admin") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var result = RoleUtility.GetRoleNamesFromClaims(principal, []);

        Assert.Empty(result);
    }

    [Fact]
    public void IsUserSuperAdmin_WithSuperAdminClaim_ReturnsTrue()
    {
        // Arrange
        var claims = new List<Claim> { new(ClaimTypes.Role, PredefinedRoles.SuperAdmin) };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = RoleUtility.IsUserSuperAdmin(principal);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsUserSuperAdmin_WithoutSuperAdminClaim_ReturnsFalse()
    {
        var claims = new List<Claim> { new(ClaimTypes.Role, "User") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var result = RoleUtility.IsUserSuperAdmin(principal);

        Assert.False(result);
    }

    [Fact]
    public void IsUserAdmin_WithAdminClaim_ReturnsTrue()
    {
        var claims = new List<Claim> { new(ClaimTypes.Role, PredefinedRoles.Admin) };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var result = RoleUtility.IsUserAdmin(principal);

        Assert.True(result);
    }

    [Fact]
    public void IsUserAdmin_WithoutAdminClaim_ReturnsFalse()
    {
        var claims = new List<Claim> { new(ClaimTypes.Role, "User") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        var result = RoleUtility.IsUserAdmin(principal);

        Assert.False(result);
    }

    [Fact]
    public void IsUserAdminOrSuperAdmin_WithAdmin_ReturnsTrue()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.Role, PredefinedRoles.Admin)
        ]));

        Assert.True(RoleUtility.IsUserAdminOrSuperAdmin(principal));
    }

    [Fact]
    public void IsUserActive_ReturnsTrue_WhenClaimIsTrue()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim("IsUserActive", "True")
        };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = RoleUtility.IsUserActive(principal);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsUserActive_ReturnsFalse_WhenClaimIsFalse()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim("IsUserActive", "False")
        };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = RoleUtility.IsUserActive(principal);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsUserActive_ThrowsException_WhenClaimIsMissing()
    {
        // Arrange
        var identity = new ClaimsIdentity(); // no claims
        var principal = new ClaimsPrincipal(identity);

        // Act & Assert
        Assert.Throws<NullReferenceException>(() => RoleUtility.IsUserActive(principal));
    }
}
