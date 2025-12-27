using System.Net;
using System.Net.Http.Json;
using Application.DTOs.Jwt;
using Application.DTOs.Setup;
using Application.Models;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using WebApi.Integration.Tests.Fixtures;

namespace WebApi.Integration.Tests.Auth;

public class SetupTests(SqlServerContainerFixture dbFixture) : IntegrationTestBase(dbFixture)
{
    [Fact]
    public async Task Setup_WhenNoUsersExist_CreatesAdminAndReturnsTokens()
    {
        // Arrange - ensure no users exist
        await ClearAllUsersAsync();

        var setupRequest = new InitialSetupDto
        {
            Email = "admin@example.com",
            Password = "SecurePassword123!",
            FirstName = "Admin",
            LastName = "User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/v1/setup", setupRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = await response.Content.ReadFromJsonAsync<ServiceResponse<JwtResponseDto>>();
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.Data!.Token.Should().NotBeNullOrEmpty();
        result.Data.RefreshToken.Should().NotBeNullOrEmpty();
        result.Data.ForceReset.Should().BeFalse();
        result.Data.RequiresMfa.Should().BeFalse();
    }

    [Fact]
    public async Task Setup_WhenAlreadyConfigured_ReturnsNotFound()
    {
        // Arrange - create a user first
        await CreateTestUserAsync(u => u.WithEmail("existing-user@example.com"));

        var setupRequest = new InitialSetupDto
        {
            Email = "another-admin@example.com",
            Password = "SecurePassword123!",
            FirstName = "Another",
            LastName = "Admin"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/v1/setup", setupRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Setup_AfterSuccessfulSetup_ReturnsNotFound()
    {
        // Arrange - ensure no users exist
        await ClearAllUsersAsync();

        var setupRequest = new InitialSetupDto
        {
            Email = "first-admin@example.com",
            Password = "SecurePassword123!",
            FirstName = "First",
            LastName = "Admin"
        };

        // First setup should succeed
        var firstResponse = await Client.PostAsJsonAsync("/api/v1/setup", setupRequest);
        firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Act - second setup attempt
        var secondRequest = new InitialSetupDto
        {
            Email = "second-admin@example.com",
            Password = "AnotherSecurePassword123!",
            FirstName = "Second",
            LastName = "Admin"
        };
        var secondResponse = await Client.PostAsJsonAsync("/api/v1/setup", secondRequest);

        // Assert
        secondResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Setup_WithInvalidEmail_ReturnsBadRequest()
    {
        // Arrange - ensure no users exist
        await ClearAllUsersAsync();

        var setupRequest = new InitialSetupDto
        {
            Email = "not-an-email",
            Password = "SecurePassword123!",
            FirstName = "Admin",
            LastName = "User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/v1/setup", setupRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Setup_WithShortPassword_ReturnsBadRequest()
    {
        // Arrange - ensure no users exist
        await ClearAllUsersAsync();

        var setupRequest = new InitialSetupDto
        {
            Email = "admin@example.com",
            Password = "short",
            FirstName = "Admin",
            LastName = "User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/v1/setup", setupRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    /// <summary>
    /// Clears all users from the database for setup testing.
    /// Must delete from all related tables first due to foreign key constraints.
    /// Also clears the setup state cache to avoid test pollution.
    /// </summary>
    private async Task ClearAllUsersAsync()
    {
        // Clear the setup state cache to avoid test pollution
        await WithServiceAsync<IMemoryCache>(cache =>
        {
            cache.Remove("SetupService:IsSetupComplete");
            return Task.CompletedTask;
        });

        await WithDbContextAsync(async db =>
        {
            // Delete from all tables with foreign keys to AppUsers (with schema prefixes)
            // Note: [Identity] is bracketed because Identity is a reserved keyword in SQL Server
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaPushChallenges");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaPushDevices");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaEmailCodes");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaChallenges");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaRecoveryCodes");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].WebAuthnCredentials");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].MfaMethods");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Identity].RefreshTokens");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Identity].PasswordResetTokens");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].AccountLockouts");
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Security].LoginAttempts");
            // Clear the join table for user roles
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Identity].AppUserRole");
            // Finally delete users
            await db.Database.ExecuteSqlRawAsync("DELETE FROM [Identity].AppUsers");
        });
    }
}