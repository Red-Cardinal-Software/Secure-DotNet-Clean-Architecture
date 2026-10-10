using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Application.DTOs.Auth;
using Application.DTOs.Jwt;
using Application.Interfaces.Providers;
using Application.Models;
using FluentAssertions;
using Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using TestUtils.EntityBuilders;
using WebApi.Integration.Tests.Fixtures;

namespace WebApi.Integration.Tests.Security;

/// <summary>
/// Integration tests for JWT signing key rotation.
/// Verifies that tokens signed with previous keys remain valid during the overlap window.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class SigningKeyRotationTests : IAsyncLifetime
{
    private readonly SqlServerContainerFixture _dbFixture;
    private KeyRotationTestWebApplicationFactory _factory = null!;
    private HttpClient _client = null!;
    private TestSigningKeyProvider _keyProvider = null!;

    public SigningKeyRotationTests(SqlServerContainerFixture dbFixture)
    {
        _dbFixture = dbFixture;
    }

    public async Task InitializeAsync()
    {
        _keyProvider = new TestSigningKeyProvider();
        _factory = new KeyRotationTestWebApplicationFactory(_dbFixture, _keyProvider);
        _client = _factory.CreateClient();

        // Initialize database
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _factory.DisposeAsync();
    }

    #region Multi-Key Validation Tests

    [Fact]
    public async Task Token_SignedWithPrimaryKey_Validates()
    {
        // Arrange - Create user and get token (signed with primary key)
        var (token, _) = await CreateUserAndGetTokensAsync("keyrotation-primary@example.com");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client.GetAsync("/api/v1/auth/mfa/overview");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Token_SignedWithPreviousKey_StillValidatesAfterRotation()
    {
        // Arrange - Create user and get token with current key
        var (tokenBeforeRotation, _) = await CreateUserAndGetTokensAsync("keyrotation-previous@example.com");

        // Rotate the key
        await _keyProvider.RotateKeyAsync();

        // Verify we now have multiple keys
        var allKeys = _keyProvider.GetAllKeys();
        allKeys.Should().HaveCountGreaterThan(1, "rotation should create a new key while keeping the old one");

        // Use the token that was signed with the previous key
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenBeforeRotation);

        // Act - Token signed with previous key should still work
        var response = await _client.GetAsync("/api/v1/auth/mfa/overview");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "tokens signed with previous key should remain valid during overlap window");
    }

    [Fact]
    public async Task NewToken_AfterRotation_IsSignedWithNewKey()
    {
        // Arrange - Get the current primary key ID
        var primaryKeyBefore = await _keyProvider.GetCurrentSigningKeyAsync();

        // Rotate the key
        var newKey = await _keyProvider.RotateKeyAsync();
        newKey.KeyId.Should().NotBe(primaryKeyBefore.KeyId);

        // Create user and get new token (should be signed with new key)
        var (tokenAfterRotation, _) = await CreateUserAndGetTokensAsync("keyrotation-new@example.com");

        // The new token should validate
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenAfterRotation);
        var response = await _client.GetAsync("/api/v1/auth/mfa/overview");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task MultipleRotations_OldTokensStillValidDuringOverlapWindow()
    {
        // Arrange - Get token with original key
        var (token1, _) = await CreateUserAndGetTokensAsync("keyrotation-multi1@example.com");

        // First rotation
        await _keyProvider.RotateKeyAsync();
        var (token2, _) = await CreateUserAndGetTokensAsync("keyrotation-multi2@example.com");

        // Second rotation
        await _keyProvider.RotateKeyAsync();
        var (token3, _) = await CreateUserAndGetTokensAsync("keyrotation-multi3@example.com");

        // Verify we have multiple keys
        var allKeys = _keyProvider.GetAllKeys();
        allKeys.Count.Should().BeGreaterThanOrEqualTo(3);

        // Act & Assert - All tokens should still work
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        var response1 = await _client.GetAsync("/api/v1/auth/mfa/overview");
        response1.StatusCode.Should().Be(HttpStatusCode.OK, "token from original key should still validate");

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        var response2 = await _client.GetAsync("/api/v1/auth/mfa/overview");
        response2.StatusCode.Should().Be(HttpStatusCode.OK, "token from first rotation should still validate");

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token3);
        var response3 = await _client.GetAsync("/api/v1/auth/mfa/overview");
        response3.StatusCode.Should().Be(HttpStatusCode.OK, "token from second rotation should validate");
    }

    #endregion

    #region Key Provider Tests

    [Fact]
    public async Task RotateKeyAsync_CreatesNewPrimaryKey()
    {
        // Arrange
        var originalPrimary = await _keyProvider.GetCurrentSigningKeyAsync();

        // Act
        var newKey = await _keyProvider.RotateKeyAsync();

        // Assert
        newKey.KeyId.Should().NotBe(originalPrimary.KeyId);
        newKey.IsPrimary.Should().BeTrue();

        var currentPrimary = await _keyProvider.GetCurrentSigningKeyAsync();
        currentPrimary.KeyId.Should().Be(newKey.KeyId);
    }

    [Fact]
    public async Task RotateKeyAsync_DemotesPreviousPrimary()
    {
        // Arrange
        var originalPrimary = await _keyProvider.GetCurrentSigningKeyAsync();
        var originalKeyId = originalPrimary.KeyId;

        // Act
        await _keyProvider.RotateKeyAsync();

        // Assert - Original key should still exist but not be primary
        var oldKey = _keyProvider.GetKeyById(originalKeyId);
        oldKey.Should().NotBeNull();
        oldKey!.IsPrimary.Should().BeFalse();
        oldKey.ExpiresAt.Should().NotBeNull("demoted key should have an expiration");
    }

    [Fact]
    public async Task GetValidationKeysAsync_ReturnsAllNonExpiredKeys()
    {
        // Arrange - Rotate a few times to create multiple keys
        await _keyProvider.RotateKeyAsync();
        await _keyProvider.RotateKeyAsync();

        // Act
        var validationKeys = await _keyProvider.GetValidationKeysAsync();

        // Assert
        validationKeys.Count.Should().BeGreaterThanOrEqualTo(3, "should have original + 2 rotated keys");
        validationKeys.Should().OnlyContain(k => k.ExpiresAt == null || k.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task GetValidationKeysAsync_ExcludesExpiredKeys()
    {
        // Arrange - Add an expired key
        _keyProvider.AddExpiredKey("expired-test-key");

        // Act
        var validationKeys = await _keyProvider.GetValidationKeysAsync();

        // Assert
        validationKeys.Should().NotContain(k => k.KeyId == "expired-test-key",
            "expired keys should not be included in validation set");
    }

    #endregion

    #region Helper Methods

    private async Task<(string accessToken, string refreshToken)> CreateUserAndGetTokensAsync(string email)
    {
        var password = "TestPassword123!";
        await CreateTestUserAsync(email, password);

        var loginResponse = await _client.PostAsJsonAsync("/api/v1/auth/login", new UserLoginDto
        {
            Username = email,
            Password = password
        });

        loginResponse.EnsureSuccessStatusCode();
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<ServiceResponse<JwtResponseDto>>();
        return (loginResult!.Data!.Token!, loginResult.Data.RefreshToken!);
    }

    private async Task CreateTestUserAsync(string email, string password)
    {
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // Ensure organization exists
        var orgId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var org = await dbContext.Set<Domain.Entities.Identity.Organization>().FindAsync(orgId);
        if (org == null)
        {
            org = new Domain.Entities.Identity.Organization("Test Organization");
            typeof(Domain.Entities.Identity.Organization).GetProperty("Id")!.SetValue(org, orgId);
            dbContext.Set<Domain.Entities.Identity.Organization>().Add(org);
            await dbContext.SaveChangesAsync();
        }

        var user = new AppUserBuilder()
            .WithEmail(email)
            .WithPassword(password)
            .WithForceResetPassword(false)
            .WithOrganizationId(orgId)
            .Build();

        dbContext.AppUsers.Add(user);
        await dbContext.SaveChangesAsync();
    }

    #endregion

    #region Custom WebApplicationFactory

    /// <summary>
    /// WebApplicationFactory configured with the TestSigningKeyProvider for key rotation testing.
    /// </summary>
    private class KeyRotationTestWebApplicationFactory : WebApplicationFactory<Program>
    {
        private readonly SqlServerContainerFixture _dbFixture;
        private readonly TestSigningKeyProvider _keyProvider;

        public KeyRotationTestWebApplicationFactory(
            SqlServerContainerFixture dbFixture,
            TestSigningKeyProvider keyProvider)
        {
            _dbFixture = dbFixture;
            _keyProvider = keyProvider;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SqlConnection"] = _dbFixture.ConnectionString,
                    ["RateLimiting:Auth:PermitLimit"] = "10000",
                    ["RateLimiting:Auth:WindowMinutes"] = "1",
                    ["RateLimiting:Api:PermitLimit"] = "10000",
                    ["RateLimiting:Global:PermitLimit"] = "10000",
                });
            });

            builder.ConfigureTestServices(services =>
            {
                // Remove existing DbContext
                services.RemoveAll<DbContextOptions<AppDbContext>>();
                services.RemoveAll<AppDbContext>();

                services.AddDbContext<AppDbContext>((sp, options) =>
                {
                    DatabaseProviderSetup.Configure(options, _dbFixture.ConnectionString);
                });

                // Replace the signing key provider with our test implementation
                services.RemoveAll<ISigningKeyProvider>();
                services.AddSingleton<ISigningKeyProvider>(_keyProvider);
            });

            builder.UseEnvironment("Testing");
        }
    }

    #endregion
}