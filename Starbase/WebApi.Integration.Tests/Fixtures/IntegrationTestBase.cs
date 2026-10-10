using Domain.Entities.Identity;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using TestUtils.EntityBuilders;
using TestUtils.Utilities;

namespace WebApi.Integration.Tests.Fixtures;

/// <summary>
/// Base class for integration tests. Provides access to the HttpClient and database context.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public abstract class IntegrationTestBase(SqlServerContainerFixture dbFixture) : IAsyncLifetime
{
    private IntegrationTestWebApplicationFactory _factory = null!;

    protected HttpClient Client { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        _factory = new IntegrationTestWebApplicationFactory(dbFixture);
        Client = _factory.CreateClient();

        // Initialize database using execution strategy to handle retry conflicts
        await WithDbContextAsync(async dbContext =>
        {
            var strategy = dbContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                // EnsureCreatedAsync will create the schema based on the model
                // Note: This doesn't run migrations, just creates based on current model
                await dbContext.Database.EnsureCreatedAsync();
            });
        });
    }

    public async Task DisposeAsync()
    {
        Client.Dispose();
        await _factory.DisposeAsync();
    }

    /// <summary>
    /// Creates a new scope and returns the database context.
    /// Remember to dispose the scope when done.
    /// </summary>
    private IServiceScope CreateScope() => _factory.Services.CreateScope();

    /// <summary>
    /// Executes an action with a scoped database context.
    /// </summary>
    protected async Task WithDbContextAsync(Func<AppDbContext, Task> action)
    {
        using var scope = CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await action(dbContext);
    }

    /// <summary>
    /// Executes a function with a scoped database context and returns the result.
    /// </summary>
    protected async Task<T> WithDbContextAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        using var scope = CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await action(dbContext);
    }

    /// <summary>
    /// Executes an action with a single scope, so several services can be resolved together and
    /// share one <see cref="AppDbContext"/>. Needed when a test depends on services interacting
    /// through the same unit of work.
    /// </summary>
    protected async Task WithScopeAsync(Func<IServiceProvider, Task> action)
    {
        using var scope = CreateScope();
        await action(scope.ServiceProvider);
    }

    /// <summary>
    /// Executes an action with a scoped service.
    /// </summary>
    protected async Task WithServiceAsync<TService>(Func<TService, Task> action) where TService : notnull
    {
        using var scope = _factory.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<TService>();
        await action(service);
    }

    /// <summary>
    /// Executes a function with a scoped service and returns the result.
    /// </summary>
    protected async Task<TResult> WithServiceAsync<TService, TResult>(Func<TService, Task<TResult>> action) where TService : notnull
    {
        using var scope = _factory.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<TService>();
        return await action(service);
    }

    #region Test Data Helpers

    /// <summary>
    /// Ensures the default test organization exists.
    /// </summary>
    protected async Task<Organization> EnsureTestOrganizationAsync(Guid? organizationId = null)
    {
        var orgId = organizationId ?? TestConstants.Ids.OrganizationId;

        return await WithDbContextAsync(async db =>
        {
            var existing = await db.Set<Organization>().FindAsync(orgId);
            if (existing is not null)
                return existing;

            var org = new Organization("Test Organization");
            // Use reflection to set the specific ID for consistency
            typeof(Organization).GetProperty("Id")!.SetValue(org, orgId);
            db.Set<Organization>().Add(org);
            await db.SaveChangesAsync();
            return org;
        });
    }

    /// <summary>
    /// Creates and persists a test user with optional configuration.
    /// Automatically ensures the organization exists.
    /// </summary>
    protected async Task<AppUser> CreateTestUserAsync(Action<AppUserBuilder>? configure = null)
    {
        // Ensure the default organization exists first
        await EnsureTestOrganizationAsync();

        return await WithDbContextAsync(async db =>
        {
            var builder = new AppUserBuilder();
            configure?.Invoke(builder);
            var user = builder.Build();
            db.AppUsers.Add(user);
            await db.SaveChangesAsync();
            return user;
        });
    }

    /// <summary>
    /// Creates and persists a test role with optional configuration.
    /// </summary>
    protected async Task<Role> CreateTestRoleAsync(Action<RoleBuilder>? configure = null)
    {
        return await WithDbContextAsync(async db =>
        {
            var builder = RoleBuilder.New();
            configure?.Invoke(builder);
            var role = builder.Build();
            db.Roles.Add(role);
            await db.SaveChangesAsync();
            return role;
        });
    }

    /// <summary>
    /// Creates a test user and assigns them to a role.
    /// </summary>
    protected async Task<AppUser> CreateTestUserWithRoleAsync(
        string roleName,
        Action<AppUserBuilder>? configureUser = null)
    {
        return await WithDbContextAsync(async db =>
        {
            var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == roleName)
                ?? throw new InvalidOperationException($"Role '{roleName}' not found. Ensure seeders have run.");

            var builder = new AppUserBuilder();
            configureUser?.Invoke(builder);
            var user = builder.Build();
            user.AddRole(role);

            db.AppUsers.Add(user);
            await db.SaveChangesAsync();
            return user;
        });
    }

    #endregion
}