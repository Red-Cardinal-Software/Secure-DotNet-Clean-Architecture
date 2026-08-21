// This file is for LOCAL DEVELOPMENT ONLY.
// It is excluded from template output and provides a SQL Server fixture for local testing.
// The template generates SqlServerContainerFixture.cs with the appropriate database provider.

using Testcontainers.MsSql;

namespace WebApi.Integration.Tests.Fixtures;

/// <summary>
/// Local development fixture - uses SQL Server.
/// This file is excluded from template output.
/// </summary>
public class SqlServerContainerFixture : IAsyncLifetime
{
    private readonly MsSqlContainer _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest")
        .Build();

    public string ConnectionString => _container.GetConnectionString();

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _container.DisposeAsync();
    }
}