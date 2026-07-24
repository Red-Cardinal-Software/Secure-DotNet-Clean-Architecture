//#if (UsePostgreSql)
using Testcontainers.PostgreSql;
//#elseif (UseOracle)
using Testcontainers.Oracle;
//#else
using Testcontainers.MsSql;
//#endif

namespace WebApi.Integration.Tests.Fixtures;

/// <summary>
/// xUnit fixture that manages the database test container lifecycle.
/// The container is started once and shared across all tests in the collection.
/// </summary>
public class SqlServerContainerFixture : IAsyncLifetime
{
//#if (UsePostgreSql)
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine")
        .Build();
//#elseif (UseOracle)
    private readonly OracleContainer _container = new OracleBuilder("gvenzl/oracle-free:23-slim-faststart")
        .Build();
//#else
    private readonly MsSqlContainer _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest")
        .Build();
//#endif

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