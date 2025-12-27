---
title: Contributing
nav_order: 10
---

# Contributing

Thank you for your interest in contributing to Starbase!

## Getting Started

### Prerequisites

- .NET 8.0 SDK
- Docker (for integration tests)
- SQL Server 2022 (or use Docker)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Red-Cardinal-Software/Secure-DotNet-Clean-Architecture.git
   cd Secure-DotNet-Clean-Architecture
   ```

2. Start dependencies:
   ```bash
   docker-compose -f docker-compose.deps.yml up -d
   ```

3. Run the application:
   ```bash
   dotnet run --project WebApi
   ```

4. Run tests:
   ```bash
   dotnet test
   ```

## Development Workflow

### Branch Naming

- `feature/description` – New features
- `fix/description` – Bug fixes
- `docs/description` – Documentation updates
- `refactor/description` – Code refactoring

### Commit Messages

Use clear, descriptive commit messages:

```
Add WebAuthn credential management endpoints

- Implement credential registration flow
- Add credential listing and deletion
- Include rate limiting for registration
```

### Pull Requests

1. Create a feature branch from `main`
2. Make your changes
3. Ensure all tests pass
4. Update documentation if needed
5. Submit a pull request

## Code Style

### General Guidelines

- Follow existing code patterns in the codebase
- Use meaningful variable and method names
- Keep methods focused and small
- Write self-documenting code

### Architecture

Starbase follows Clean Architecture:

```
Domain/           → Entities, value objects (no dependencies)
Application/      → Business logic, services, DTOs
Infrastructure/   → Data access, external services
WebApi/           → Controllers, middleware
```

### Patterns

- **ServiceResponse<T>** – All service methods return this for consistent error handling
- **Repository Pattern** – Use `IRepository<T>` for data access
- **Specification Pattern** – Use specifications for complex queries

## Testing

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit Tests | `*.Tests/` | Test individual components |
| Integration Tests | `WebApi.Integration.Tests/` | Test full API flows |

### Writing Tests

```csharp
[Fact]
public async Task Login_WithValidCredentials_ReturnsToken()
{
    // Arrange
    var request = new LoginRequest("user@example.com", "password");

    // Act
    var result = await _authService.LoginAsync(request);

    // Assert
    result.Success.Should().BeTrue();
    result.Data.Should().NotBeNull();
}
```

### Running Tests

```bash
# All tests
dotnet test

# Specific project
dotnet test Domain.Tests/

# With coverage
dotnet test --collect:"XPlat Code Coverage"
```

### Integration Tests

Integration tests use Testcontainers for SQL Server:

```csharp
public class AuthControllerTests : IClassFixture<SqlServerContainerFixture>
{
    private readonly SqlServerContainerFixture _fixture;

    public AuthControllerTests(SqlServerContainerFixture fixture)
    {
        _fixture = fixture;
    }
}
```

## Security Contributions

### Reporting Vulnerabilities

Please report security vulnerabilities privately via email rather than public issues.

### Security Guidelines

When contributing security-related code:

- Never log sensitive data (passwords, tokens, PII)
- Use parameterized queries (EF Core handles this)
- Validate all user input
- Follow OWASP guidelines

## Documentation

### Updating Documentation

Documentation lives in the `docs/` folder and uses MkDocs:

```bash
# Install MkDocs
pip install mkdocs-material

# Serve locally
mkdocs serve

# Build
mkdocs build
```

### Documentation Style

- Use clear, concise language
- Include code examples
- Add configuration tables where appropriate
- Link to related documentation

## Template Development

### Testing Template Generation

```bash
# Install template locally
dotnet new install .

# Create test project
dotnet new starbase -n TestProject -o ../TestProject

# Verify it builds
cd ../TestProject
dotnet build
dotnet test
```

### Template Symbols

The template uses symbols for string replacement:

| Symbol | Replacement |
|--------|-------------|
| `Starbase` | Project name |
| `starbase` | Lowercase project name |

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive in discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.