# Starbase

A secure, production-ready .NET API template with JWT authentication, MFA, rate limiting, audit logging, and security headers.

## Installation

```bash
# Install the template from NuGet
dotnet new install Starbase

# Create a new project
dotnet new starbase -n MyApi
```

## Template Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --name` | Project name | SecureApi |
| `--DatabaseProvider` | Database: `SqlServer`, `PostgreSQL`, `Oracle` | SqlServer |
| `--CloudProvider` | Secrets management: `None`, `Azure`, `AWS`, `GCP` | None |
| `--EmailProvider` | Email provider: `None`, `Smtp`, `SendGrid`, `AwsSes`, `Postmark`, `Mailgun`, `Mailchimp` | None |
| `--IncludeDocker` | Include Docker files | true |

### Examples

```bash
# Basic project
dotnet new starbase -n MyApi

# With PostgreSQL and Azure Key Vault
dotnet new starbase -n MyApi --DatabaseProvider PostgreSQL --CloudProvider Azure

# With SendGrid email provider
dotnet new starbase -n MyApi --EmailProvider SendGrid

# Without Docker files
dotnet new starbase -n MyApi --IncludeDocker false
```

## Getting Started

```bash
# Start dependencies
docker-compose -f docker-compose.deps.yml up -d

# Run the API
dotnet run --project WebApi

# Run tests
dotnet test
```

## Configuration

Key settings in `WebApi/appsettings.json`:

| Setting | Description |
|---------|-------------|
| `ConnectionStrings:SqlConnection` | Database connection string |
| `AppSettings:JwtSigningKey` | JWT signing key (min 32 chars) |
| `AppSettings:JwtIssuer` | Token issuer URL |
| `AppSettings:JwtAudience` | Token audience |

## Project Structure

```
Domain/           → Entities, value objects, domain logic
Application/      → Business logic, services, DTOs
Infrastructure/   → Data access, EF Core, repositories
WebApi/           → Controllers, middleware, API config
```

## Documentation

For detailed documentation on security features, MFA setup, audit logging, and more, visit the original template documentation at **[View Full Documentation →](https://red-cardinal-software.github.io/Secure-DotNet-Clean-Architecture/)**.

## Need Help?

Starbase is free and open source, but if you need help with implementation, customization, or security consulting, I'm available for hire.

**Services offered:**
- Custom feature development
- Security audits and hardening
- Architecture reviews
- Integration assistance
- Training and onboarding

Contact: **james@redcardinalsoftware.com**

## License

MIT License