# Getting Started

## Prerequisites

- .NET 8 SDK or later
- SQL Server 2022+ (for Ledger table support) or SQL Server 2019+
- Redis (optional, for distributed caching)

## Installation

### Clone the Repository

```bash
git clone https://github.com/Red-Cardinal-Software/Starbase.git
cd Starbase
```

### Or Install as a Template

```bash
# Install the template
dotnet new install .

# Create a new project
dotnet new starbase -n MyCompanyApi
cd MyCompanyApi
```

## Configuration

### Database Connection

Update the connection string in `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "SqlConnection": "Server=localhost;Database=Starbase;User Id=sa;Password=YourPassword;TrustServerCertificate=True"
  }
}
```

### Apply Migrations

```bash
dotnet ef database update --project Infrastructure --startup-project WebApi
```

## Run the Application

### Using .NET CLI

```bash
dotnet run --project WebApi
```

### Using Docker

```bash
# Run full stack (API + SQL Server + Redis)
docker-compose up --build

# Or just run dependencies for local development
docker-compose -f docker-compose.deps.yml up -d
dotnet run --project WebApi
```

## Verify Installation

Once running, verify the API is working:

```bash
# Check health endpoint
curl http://localhost:5000/api/health

# Expected response
{"status":"Healthy","timestamp":"2024-01-15T10:30:00.000Z"}
```

## Initial Setup

On first run, create an admin user via the one-time setup endpoint:

```bash
curl -X POST http://localhost:5000/api/v1/setup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "YourSecurePassword123!",
    "firstName": "Admin",
    "lastName": "User"
  }'
```

This returns JWT tokens so you're immediately logged in. The endpoint only works once—after setup it returns 404.

## Development vs Production

The template behaves differently based on environment:

| Feature | Development | Production |
|---------|-------------|------------|
| Swagger UI | Enabled | Disabled |
| Detailed errors | Shown | Hidden |
| Console logging | Enabled | Disabled |
| HTTPS redirect | Optional | Enforced |

Set the environment via:

```bash
# Windows
set ASPNETCORE_ENVIRONMENT=Development

# Linux/Mac
export ASPNETCORE_ENVIRONMENT=Development
```

## Next Steps

- [Configure Authentication](authentication/jwt.md)
- [Set up MFA](authentication/mfa.md)
- [Review Security Settings](security/rate-limiting.md)
- [Configure Audit Logging](audit-logging.md)