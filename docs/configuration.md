---
title: Configuration
nav_order: 3
---

# Configuration

Starbase uses the standard ASP.NET Core configuration system with environment-specific overrides.

## Configuration Files

| File | Purpose |
|------|---------|
| `appsettings.json` | Base configuration (production defaults) |
| `appsettings.Development.json` | Development overrides |
| `appsettings.{Environment}.json` | Environment-specific settings |

## Core Settings

### Application Settings

```json
{
  "AppSettings": {
    "AppName": "My API",
    "JwtSigningKey": "[Use Azure Key Vault]",
    "JwtIssuer": "https://api.example.com",
    "JwtAudience": "myapp-api-users",
    "JwtExpirationTimeMinutes": 15,
    "RefreshTokenExpirationTimeHours": 24,
    "PasswordResetExpirationTimeHours": 1,
    "PasswordMinimumLength": 8,
    "PasswordMaximumLength": 64
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `JwtSigningKey` | - | **Required.** Minimum 32 characters. Use secret storage. |
| `JwtExpirationTimeMinutes` | 15 | Access token lifetime |
| `RefreshTokenExpirationTimeHours` | 24 | Refresh token lifetime |
| `PasswordMinimumLength` | 8 | Minimum password length |
| `PasswordMaximumLength` | 64 | Maximum password length |

### Connection Strings

```json
{
  "ConnectionStrings": {
    "SqlConnection": "Server=...;Database=...;",
    "Redis": "localhost:6379"
  }
}
```

## Security Settings

### Rate Limiting

```json
{
  "RateLimiting": {
    "Auth": {
      "PermitLimit": 5,
      "WindowMinutes": 1
    },
    "PasswordReset": {
      "PermitLimit": 3,
      "WindowMinutes": 5
    },
    "Api": {
      "PermitLimit": 100,
      "WindowMinutes": 1
    },
    "Health": {
      "PermitLimit": 30,
      "WindowMinutes": 1
    },
    "MfaSetup": {
      "PermitLimit": 10,
      "WindowMinutes": 5
    },
    "Global": {
      "PermitLimit": 200,
      "WindowMinutes": 1
    }
  }
}
```

See [Rate Limiting](security/rate-limiting.md) for details.

### Account Lockout

```json
{
  "AccountLockout": {
    "FailedAttemptThreshold": 5,
    "BaseLockoutDurationMinutes": 5,
    "MaxLockoutDurationMinutes": 60,
    "AttemptResetWindowMinutes": 15,
    "EnableAccountLockout": true,
    "TrackLoginAttempts": true
  }
}
```

See [Account Lockout](authentication/account-lockout.md) for details.

### CORS

```json
{
  "Cors": {
    "Enabled": true,
    "AllowedOrigins": [
      "https://app.example.com",
      "https://admin.example.com"
    ],
    "AllowedMethods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    "AllowedHeaders": ["Authorization", "Content-Type", "Accept", "X-Requested-With"],
    "ExposedHeaders": ["X-Pagination", "X-Total-Count"],
    "AllowCredentials": true,
    "PreflightMaxAgeSeconds": 600
  }
}
```

## MFA Settings

### General MFA

```json
{
  "MfaSettings": {
    "MaxActiveChallenges": 3,
    "MaxChallengesPerWindow": 5,
    "RateLimitWindowMinutes": 5,
    "ChallengeExpiryMinutes": 5,
    "PromptSetup": true
  }
}
```

### Email MFA

```json
{
  "EmailMfaSettings": {
    "MaxCodesPerWindow": 3,
    "RateLimitWindowMinutes": 15,
    "CodeExpiryMinutes": 5,
    "CleanupAgeHours": 24,
    "AppName": "My Application",
    "EnableSecurityWarnings": true
  }
}
```

### WebAuthn

```json
{
  "WebAuthn": {
    "Origins": ["https://app.example.com"],
    "RelyingPartyName": "My Application",
    "RelyingPartyId": "example.com",
    "TimestampDriftTolerance": 300000
  }
}
```

### Push MFA

```json
{
  "PushMfaSettings": {
    "ChallengeExpiryMinutes": 5,
    "MaxChallengesPerWindow": 5,
    "RateLimitWindowMinutes": 5,
    "CleanupAgeHours": 24,
    "Provider": "Mock"
  }
}
```

## Audit Settings

```json
{
  "Audit": {
    "ProcessingMode": "Sync",
    "BatchSize": 100,
    "FlushIntervalMs": 5000,
    "EnableConsoleLogging": false
  },
  "AuditArchive": {
    "Enabled": true,
    "CheckInterval": "01:00:00",
    "AddPartitionOnDay": 25,
    "ArchiveOnDay": 5,
    "MonthsToKeepBeforeArchive": 2,
    "AutoPurgeAfterArchive": true,
    "MinWaitBeforePurge": "1.00:00:00",
    "RetentionPolicy": "default"
  }
}
```

See [Audit Logging](audit-logging.md) for details.

## Health Checks

```json
{
  "HealthChecks": {
    "MemoryThresholdMB": 1024,
    "IncludeMemoryCheck": false
  }
}
```

See [Health Checks](health-checks.md) for details.

## Environment Variables

All settings can be overridden via environment variables using the `__` separator:

```bash
# Override JWT settings
export AppSettings__JwtSigningKey="your-secret-key"
export AppSettings__JwtExpirationTimeMinutes="30"

# Override connection strings
export ConnectionStrings__SqlConnection="Server=prod-server;..."

# Override rate limits
export RateLimiting__Auth__PermitLimit="3"
```

## Development vs Production

### Development Defaults

| Setting | Value | Reason |
|---------|-------|--------|
| `JwtExpirationTimeMinutes` | 60 | Longer tokens for testing |
| `RateLimiting.Auth.PermitLimit` | 50 | Higher limits for development |
| `RateLimiting.Api.PermitLimit` | 1000 | Higher limits for development |
| `PasswordMinimumLength` | 6 | Easier test passwords |

### Production Recommendations

| Setting | Value | Reason |
|---------|-------|--------|
| `JwtExpirationTimeMinutes` | 15 | Short-lived access tokens |
| `RateLimiting.Auth.PermitLimit` | 5 | Strict brute force protection |
| `PasswordMinimumLength` | 12 | Stronger passwords |
| `AccountLockout.FailedAttemptThreshold` | 5 | Balance security and usability |

## Secret Management

Never store secrets in configuration files. Use:

### Azure Key Vault

```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{keyVaultName}.vault.azure.net/"),
    new DefaultAzureCredential());
```

### User Secrets (Development)

```bash
dotnet user-secrets set "AppSettings:JwtSigningKey" "your-dev-key"
```

### Environment Variables (Docker/K8s)

```yaml
env:
  - name: AppSettings__JwtSigningKey
    valueFrom:
      secretKeyRef:
        name: api-secrets
        key: jwt-signing-key
```

## Configuration Validation

The application validates required settings at startup:

- `JwtSigningKey` must be at least 32 characters
- `JwtIssuer` must be a valid URL
- Connection strings must be provided

Invalid configuration will prevent the application from starting.