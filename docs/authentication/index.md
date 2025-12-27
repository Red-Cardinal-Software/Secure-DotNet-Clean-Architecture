---
title: Authentication
nav_order: 4
has_children: true
---

# Authentication Overview

Starbase includes a comprehensive authentication system with multiple layers of security.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Authentication Flow                   │
├─────────────────────────────────────────────────────────┤
│  1. Login Request (username/password)                   │
│  2. Rate Limit Check (5 requests/min per IP)            │
│  3. Account Lockout Check                               │
│  4. Credential Validation (BCrypt)                      │
│  5. MFA Challenge (if enabled)                          │
│  6. JWT + Refresh Token Issued                          │
└─────────────────────────────────────────────────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| [JWT & Refresh Tokens](jwt.md) | Short-lived access tokens with secure refresh |
| [Multi-Factor Authentication](mfa.md) | TOTP, Email, WebAuthn support |
| [WebAuthn & Passkeys](webauthn.md) | Hardware security keys and biometrics |
| [Account Lockout](account-lockout.md) | Exponential backoff protection |

## Security Layers

### 1. Rate Limiting
Prevents brute force attacks by limiting login attempts per IP address.

### 2. Account Lockout
Locks accounts after repeated failed attempts with exponential backoff.

### 3. Password Hashing
BCrypt with configurable work factor adds computational cost to attacks.

### 4. Multi-Factor Authentication
Optional second factor using TOTP, email codes, or hardware keys.

### 5. Short-Lived Tokens
Access tokens expire quickly (default: 15 minutes), limiting exposure window.

## Configuration

Core authentication settings in `appsettings.json`:

```json
{
  "AppSettings": {
    "JwtSigningKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong",
    "JwtIssuer": "https://your-api.com",
    "JwtAudience": "your-api-users",
    "AccessTokenExpirationMinutes": 15,
    "RefreshTokenExpirationTimeHours": 168
  }
}
```

## Audit Integration

All authentication events are captured via domain events:

- `LoginAttemptedEvent` - Success and failure
- `LogoutEvent` - User logout
- `TokenRefreshedEvent` - Token refresh
- `PasswordResetRequestedEvent` - Password reset requests

See [Audit Logging](../audit-logging.md) for details.