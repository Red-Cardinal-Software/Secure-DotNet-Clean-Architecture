---
title: JWT & Refresh Tokens
parent: Authentication
nav_order: 1
---

# JWT & Refresh Tokens

Starbase uses short-lived JWT access tokens paired with longer-lived refresh tokens for secure authentication.

## How It Works

```
┌──────────┐     Login      ┌──────────┐
│  Client  │ ──────────────>│   API    │
└──────────┘                └──────────┘
     │                           │
     │   Access Token (15min)    │
     │   Refresh Token (7 days)  │
     │<──────────────────────────│
     │                           │
     │   API Request + Bearer    │
     │──────────────────────────>│
     │                           │
     │   Token Expired (401)     │
     │<──────────────────────────│
     │                           │
     │   Refresh Token Request   │
     │──────────────────────────>│
     │                           │
     │   New Access + Refresh    │
     │<──────────────────────────│
```

## Configuration

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

| Setting | Default | Description |
|---------|---------|-------------|
| `JwtSigningKey` | Required | Minimum 32 characters, keep secret |
| `AccessTokenExpirationMinutes` | 15 | Short-lived for security |
| `RefreshTokenExpirationTimeHours` | 168 (7 days) | Longer-lived, stored securely |

## API Endpoints

### Login

```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "yourpassword"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "requiresMfa": false,
    "forceReset": false
  }
}
```

### Refresh Token

```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

### Logout

```bash
POST /api/auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "refreshToken": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

## Token Claims

The JWT includes these claims:

| Claim | Description |
|-------|-------------|
| `sub` | User ID (GUID) |
| `email` | User's email address |
| `name` | Display name |
| `role` | User's roles (array) |
| `org` | Organization ID |
| Custom privileges | Fine-grained permissions |

## Refresh Token Security

- **Token Families**: Refresh tokens are grouped into families
- **Rotation**: Each refresh generates a new token, invalidating the old one
- **Reuse Detection**: If an old token is reused, the entire family is revoked (indicates theft)
- **IP Tracking**: Tokens are associated with the creating IP address

## Best Practices

1. **Store tokens securely** - Use HttpOnly cookies or secure storage
2. **Never log tokens** - Treat as secrets
3. **Implement token refresh** - Don't wait for expiration
4. **Handle 401 gracefully** - Refresh or redirect to login
5. **Revoke on logout** - Always call the logout endpoint