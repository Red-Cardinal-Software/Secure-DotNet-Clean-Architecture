---
title: Multi-Factor Authentication
parent: Authentication
nav_order: 2
---

# Multi-Factor Authentication

Starbase includes a comprehensive MFA system supporting multiple authentication methods.

## Supported Methods

| Method | Security Level | Use Case |
|--------|----------------|----------|
| **TOTP** | High | Primary MFA - Google Authenticator, Authy, etc. |
| **WebAuthn/FIDO2** | Highest | Hardware keys, biometrics, passkeys |
| **Email Codes** | Medium | Backup method |
| **Recovery Codes** | Emergency | Account recovery when other methods unavailable |

## Configuration

```json
{
  "MfaSettings": {
    "MaxActiveChallenges": 3,
    "MaxChallengesPerWindow": 5,
    "RateLimitWindowMinutes": 5,
    "ChallengeExpiryMinutes": 5,
    "PromptSetup": true
  },
  "AppName": "YourApp"
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxActiveChallenges` | 3 | Maximum simultaneous active MFA challenges per user |
| `MaxChallengesPerWindow` | 5 | Maximum challenges created within rate limit window |
| `RateLimitWindowMinutes` | 5 | Time window for challenge rate limiting |
| `ChallengeExpiryMinutes` | 5 | How long MFA challenges remain valid |
| `PromptSetup` | true | Whether to prompt users to set up MFA after login |

## TOTP Setup Flow

### 1. Start Setup

```bash
POST /api/mfa/setup/totp
Authorization: Bearer <token>
Content-Type: application/json

{
  "accountName": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrCodeImage": "data:image/png;base64,...",
    "manualEntryKey": "JBSWY3DPEHPK3PXP",
    "instructions": "Scan the QR code with your authenticator app"
  }
}
```

### 2. Verify Setup

User scans QR code and enters the 6-digit code:

```bash
POST /api/mfa/verify-setup
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "123456",
  "name": "My Phone"
}
```

**Response includes recovery codes:**
```json
{
  "success": true,
  "data": {
    "recoveryCodes": [
      "XXXX-XXXX-XXXX",
      "YYYY-YYYY-YYYY",
      ...
    ]
  }
}
```

## Authentication with MFA

When a user with MFA enabled logs in:

### 1. Initial Login Returns MFA Required

```json
{
  "success": true,
  "data": {
    "requiresMfa": true,
    "challengeToken": "abc123...",
    "availableMethods": ["totp", "email"]
  }
}
```

### 2. Complete MFA Challenge

```bash
POST /api/auth/mfa/verify
Content-Type: application/json

{
  "challengeToken": "abc123...",
  "code": "654321"
}
```

### 3. Receive Final Tokens

```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "a1b2c3d4..."
  }
}
```

## Recovery Codes

Recovery codes are one-time use backup codes:

- Generated during MFA setup
- 8-10 codes provided
- Each can only be used once
- Securely hashed in database

### Regenerate Recovery Codes

```bash
POST /api/mfa/regenerate-recovery
Authorization: Bearer <token>
```

!!! warning "Important"
    Regenerating codes invalidates all previous recovery codes.

## API Endpoints

### User Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mfa/setup/totp` | POST | Start TOTP setup |
| `/api/mfa/verify-setup` | POST | Complete setup with verification code |
| `/api/mfa/overview` | GET | Get user's configured MFA methods |
| `/api/mfa/regenerate-recovery` | POST | Generate new recovery codes |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/mfa/challenge` | POST | Create MFA challenge during login |
| `/api/auth/mfa/verify` | POST | Verify MFA code to complete login |

### Administrative Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/mfa/statistics/system` | GET | System-wide MFA adoption metrics |
| `/api/admin/mfa/statistics/organization/{id}` | GET | Organization MFA metrics |
| `/api/admin/mfa/cleanup/unverified` | DELETE | Clean up old unverified setups |

## Security Features

### Challenge Security

- Challenges expire after 5 minutes by default
- Rate limiting prevents brute force attacks
- Failed attempts are tracked and limited
- Automatic invalidation of other challenges on success

### Multiple Methods

- Users can configure multiple MFA methods
- Default method selection for convenience
- Fallback to other methods if primary fails

## Best Practices

1. **Require MFA for privileged accounts** - Enforce for admins
2. **Monitor recovery code usage** - Alert on usage as it may indicate compromise
3. **Regular cleanup** - Remove old unverified MFA setups
4. **User education** - Provide clear setup instructions
5. **Recovery planning** - Document admin procedures for locked-out users