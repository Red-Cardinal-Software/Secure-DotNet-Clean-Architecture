---
title: Email MFA
nav_order: 11
---

# Email MFA Configuration Guide

## Overview

Email-based Multi-Factor Authentication (MFA) provides an additional layer of security by sending one-time verification codes to users' email addresses. While not as secure as hardware tokens or authenticator apps, email MFA offers a convenient backup method for users who may not have access to other MFA options.

## Security Considerations

⚠️ **Important Security Notes:**

1. **Email MFA is less secure than other methods** because:
   - Email accounts can be compromised
   - Email transmission is not always encrypted
   - Email providers have access to messages
   - Emails can be forwarded or accessed from multiple devices

2. **Email MFA should be used as a backup method**, not as the primary MFA option when more secure alternatives are available.

3. **Consider implementing additional security measures**:
   - Monitor for suspicious login patterns
   - Implement rate limiting (already included)
   - Use secure email providers with TLS
   - Educate users about email security

## Configuration

### appsettings.json

Add the following configuration to your `appsettings.json`:

```json
{
  "EmailMfaSettings": {
    "MaxCodesPerWindow": 3,
    "RateLimitWindowMinutes": 15,
    "CodeExpiryMinutes": 5,
    "CleanupAgeHours": 24,
    "AppName": "Your App Name",
    "EnableSecurityWarnings": true
  }
}
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxCodesPerWindow` | 3 | Maximum number of codes a user can request within the rate limit window |
| `RateLimitWindowMinutes` | 15 | Time window for rate limiting (in minutes) |
| `CodeExpiryMinutes` | 5 | How long a code remains valid (in minutes) |
| `CleanupAgeHours` | 24 | How old expired codes must be before cleanup (in hours) |
| `AppName` | "OAuth .NET API" | Application name shown in emails |
| `EnableSecurityWarnings` | true | Whether to show security warnings to users |

## Email Template Customization

The default email template can be customized by modifying the `SendCodeEmailAsync` method in `MfaEmailService.cs`:

```csharp
var renderedEmail = new RenderedEmail
{
    Subject = "Your verification code",
    Body = $@"
<html>
<body>
    <h2>Verification Code</h2>
    <p>Your verification code is: <strong>{code}</strong></p>
    <p>This code will expire in {config.CodeExpiryMinutes} minutes.</p>
    <p>If you didn't request this code, please ignore this email or contact support.</p>
    <hr>
    <small>This is an automated message from {config.AppName}. Please do not reply.</small>
</body>
</html>",
    IsHtml = true
};
```

## API Endpoints

### Send Email Code
```http
POST /api/mfa/email/send
{
  "challengeId": "guid",
  "emailAddress": "user@example.com" // Optional, uses account email if not provided
}
```

### Verify Email Code
```http
POST /api/mfa/email/verify
{
  "challengeId": "guid",
  "code": "12345678"
}
```

### Check Rate Limit Status
```http
GET /api/mfa/email/rate-limit
```

## Best Practices

1. **Always use HTTPS** to protect API requests containing verification codes
2. **Implement proper email service** - Replace `NotImplementedEmailService` with a real implementation
3. **Monitor failed attempts** - Track and alert on suspicious verification patterns
4. **Use secure random number generation** - The implementation uses `RandomNumberGenerator.Create()`
5. **Hash codes before storage** - Codes are hashed using the configured password hasher
6. **Implement cleanup jobs** - Regularly clean up expired codes to maintain database performance

## Security Warnings for Users

When email MFA is enabled, consider displaying warnings to users:

- "Email MFA is less secure than authenticator apps or security keys"
- "For maximum security, consider using WebAuthn or TOTP instead"
- "Never share your verification codes with anyone"
- "Ensure your email account has a strong password and 2FA enabled"

## Troubleshooting

### Common Issues

1. **Emails not being sent**
   - Check email service implementation
   - Verify SMTP settings if using SMTP
   - Check email service logs

2. **Rate limiting too restrictive**
   - Adjust `MaxCodesPerWindow` and `RateLimitWindowMinutes`
   - Monitor actual usage patterns

3. **Codes expiring too quickly**
   - Increase `CodeExpiryMinutes`
   - Consider network latency and email delivery times

### Monitoring

Monitor the following metrics:
- Email delivery success rate
- Average time between code request and verification
- Rate limit hits
- Failed verification attempts
- Cleanup job performance

## Integration with MFA Flow

Email MFA integrates with the standard MFA authentication flow:

1. User initiates login
2. System creates MFA challenge
3. User selects email MFA method
4. System sends code via email
5. User enters code
6. System verifies code and completes authentication

The email MFA system respects the same challenge expiry and attempt limits as other MFA methods.