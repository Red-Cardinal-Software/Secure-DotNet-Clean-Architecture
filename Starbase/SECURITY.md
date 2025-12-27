# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Starbase, please report it responsibly by emailing:

**james@redcardinalsoftware.com**

Please include:
- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)

We will acknowledge receipt within 48 hours and aim to provide a fix within 30 days for critical vulnerabilities.

**Please do not open public GitHub issues for security vulnerabilities.**

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Security Features

Starbase is designed with security as a first-class concern. The template includes:

### Authentication & Authorization
- **JWT Authentication** with secure token handling
- **Refresh Tokens** with rotation and revocation support
- **Multi-Factor Authentication (MFA)**
  - TOTP (Time-based One-Time Passwords)
  - Email verification codes
  - WebAuthn/FIDO2 (passkeys and security keys)

### Account Protection
- **Account Lockout** after failed login attempts
- **Rate Limiting** on sensitive endpoints (auth, password reset, MFA setup)
- **Secure Password Reset** with token-based flow and IP tracking

### HTTP Security
- **Security Headers** via middleware:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- **CORS** with strict origin configuration

### Data Protection
- **Password Hashing** using industry-standard algorithms
- **Sensitive Data Logging** prevention
- **Input Validation** on all endpoints

## Security Best Practices

When using this template, we recommend:

1. **Environment Configuration**: Never commit secrets to source control. Use environment variables or a secrets manager.
2. **HTTPS Only**: Always deploy with HTTPS in production.
3. **Regular Updates**: Keep dependencies updated to receive security patches.
4. **Audit Logging**: Enable and monitor audit logs for suspicious activity.
5. **Database Security**: Use parameterized queries (EF Core handles this) and principle of least privilege.

## Disclosure Policy

- We will confirm receipt of your vulnerability report within 48 hours
- We will provide an initial assessment within 7 days
- We aim to release patches for critical vulnerabilities within 30 days
- We will credit reporters in release notes (unless anonymity is requested)