---
title: Security
nav_order: 5
has_children: true
---

# Security

Starbase includes multiple layers of security protection enabled by default.

## Security Features

| Feature | Description |
|---------|-------------|
| [Rate Limiting](rate-limiting.md) | IP-based request throttling to prevent brute force attacks |
| [Security Headers](security-headers.md) | CSP, HSTS, X-Frame-Options, and more |
| [JWT Key Rotation](jwt-key-rotation.md) | Automatic signing key rotation with zero downtime |

## Defense in Depth

Starbase implements a defense-in-depth strategy:

1. **Network Layer** - Rate limiting prevents abuse and DoS attacks
2. **Transport Layer** - HSTS enforces HTTPS connections
3. **Application Layer** - Security headers prevent XSS, clickjacking, and injection
4. **Authentication Layer** - MFA, account lockout, and secure token handling
5. **Data Layer** - Audit logging and tamper detection

## Quick Security Checklist

### Development

- [ ] Rate limiting configured for testing needs
- [ ] CORS allows localhost origins
- [ ] Development HTTPS certificates installed

### Production

- [ ] Rate limits tuned for expected traffic
- [ ] CORS restricted to known frontend domains
- [ ] Security headers validated with online tools
- [ ] JWT key rotation enabled with cloud secrets manager
- [ ] Audit logging enabled
- [ ] Health check endpoints restricted

## Related Documentation

- [Authentication](../authentication/) - Login, MFA, and token security
- [Audit Logging](../audit-logging.md) - Tamper-evident event logging
- [Configuration](../configuration.md) - All security-related settings