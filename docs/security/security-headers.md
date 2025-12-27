---
title: Security Headers
parent: Security
nav_order: 2
---

# Security Headers

Starbase includes security headers middleware that adds defense-in-depth protection against common web vulnerabilities.

## Enabled Headers

| Header | Value | Protection |
|--------|-------|------------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Content-Security-Policy` | Configured | Prevents XSS and injection attacks |
| `Permissions-Policy` | Configured | Controls browser features |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS |

## Content Security Policy

Default CSP configuration:

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
form-action 'self';
base-uri 'self';
```

## Permissions Policy

Restricts browser features:

```
accelerometer=(), camera=(), geolocation=(), gyroscope=(),
magnetometer=(), microphone=(), payment=(), usb=()
```

## Implementation

The middleware is in `Infrastructure/Web/Middleware/SecurityHeadersMiddleware.cs`:

```csharp
public class SecurityHeadersMiddleware
{
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Append("X-Frame-Options", "DENY");
        context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
        context.Response.Headers.Append("Content-Security-Policy", GetCsp());
        context.Response.Headers.Append("Permissions-Policy", GetPermissionsPolicy());

        if (context.Request.IsHttps)
        {
            context.Response.Headers.Append("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains");
        }

        await _next(context);
    }
}
```

## CORS Configuration

CORS is configured separately in `appsettings.json`:

```json
{
  "Cors": {
    "AllowedOrigins": [
      "https://your-frontend.com",
      "https://admin.your-frontend.com"
    ]
  }
}
```

For development:

```json
{
  "Cors": {
    "AllowedOrigins": [
      "http://localhost:3000",
      "http://localhost:5173"
    ]
  }
}
```

## Customizing Headers

### Modify CSP for Your Needs

If you need to allow external resources:

```csharp
// Allow Google Fonts
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com;

// Allow CDN scripts
script-src 'self' https://cdn.example.com;
```

### Allow Framing for Specific Origins

```csharp
// Instead of DENY
context.Response.Headers.Append("X-Frame-Options", "SAMEORIGIN");

// Or use CSP frame-ancestors
frame-ancestors 'self' https://trusted-site.com;
```

## Testing Headers

Use browser DevTools or online tools:

```bash
# Check headers with curl
curl -I https://your-api.com/api/health
```

Online tools:
- [SecurityHeaders.com](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)

## Production Checklist

- [ ] HSTS enabled with appropriate max-age
- [ ] CSP configured for your specific needs
- [ ] CORS origins restricted to known frontends
- [ ] X-Frame-Options set appropriately
- [ ] No unnecessary permissions granted