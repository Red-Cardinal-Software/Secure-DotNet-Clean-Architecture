---
title: Rate Limiting
parent: Security
nav_order: 1
---

# Rate Limiting

Starbase includes comprehensive rate limiting to protect against brute force attacks, credential stuffing, and API abuse using .NET's built-in `Microsoft.AspNetCore.RateLimiting` middleware.

## Overview

**Two-Layer Protection:**

1. **Policy-Based Limits** – Specific rate limits applied to endpoint groups
2. **Global IP-Based Limiter** – Baseline protection across all endpoints

## Default Rate Limits

| Policy | Endpoints | Limit | Window | Purpose |
|--------|-----------|-------|--------|---------|
| `auth` | Login, Refresh Token | 5 requests | 1 minute | Prevents brute force authentication attacks |
| `password-reset` | Password Reset | 3 requests | 5 minutes | Prevents email spam and abuse |
| `mfa-setup` | MFA Setup | 10 requests | 5 minutes | Prevents MFA enumeration |
| `health` | Health Check | 30 requests | 1 minute | Prevents health check abuse |
| `api` | General endpoints | 100 requests | 1 minute | General API protection |
| `global` | All endpoints | 200 requests | 1 minute | Baseline protection per IP |

## Configuration

All rate limits are configurable via `appsettings.json`:

```json
{
  "RateLimiting-Auth-PermitLimit": "5",
  "RateLimiting-Auth-WindowMinutes": "1",
  "RateLimiting-PasswordReset-PermitLimit": "3",
  "RateLimiting-PasswordReset-WindowMinutes": "5",
  "RateLimiting-Api-PermitLimit": "100",
  "RateLimiting-Api-WindowMinutes": "1",
  "RateLimiting-Global-PermitLimit": "200",
  "RateLimiting-Global-WindowMinutes": "1"
}
```

## Response Format

When rate limit is exceeded:

**HTTP 429 Too Many Requests**
```json
{
  "error": "Too many requests. Please try again later.",
  "retryAfter": 60.0
}
```

**Headers:**
```
Retry-After: 60
```

## Common Scenarios

### More Restrictive Authentication

```json
{
  "RateLimiting-Auth-PermitLimit": "3"
}
```

### High-Traffic Production API

```json
{
  "RateLimiting-Api-PermitLimit": "500",
  "RateLimiting-Global-PermitLimit": "1000"
}
```

### Stricter Password Reset

```json
{
  "RateLimiting-PasswordReset-PermitLimit": "1",
  "RateLimiting-PasswordReset-WindowMinutes": "10"
}
```

## Adding Custom Policies

### 1. Define the Policy

In `RateLimitingExtensions.cs`:

```csharp
options.AddPolicy("upload", context =>
{
    var ip = GetClientIpAddress(context);
    return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = 10,
        Window = TimeSpan.FromMinutes(5),
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        QueueLimit = 0
    });
});
```

### 2. Apply to Endpoints

```csharp
[HttpPost("upload")]
[EnableRateLimiting("upload")]
public async Task<IActionResult> UploadFile(IFormFile file) => ...
```

## Exempting Endpoints

```csharp
[DisableRateLimiting]
public async Task<IActionResult> ExemptEndpoint() => ...
```

## Behind a Reverse Proxy

If behind nginx, Azure App Gateway, or Cloudflare, configure forwarded headers:

```csharp
// In Program.cs
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

// In middleware pipeline
app.UseForwardedHeaders();
app.UseRateLimiter();
```

## IP Detection

Rate limiting uses IP-based partitioning with `X-Forwarded-For` support:

```csharp
private static string GetClientIpAddress(HttpContext context)
{
    var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
    if (!string.IsNullOrEmpty(forwardedFor))
    {
        var ip = forwardedFor.Split(',').FirstOrDefault()?.Trim();
        if (!string.IsNullOrEmpty(ip))
            return ip;
    }
    return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
```

## Testing

```bash
# Make 6 login requests (limit is 5)
for i in {1..6}; do
  curl -X POST http://localhost:5000/api/Auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}' \
    -w "\nStatus: %{http_code}\n"
done
```

Expected: First 5 requests process normally, 6th returns HTTP 429.

## Security Considerations

- **Rate limits are per IP** – Distributed attacks can bypass individual limits
- **BCrypt adds natural limiting** – Password hashing work factor adds computational cost
- **Global limiter prevents resource exhaustion** – Even if policy limits are generous
- **Consider WAF/DDoS protection** – For infrastructure-level protection