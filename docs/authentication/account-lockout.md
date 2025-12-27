---
title: Account Lockout
parent: Authentication
nav_order: 4
---

# Account Lockout

Starbase includes a comprehensive account lockout system to protect against brute force attacks, credential stuffing, and unauthorized access attempts.

## Overview

The system implements intelligent lockout policies with exponential backoff and automatic unlocking.

**Multi-Layer Defense:**

1. **Automatic Lockout** – Locks accounts after repeated failed login attempts
2. **Exponential Backoff** – Increases lockout duration with continued failed attempts
3. **Manual Lockout** – Administrators can manually lock accounts for security reasons
4. **Login Attempt Tracking** – Detailed audit trail of all login attempts

## Configuration

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

| Setting | Default | Description |
|---------|---------|-------------|
| `FailedAttemptThreshold` | 5 | Number of failed attempts before lockout |
| `BaseLockoutDurationMinutes` | 5 | Initial lockout duration |
| `MaxLockoutDurationMinutes` | 60 | Maximum lockout duration (caps exponential growth) |
| `AttemptResetWindowMinutes` | 15 | Time window after which failed attempts reset |
| `EnableAccountLockout` | true | Master switch to enable/disable lockout feature |
| `TrackLoginAttempts` | true | Whether to track successful login attempts |

## Exponential Backoff

Lockout duration increases with each lockout event:

| Lockout # | Duration |
|-----------|----------|
| 1st | 5 minutes (base) |
| 2nd | 10 minutes |
| 3rd | 20 minutes |
| 4th | 40 minutes |
| 5th+ | 60 minutes (max) |

## Automatic Reset

- Failed attempt counter resets after 15 minutes of no attempts
- Accounts automatically unlock when lockout period expires
- Successful login immediately unlocks account and resets counter

## Response Examples

**Failed Login (Not Locked):**
```json
{
  "success": false,
  "message": "Invalid username or password",
  "statusCode": 401
}
```

**Failed Login (Account Locked):**
```json
{
  "success": false,
  "message": "Account is locked. Please try again later or contact support.",
  "statusCode": 401
}
```

## Integration with AuthService

```csharp
// Automatically called on login failure
await accountLockoutService.RecordFailedAttemptAsync(
    userId, username, ipAddress, userAgent, failureReason);

// Automatically called on successful login
await accountLockoutService.RecordSuccessfulLoginAsync(
    userId, username, ipAddress, userAgent);

// Check lockout status
var isLocked = await accountLockoutService.IsAccountLockedOutAsync(userId);
```

## Common Scenarios

### More Aggressive Lockout

```json
{
  "AccountLockout": {
    "FailedAttemptThreshold": 3,
    "MaxLockoutDurationMinutes": 30
  }
}
```

### Lenient Policy for Internal Apps

```json
{
  "AccountLockout": {
    "FailedAttemptThreshold": 10,
    "BaseLockoutDurationMinutes": 1,
    "MaxLockoutDurationMinutes": 10
  }
}
```

### Disable for Development

```json
{
  "AccountLockout": {
    "EnableAccountLockout": false
  }
}
```

## Maintenance

### Periodic Cleanup

```csharp
// Clean up login attempts older than 90 days
var deletedCount = await accountLockoutService.CleanupOldLoginAttemptsAsync(
    TimeSpan.FromDays(90));

// Process expired lockouts
var unlockedCount = await accountLockoutService.ProcessExpiredLockoutsAsync();
```

## Testing

```bash
# Make 6 failed login attempts (threshold is 5)
for i in {1..6}; do
  curl -X POST http://localhost:5000/api/Auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrongpassword"}' \
    -w "\nAttempt $i - Status: %{http_code}\n"
  sleep 1
done
```

Expected: First 5 attempts return 401, 6th returns 401 with lockout message.

## Security Best Practices

1. **Monitor failed attempts** – Set up alerts for accounts with repeated failures
2. **Review manual lockouts** – Audit administrator-initiated lockouts regularly
3. **Analyze patterns** – Use login attempt data to identify attack patterns
4. **Coordinate with rate limiting** – Ensure rate limits complement lockout policies
5. **Consider IP-based rules** – Add IP-based blocking for persistent attackers
6. **Regular maintenance** – Clean up old data to maintain performance