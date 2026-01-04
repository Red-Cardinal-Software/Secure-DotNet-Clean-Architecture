# API Examples

Ready-to-use API examples for testing and exploring Starbase endpoints.

## Quick Start

### Option 1: Postman

1. Import `Starbase.postman_collection.json` into Postman
2. Run the **Initial Setup** request (only works once)
3. Run **Login** to authenticate
4. Tokens are automatically saved to collection variables

### Option 2: VS Code REST Client

1. Install the [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) extension
2. Open any `.http` file
3. Select environment: `Ctrl+Alt+E` (or `Cmd+Alt+E` on Mac)
4. Click "Send Request" above any request

### Option 3: JetBrains IDEs (Rider, IntelliJ)

1. Open any `.http` file
2. Select environment from the dropdown
3. Click the play button next to any request

## Files

| File | Description |
|------|-------------|
| `Starbase.postman_collection.json` | Complete Postman collection with all endpoints |
| `http-client.env.json` | Environment variables for .http files |
| `auth.http` | Login, logout, token refresh, password reset |
| `mfa.http` | MFA configuration (TOTP, email) |
| `webauthn.http` | WebAuthn/FIDO2 credential management |
| `push-mfa.http` | Push notification MFA |
| `users.http` | User management (admin) |
| `audit.http` | Audit log queries and verification |
| `health.http` | Health check endpoints |

## Environment Configuration

Edit `http-client.env.json` to configure your environments:

```json
{
    "dev": {
        "baseUrl": "http://localhost:5000",
        "username": "admin@example.com",
        "password": "YourSecurePassword123!"
    }
}
```

## Authentication Flow

1. **First Run (No Users)**
   ```
   POST /api/v1/setup
   ```
   Creates initial admin user. Only works once.

2. **Login**
   ```
   POST /api/v1/auth/login
   ```
   Returns `accessToken` and `refreshToken` (or MFA challenge).

3. **Use Access Token**
   ```
   Authorization: Bearer <accessToken>
   ```

4. **Refresh Token**
   ```
   POST /api/v1/auth/refresh
   ```
   When access token expires, get a new one.

## Rate Limits

| Endpoint Type | Default Limit |
|---------------|---------------|
| Login/Refresh | 5/minute |
| Password Reset | 3/5 minutes |
| MFA Setup | 10/5 minutes |
| General API | 100/minute |
| Health Checks | 30/minute |

Rate limit exceeded returns `429 Too Many Requests` with `Retry-After` header.

## Common Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Validation error |
| 401 | Not authenticated |
| 403 | Insufficient privileges |
| 404 | Not found (or setup already complete) |
| 429 | Rate limit exceeded |
| 500 | Server error |

## Privileges Required

| Endpoint Category | Required Privilege |
|-------------------|-------------------|
| View all users | `UserManagement.View` |
| View basic users | `UserManagement.ViewBasic` |
| Create users | `UserManagement.Create` |
| Update users | `UserManagement.Update` |
| Deactivate users | `UserManagement.Deactivate` |
| View audit logs | `Audit.View` |
| Verify audit ledger | `Audit.Verify` |
| View archives | `Audit.ViewArchives` |
| System metrics | `SystemAdministration.Metrics` |
| Org MFA metrics | `OrganizationManagement.MfaMetrics` |