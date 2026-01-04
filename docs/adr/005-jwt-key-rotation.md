# ADR-005: JWT Signing Key Rotation

## Status
Accepted

## Context

JWT signing keys need to be rotated periodically for security:

1. **Key compromise risk** - Longer a key exists, higher chance of exposure
2. **Compliance requirements** - SOC 2, PCI-DSS require key rotation policies
3. **Best practices** - NIST recommends cryptographic key rotation
4. **Zero-downtime** - Rotation must not invalidate active user sessions

Challenges:
- Rotating keys invalidates all existing tokens
- Distributed systems may have key sync delays
- Cloud providers have different secret management APIs

## Decision

We will implement **automatic JWT signing key rotation** with an overlap window:

```
Timeline:
├── Key A active ──────────────────────┤
│                    ├── Key B active ─────────────────────┤
│                    │                  ├── Key C active ──────▶
│   ◀── overlap ──▶  │   ◀── overlap ──▶│
```

**Key design choices**:

### 1. Multiple Valid Keys
Tokens signed with previous keys remain valid during overlap:
```csharp
IssuerSigningKeyResolver = (token, securityToken, kid, params) =>
{
    var keys = keyProvider.GetValidationKeysAsync().Result;
    return keys.Select(k => k.Key);  // All keys in overlap window
};
```

### 2. Pluggable Key Providers
```csharp
public interface ISigningKeyProvider
{
    Task<SigningKeyInfo> GetCurrentSigningKeyAsync();
    Task<IReadOnlyList<SigningKeyInfo>> GetValidationKeysAsync();
    Task RotateKeyAsync();
}
```

Implementations:
- `LocalSigningKeyProvider` - Development (file-based)
- `AzureKeyVaultSigningKeyProvider` - Azure Key Vault
- `AwsSecretsManagerSigningKeyProvider` - AWS Secrets Manager
- `GcpSecretManagerSigningKeyProvider` - GCP Secret Manager

### 3. Background Rotation Service
```csharp
public class SigningKeyRotationBackgroundService : BackgroundService
{
    // Checks rotation schedule, rotates when due
    // Configurable interval and overlap window
}
```

### Configuration
```json
{
  "SigningKeyRotation": {
    "Enabled": true,
    "RotationIntervalDays": 30,
    "KeyOverlapWindowDays": 7,
    "MaximumActiveKeys": 3
  }
}
```

## Consequences

### Positive

- **Zero-downtime rotation** - Users don't get logged out during rotation
- **Automatic** - No manual intervention required
- **Cloud-native** - Works with Azure, AWS, GCP secret managers
- **Compliance-friendly** - Meets SOC 2/PCI-DSS rotation requirements
- **Configurable** - Interval and overlap window adjustable

### Negative

- **Complexity** - More moving parts than static key
- **Multiple keys to validate** - Slightly more work per token validation
- **Cloud dependency** - Production requires cloud secret manager
- **Clock sync** - Servers must have synchronized clocks

### Neutral

- **Development uses local provider** - File-based, no cloud setup needed
- **Overlap means more valid keys** - 2-3 keys valid simultaneously during transition
- **Background service pattern** - Follows .NET hosted service conventions

## Token Validation Flow

```
1. Request arrives with JWT
2. JwtBearerHandler extracts token
3. IssuerSigningKeyResolver called
4. SigningKeyProvider returns all valid keys (current + previous)
5. Token validated against each key until one succeeds
6. If none succeed, 401 Unauthorized
```

## Rotation Flow

```
1. Background service wakes up (CheckIntervalMinutes)
2. Checks if current key age > RotationIntervalDays
3. If yes:
   a. Generate new key
   b. Store in cloud secret manager
   c. Mark as current
   d. Previous key remains valid for KeyOverlapWindowDays
4. Prune keys older than overlap window
```

## Alternatives Considered

### No Rotation (Static Key)
Rejected because:
- Security risk if key is compromised
- Doesn't meet compliance requirements
- Industry best practice is to rotate

### Token Refresh Only
Rejected because:
- Doesn't address key compromise scenarios
- Refresh tokens still need to validate against signing key
- Rotation is complementary, not alternative, to refresh

### Asymmetric Keys (RS256)
Considered and supported, but symmetric (HS256) is default because:
- Simpler key management
- Faster signing/validation
- Sufficient for API-to-API scenarios
- RS256 can be configured if needed (for public key distribution)

### External Identity Provider (Auth0, Okta)
Out of scope because:
- Template should work standalone
- Users can integrate external IdP if desired
- Adds external dependency and cost

## References

- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 7517 - JSON Web Key](https://datatracker.ietf.org/doc/html/rfc7517)
- [Azure Key Vault Key Rotation](https://docs.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation)