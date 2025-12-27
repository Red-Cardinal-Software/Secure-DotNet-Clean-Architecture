---
title: JWT Key Rotation
parent: Security
nav_order: 3
---

# JWT Signing Key Rotation

Starbase supports automatic JWT signing key rotation with zero-downtime token validation. Keys are stored in cloud secrets managers (Azure Key Vault, AWS Secrets Manager, or GCP Secret Manager) and rotated on a configurable schedule.

## Why Rotate Keys?

- **Limit exposure** – If a key is compromised, damage is limited to the rotation window
- **Compliance** – Many security frameworks require periodic key rotation (SOC2, PCI-DSS, HIPAA)
- **Best practice** – Cryptographic hygiene for production systems

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                 Background Rotation Service                      │
│                   (checks every 60 minutes)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Key age > 30 days? │
                   └─────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               │ No                          │ Yes
               ▼                             ▼
             Sleep                    Generate new key
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Cloud Secrets Manager                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ {                                                          │ │
│  │   "keys": [                                                │ │
│  │     { "keyId": "key-20250121", "isPrimary": true },       │ │
│  │     { "keyId": "key-20241221", "isPrimary": false },      │ │  ← Old keys still
│  │     { "keyId": "key-20241121", "isPrimary": false }       │ │    valid for 7 days
│  │   ]                                                        │ │
│  │ }                                                          │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Token Validation                              │
│                                                                  │
│   Incoming token → Try ALL valid keys → Accept if any matches   │
│                                                                  │
│   • New tokens signed with primary key                          │
│   • Old tokens (previous keys) still validate during overlap    │
│   • Zero downtime during rotation                               │
└─────────────────────────────────────────────────────────────────┘
```

**Key insight:** During rotation, multiple keys are valid simultaneously. Tokens signed with the previous key continue to work until that key expires.

## Configuration

```json
{
  "SigningKeyRotation": {
    "Enabled": true,
    "RotationIntervalDays": 30,
    "KeyOverlapWindowDays": 7,
    "MaximumActiveKeys": 3,
    "CheckIntervalMinutes": 60,
    "SecretName": "jwt-signing-keys",
    "Algorithm": "HS256",
    "KeySizeBytes": 64
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `Enabled` | `false` | Enable automatic rotation (disabled by default for safety) |
| `RotationIntervalDays` | `30` | How often to rotate keys |
| `KeyOverlapWindowDays` | `7` | How long old keys remain valid after rotation |
| `MaximumActiveKeys` | `3` | Maximum keys kept (current + previous versions) |
| `CheckIntervalMinutes` | `60` | How often the background service checks |
| `SecretName` | `jwt-signing-keys` | Name of the secret in your cloud provider |
| `KeySizeBytes` | `64` | Key size (64 bytes = 512 bits) |

## Cloud Provider Setup

### Azure Key Vault

1. **Create a Key Vault** (if you don't have one):
   ```bash
   az keyvault create --name myapp-vault --resource-group myapp-rg --location eastus
   ```

2. **Grant access** to your application:
   ```bash
   # For Managed Identity (recommended)
   az keyvault set-policy --name myapp-vault \
     --object-id <your-app-managed-identity-id> \
     --secret-permissions get set

   # For local development with Azure CLI
   az keyvault set-policy --name myapp-vault \
     --upn your-email@company.com \
     --secret-permissions get set
   ```

3. **Configure appsettings.json**:
   ```json
   {
     "AzureKeyVault": {
       "VaultUri": "https://myapp-vault.vault.azure.net/"
     },
     "SigningKeyRotation": {
       "Enabled": true,
       "SecretName": "jwt-signing-keys"
     }
   }
   ```

### AWS Secrets Manager

1. **Create IAM policy** for Secrets Manager access:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "secretsmanager:GetSecretValue",
           "secretsmanager:PutSecretValue",
           "secretsmanager:CreateSecret"
         ],
         "Resource": "arn:aws:secretsmanager:*:*:secret:jwt-signing-keys*"
       }
     ]
   }
   ```

2. **Configure appsettings.json**:
   ```json
   {
     "AwsSecretsManager": {
       "Region": "us-east-1"
     },
     "SigningKeyRotation": {
       "Enabled": true,
       "SecretName": "myapp/jwt-signing-keys"
     }
   }
   ```

### GCP Secret Manager

1. **Enable the Secret Manager API**:
   ```bash
   gcloud services enable secretmanager.googleapis.com
   ```

2. **Grant access** to your service account:
   ```bash
   gcloud projects add-iam-policy-binding myproject \
     --member="serviceAccount:myapp@myproject.iam.gserviceaccount.com" \
     --role="roles/secretmanager.secretAccessor"

   gcloud projects add-iam-policy-binding myproject \
     --member="serviceAccount:myapp@myproject.iam.gserviceaccount.com" \
     --role="roles/secretmanager.secretVersionAdder"
   ```

3. **Configure appsettings.json**:
   ```json
   {
     "GcpSecretManager": {
       "ProjectId": "myproject"
     },
     "SigningKeyRotation": {
       "Enabled": true,
       "SecretName": "jwt-signing-keys"
     }
   }
   ```

## Development Mode

In development, key rotation uses the `LocalSigningKeyProvider` which:

- Uses the static key from `AppSettings:JwtSigningKey`
- Does **not** support rotation (throws if rotation is attempted)
- Logs a warning that rotation requires a cloud provider

This is intentional – local development doesn't need rotation complexity.

## Monitoring

The rotation service logs key events:

```
[INF] Signing key rotation background service started. Rotation interval: 30 days
[INF] Starting key rotation...
[INF] Key rotation complete. New key ID: key-20250121-a1b2c3d4, active keys: 3
```

**Key metrics to monitor:**

| Log Pattern | Meaning |
|-------------|---------|
| `Key rotation complete` | Successful rotation |
| `Key rotation due` | Rotation triggered by age |
| `No primary key found` | First-time initialization |
| `Failed to rotate signing key` | Error – manual intervention needed |

## Multi-Instance Deployments

Key rotation is safe for multi-instance deployments:

1. **Only one instance rotates** – The cloud secrets manager acts as the coordination point
2. **All instances read same keys** – Keys are cached for 5 minutes, then refreshed
3. **No race conditions** – Rotation uses optimistic concurrency in the secrets manager

If two instances check simultaneously:
- First one to rotate succeeds
- Second one sees the new key on next refresh
- Tokens remain valid throughout

## Manual Rotation

To force an immediate rotation, you can:

1. **Via configuration** – Set `RotationIntervalDays` to `0` temporarily
2. **Via code** – Call `ISigningKeyProvider.RotateKeyAsync()` from a management endpoint
3. **Via cloud console** – Delete the secret and let the app recreate it

## Fallback Behavior

If the cloud secrets manager is unavailable:

- **Token signing** – Uses the last cached primary key
- **Token validation** – Uses all cached valid keys
- **Cache duration** – 5 minutes before retry

The application logs errors but continues operating with cached keys.

## Security Considerations

- **Never log key material** – Only key IDs are logged
- **Use managed identity** – Avoid storing cloud credentials in config
- **Separate environments** – Use different secrets per environment
- **Audit access** – Enable cloud provider audit logging for the secrets
- **Key overlap window** – Should be longer than your longest-lived token

## Disabling Rotation

To use a static key (not recommended for production):

```json
{
  "SigningKeyRotation": {
    "Enabled": false
  },
  "AppSettings": {
    "JwtSigningKey": "YourStaticKeyHere..."
  }
}
```

The application will use `AppSettings:JwtSigningKey` directly without rotation.