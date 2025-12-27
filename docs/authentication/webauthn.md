---
title: WebAuthn & Passkeys
parent: Authentication
nav_order: 3
---

# WebAuthn & Passkeys

Starbase includes production-ready WebAuthn/FIDO2 support using the Fido2.NetLib library.

## Supported Authenticators

| Type | Examples |
|------|----------|
| **Platform authenticators** | TouchID, FaceID, Windows Hello, Android biometrics |
| **Cross-platform authenticators** | YubiKey, Titan Security Key, SoloKey |
| **Passkeys** | iCloud Keychain, Google Password Manager, 1Password |

## Configuration

```json
{
  "WebAuthn": {
    "Origins": ["https://yourdomain.com", "https://localhost:5000"],
    "RelyingPartyName": "Your App Name",
    "RelyingPartyId": "yourdomain.com",
    "TimestampDriftTolerance": 300000
  }
}
```

| Setting | Description |
|---------|-------------|
| `Origins` | Allowed origins for WebAuthn ceremonies |
| `RelyingPartyName` | Display name shown to users |
| `RelyingPartyId` | Domain identifier (usually your domain) |
| `TimestampDriftTolerance` | Clock drift tolerance in milliseconds |

## Registration Flow

### 1. Start Registration

```bash
POST /api/mfa/webauthn/register/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "displayName": "My Security Key"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "challenge": "base64-encoded-challenge",
    "rpId": "yourdomain.com",
    "rpName": "Your App Name",
    "userId": "base64-encoded-user-id",
    "userName": "user@example.com",
    "userDisplayName": "John Doe",
    "pubKeyCredParams": [...],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "residentKey": "preferred",
      "userVerification": "preferred"
    }
  }
}
```

### 2. Complete Registration

After the browser/authenticator creates the credential:

```bash
POST /api/mfa/webauthn/register/complete
Authorization: Bearer <token>
Content-Type: application/json

{
  "challenge": "original-challenge",
  "attestationResponse": {
    "id": "credential-id",
    "rawId": "base64-raw-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64-client-data",
      "attestationObject": "base64-attestation"
    }
  },
  "credentialName": "My YubiKey"
}
```

## Authentication Flow

### 1. Start Authentication

```bash
POST /api/mfa/webauthn/authenticate/start
Content-Type: application/json

{
  "userId": "user-guid"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "challenge": "base64-encoded-challenge",
    "rpId": "yourdomain.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "credential-id-1"
      }
    ],
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

### 2. Complete Authentication

```bash
POST /api/mfa/webauthn/authenticate/complete
Content-Type: application/json

{
  "credentialId": "credential-id",
  "challenge": "original-challenge",
  "assertionResponse": {
    "id": "credential-id",
    "rawId": "base64-raw-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64-client-data",
      "authenticatorData": "base64-auth-data",
      "signature": "base64-signature",
      "userHandle": "base64-user-handle"
    }
  }
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mfa/webauthn/register/start` | POST | Begin credential registration |
| `/api/mfa/webauthn/register/complete` | POST | Complete registration |
| `/api/mfa/webauthn/authenticate/start` | POST | Begin authentication |
| `/api/mfa/webauthn/authenticate/complete` | POST | Complete authentication |
| `/api/mfa/webauthn/credentials` | GET | List user's credentials |
| `/api/mfa/webauthn/credentials/{id}` | DELETE | Remove a credential |

## Security Features

### FIDO2 Compliance

- Full FIDO2/WebAuthn specification support
- Cryptographic verification of assertions
- No shared secrets - public key cryptography

### Clone Detection

- Sign count tracking detects cloned authenticators
- Warnings logged if sign count doesn't increment properly

### Hardware Attestation

- Optional verification of authenticator make/model
- Useful for high-security environments requiring specific hardware

## Frontend Integration

Example JavaScript for WebAuthn registration:

```javascript
// Start registration
const startResponse = await fetch('/api/mfa/webauthn/register/start', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${token}` }
});
const options = await startResponse.json();

// Create credential
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: base64ToArrayBuffer(options.data.challenge),
    rp: { id: options.data.rpId, name: options.data.rpName },
    user: {
      id: base64ToArrayBuffer(options.data.userId),
      name: options.data.userName,
      displayName: options.data.userDisplayName
    },
    pubKeyCredParams: options.data.pubKeyCredParams,
    timeout: options.data.timeout,
    attestation: options.data.attestation
  }
});

// Complete registration
await fetch('/api/mfa/webauthn/register/complete', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    challenge: options.data.challenge,
    attestationResponse: {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64(credential.response.attestationObject)
      }
    },
    credentialName: 'My Security Key'
  })
});
```

## Best Practices

1. **Encourage passkey adoption** - More secure than TOTP
2. **Support multiple credentials** - Users may have backup keys
3. **Provide clear UI** - WebAuthn requires user interaction
4. **Test on multiple browsers** - Implementation varies slightly
5. **Have fallback methods** - Not all users have compatible devices