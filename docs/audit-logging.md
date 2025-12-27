---
title: Audit Logging
nav_order: 6
---

# Audit Logging

Starbase includes an enterprise-grade audit logging system designed for compliance, security monitoring, and forensic analysis.

## Architecture

The audit system uses a **dual strategy**:

| Mechanism | Purpose | Captures |
|-----------|---------|----------|
| **Entity Interceptor** | Tracks data changes | User created/updated, Role changes, MFA enabled |
| **Domain Events** | Tracks business actions | Login attempts, Logout, Token refresh, Password reset |

## Key Features

- **Hash Chain Integrity** – Each entry includes a SHA-256 hash of the previous entry
- **SQL Server Ledger Tables** – Cryptographic verification (SQL Server 2022+)
- **Monthly Partitioning** – Automatic partition management for performance
- **Configurable Processing** – Sync (reliable) or Batched (high-performance)
- **Domain Event Integration** – MediatR-based extensibility

## Configuration

```json
{
  "Audit": {
    "ProcessingMode": "Sync",
    "BatchSize": 100,
    "FlushIntervalMs": 5000,
    "EnableConsoleLogging": false
  },
  "AuditArchive": {
    "Enabled": true,
    "CheckInterval": "01:00:00",
    "AddPartitionOnDay": 25,
    "ArchiveOnDay": 5,
    "MonthsToKeepBeforeArchive": 2,
    "AutoPurgeAfterArchive": true,
    "MinWaitBeforePurge": "1.00:00:00",
    "RetentionPolicy": "default"
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `ProcessingMode` | Sync | `Sync` for reliability, `Batched` for throughput |
| `BatchSize` | 100 | Entries per batch (Batched mode) |
| `FlushIntervalMs` | 5000 | Max time before flush (Batched mode) |
| `AddPartitionOnDay` | 25 | Day of month to add next partition |
| `MonthsToKeepBeforeArchive` | 2 | Months before archiving |

## Processing Modes

### Sync Mode (Default)

- Audit entry written immediately with each event
- Transactional consistency – entry guaranteed if action succeeds
- **Best for**: Compliance requirements, smaller deployments

### Batched Mode

- Events queued in-memory using `Channel<T>`
- Background service flushes batches to database
- **Best for**: High-throughput applications, eventual consistency acceptable

```json
{
  "Audit": {
    "ProcessingMode": "Batched",
    "BatchSize": 100,
    "FlushIntervalMs": 5000
  }
}
```

!!! warning "Batched Mode Trade-off"
    In batched mode, audit entries can be lost if the application crashes before flush.

## Domain Events

Authentication events captured via MediatR:

| Event | Trigger | Data Captured |
|-------|---------|---------------|
| `LoginAttemptedEvent` | Login success/failure | UserId, Username, IP, Success, FailureReason |
| `LogoutEvent` | User logout | UserId, Username |
| `TokenRefreshedEvent` | Token refresh | UserId, Username, IP |
| `PasswordResetRequestedEvent` | Password reset request | UserId, Email, IP |

### Extensibility

Add custom handlers for SIEM integration, alerts, etc.:

```csharp
public class SiemNotificationHandler : INotificationHandler<LoginAttemptedEvent>
{
    private readonly ISiemClient _siemClient;

    public SiemNotificationHandler(ISiemClient siemClient)
    {
        _siemClient = siemClient;
    }

    public async Task Handle(LoginAttemptedEvent notification, CancellationToken cancellationToken)
    {
        if (!notification.Success)
        {
            await _siemClient.SendSecurityEventAsync(new SecurityEvent
            {
                Type = "FailedLogin",
                Username = notification.Username,
                IpAddress = notification.IpAddress,
                Timestamp = notification.OccurredAt
            });
        }
    }
}
```

## Entity Auditing

Entities marked with `[Audited]` are automatically tracked:

```csharp
[Audited]
public class Role : IEquatable<Role>
{
    // Changes to this entity are automatically audited
}
```

**Currently Audited Entities:**

- `Organization` – Org lifecycle and settings
- `Role` – Role changes
- `Privilege` – Permission changes
- `AccountLockout` – Lockout state changes
- `MfaMethod` – MFA configuration changes
- `MfaPushDevice` – Push device registration
- `WebAuthnCredential` – WebAuthn credential lifecycle

## Audit Ledger Schema

| Column | Description |
|--------|-------------|
| `SequenceNumber` | Monotonically increasing sequence |
| `EventId` | Unique event identifier |
| `OccurredAt` | Event timestamp (partition key) |
| `Hash` | SHA-256 hash of entry |
| `PreviousHash` | Hash of previous entry (chain integrity) |
| `UserId` / `Username` | Acting user |
| `IpAddress` / `UserAgent` | Request context |
| `EventType` | Category (Authentication, DataChange, etc.) |
| `Action` | Specific action (LoginSuccess, Create, Update) |
| `EntityType` / `EntityId` | Affected entity |
| `OldValues` / `NewValues` | JSON of changed values |
| `Success` / `FailureReason` | Outcome details |

## Partition Management

Partitions are managed automatically:

1. **Initial Setup** – Migration creates 12 months back + 24 months forward
2. **Runtime** – Background service adds new partitions monthly
3. **Archival** – Old partitions archived to blob storage
4. **Purge** – Archived partitions purged after verification

### Manual Operations

```csharp
// Add partition boundary
await auditArchiver.AddPartitionBoundaryAsync(new DateTime(2027, 1, 1));

// Archive a partition
var result = await auditArchiver.ArchivePartitionAsync(
    new DateTime(2024, 1, 1),
    archivedBy: "admin",
    retentionPolicy: "7-year");
```

## Verification

Verify audit chain integrity:

```csharp
var verification = await auditLedger.VerifyChainIntegrityAsync(
    fromSequence: 1,
    toSequence: 1000);

if (!verification.IsValid)
{
    _logger.LogCritical("Audit chain tampered at sequence {Seq}",
        verification.FirstInvalidSequence);
}
```

## Compliance Considerations

### SOC 2 / HIPAA

- All authentication events captured
- Data changes include before/after values
- Hash chain provides tamper evidence
- SQL Server Ledger provides database-level verification

### GDPR

- Audit entries include user context for access tracking
- Archival system supports retention policies
- Consider data export requirements for audit data

## Best Practices

1. **Use Sync mode for compliance-critical deployments**
2. **Regularly verify hash chain integrity**
3. **Archive old partitions to immutable storage**
4. **Monitor for audit chain breaks**
5. **Include audit data in backup strategy**
6. **Set up alerts for suspicious patterns**