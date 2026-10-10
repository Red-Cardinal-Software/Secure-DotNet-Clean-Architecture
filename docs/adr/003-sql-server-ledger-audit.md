# ADR-003: Database-Level Immutable Audit

## Status
Accepted

## Context

Audit logging is critical for security and compliance. Requirements:

1. **Immutability** - Audit records cannot be modified or deleted (HIPAA, SOC 2, PCI-DSS)
2. **Tamper evidence** - Any tampering should be detectable
3. **Performance** - Audit writes shouldn't significantly impact request latency
4. **Queryability** - Need to search and analyze audit data efficiently
5. **Retention** - Different compliance frameworks require 1-7 year retention

Common approaches:
- **Application-level append-only** - Soft deletes, no UPDATE permissions
- **Event sourcing** - Store events, derive state
- **Blockchain/distributed ledger** - External immutability guarantees
- **Database-native immutability** - SQL Server Ledger, Oracle Blockchain Tables, PostgreSQL append-only
- **Write-once storage** - Blob storage with immutability policies

**Each supported database enforces append-only at the database layer; the mechanism differs per provider:**

| Database | Immutability Feature | Version Required |
|----------|---------------------|------------------|
| SQL Server | Ledger table (`LEDGER = ON (APPEND_ONLY = ON)`) | 2022+ |
| PostgreSQL | `BEFORE UPDATE/DELETE` trigger + `REVOKE` | 14+ |
| Oracle | `BEFORE UPDATE/DELETE` trigger | 19c+ |

> **Why triggers on PostgreSQL/Oracle rather than their "native" features.** PostgreSQL has no ledger
> table, and RLS (an earlier idea) is the wrong tool — a `FOR ALL USING(false)` policy also blocks
> `SELECT`, so the audit log becomes unreadable. Oracle *does* have Blockchain Tables, but their
> retention (`NO DELETE`/`NO DROP UNTIL ...`) makes rows and the table itself un-removable for the
> retention window, which conflicts with the partition archive/purge workflow (SQL Server's ledger has
> the same limitation — it cannot be partition-switched). A `BEFORE UPDATE/DELETE` trigger blocks row
> modification on both while leaving `INSERT` and `DROP PARTITION` (archival) intact, and it is applied
> by the shipped migration so it needs no manual setup.

## Decision

We will enforce append-only at the database layer with a provider-specific mechanism, and layer the
application hash chain on top for cross-provider tamper *detection*.

### SQL Server (Ledger table)
```sql
CREATE TABLE [Audit].[AuditLedger] (...)
  WITH (LEDGER = ON (APPEND_ONLY = ON));
```

### PostgreSQL / Oracle (append-only trigger)
```sql
-- PostgreSQL
CREATE OR REPLACE FUNCTION "Audit".audit_ledger_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'AuditLedger is append-only; % is not permitted', TG_OP; END; $$;
CREATE TRIGGER audit_ledger_no_modify
  BEFORE UPDATE OR DELETE ON "Audit"."AuditLedger"
  FOR EACH ROW EXECUTE FUNCTION "Audit".audit_ledger_append_only();

-- Oracle
CREATE OR REPLACE TRIGGER "AUDIT_LEDGER_APPEND_ONLY"
  BEFORE UPDATE OR DELETE ON "AuditLedger"
BEGIN RAISE_APPLICATION_ERROR(-20001, 'AuditLedger is append-only'); END;
```

> **Implementation notes.** The provider is selected by the `DatabaseProvider` template switch. Each
> provider ships its own EF migration set (SQL Server in `Migrations/`; PostgreSQL and Oracle are moved
> in from `Migrations.PostgreSql`/`Migrations.Oracle` at generation time), each with the trigger/ledger
> DDL baked in. On Oracle, schemas are database users, so all tables are mapped into the single
> connecting schema rather than one user per logical schema.

**Key design choices**:
- **Append-only enforcement** - INSERT only, no UPDATE/DELETE at database level
- **Cryptographic verification** - Application-layer hash chain for tamper detection (all databases)
- **Monthly partitioning** - Partition switching for efficient archival
- **EF Core interceptor** - Automatic audit capture on entity changes

**Architecture**:
```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│ EF Core      │────▶│ AuditInterceptor│────▶│ AuditLedger      │
│ SaveChanges  │     │ (captures diff) │     │ (append-only)    │
└──────────────┘     └─────────────────┘     └──────────────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │ Archive Service  │
                                             │ (blob storage)   │
                                             └──────────────────┘
```

**Defense in Depth**:

All databases share a fundamental limitation: superusers/sysadmins can bypass any protection. Our security model addresses this with layered defenses:

| Layer | Protection | Threat Mitigated |
|-------|------------|------------------|
| Database | Append-only (Ledger on SQL Server; trigger on PostgreSQL/Oracle) | Normal users, application bugs, regular DBAs |
| Application | Hash chain verification | Tampering detection (even by superusers) |
| Archive | Immutable blob storage (WORM) | Long-term proof, database destruction |
| Access Control | No superuser access for app accounts | Reduces attack surface |

The application-layer hash chain ensures **all three databases have equivalent tamper detection**. Database-native features provide prevention; the hash chain provides detection.

## Consequences

### Positive

- **True immutability** - Database enforces append-only for normal users and DBAs
- **Cryptographic integrity** - Application-layer hash chain detects tampering (all databases)
- **Defense in depth** - Database-level prevention + application-level detection
- **Supports compliance** - Provides technical controls for HIPAA, SOC 2, PCI-DSS audit requirements (see note below)
- **Multi-database support** - Generates a runnable, append-only audit ledger for SQL Server,
  PostgreSQL, and Oracle, each with a provider-appropriate mechanism and its own migration set
- **Native features** - No external dependencies, works with existing tooling

> **Compliance Note**: This implementation provides *technical controls* that support compliance frameworks. Full compliance requires additional administrative controls (policies, training, incident response), physical controls, risk assessments, and legal agreements (e.g., BAAs for HIPAA). Technical controls alone do not constitute compliance.

### Negative

- **Minimum version requirements** - SQL Server 2022+ (ledger); PostgreSQL 14+, Oracle 19c+ (triggers)
- **Storage growth** - Cannot delete old audit records (must archive)
- **Slightly slower inserts** - Hash chain computation adds small overhead
- **Superuser limitation** - All databases can be bypassed by superuser/sysadmin (mitigated by hash chain detection)

### Neutral

- **Sensitive data masking** - `[SensitiveData]` attribute masks values before logging
- **Sync vs Batch modes** - Configurable; sync is reliable, batch is performant
- **Archive to blob storage** - Background service archives old partitions

## Implementation Details

### Audited Entities
Mark entities for auditing:
```csharp
[Audited(EntityTypeName = "User", IncludeNewValues = true, IncludeOldValues = true)]
public class AppUser { }
```

### Sensitive Data Masking
```csharp
[SensitiveData]
public string Password { get; set; }  // Logged as "***REDACTED***"
```

### Partition Strategy
- New partition created on 25th of each month
- Archive runs on 5th, moves data older than configured retention
- Partition switching is O(1), not O(n)

## Alternatives Considered

### Application-Level Append-Only
Rejected because:
- DBAs could still run `DELETE` statements
- No cryptographic verification
- Harder to prove immutability to auditors

### Event Sourcing
Rejected because:
- Significant architectural change for existing CRUD applications
- Complexity overhead for teams unfamiliar with the pattern
- Overkill when we just need audit trail, not full event replay

### External Blockchain
Rejected because:
- Massive complexity and operational overhead
- Latency impact on every audited operation
- Not necessary when database-native features provide similar guarantees

### Azure Immutable Blob Storage
Considered for archive layer:
- Good for long-term retention
- Currently using file system for development; production would use cloud storage
- Could add as enhancement for production deployments

## References

- [SQL Server Ledger Documentation](https://docs.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-overview)
- [Oracle Blockchain Tables](https://docs.oracle.com/en/database/oracle/oracle-database/21/admin/managing-tables.html#GUID-43470B0C-DE4A-4640-9278-B5E3C4E949AA)
- [PostgreSQL Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [HIPAA Audit Controls §164.312(b)](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)