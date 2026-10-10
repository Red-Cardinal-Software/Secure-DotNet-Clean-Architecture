using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditLedger : Migration
    {
        /// <summary>
        /// The audit ledger is created with raw, provider-specific DDL rather than the fluent
        /// migration API, because two things it needs cannot be expressed provider-neutrally:
        /// <list type="bullet">
        /// <item><b>Append-only enforcement</b> - the mechanism differs per database:
        /// SQL Server uses a native append-only Ledger table; PostgreSQL and Oracle use a
        /// BEFORE UPDATE/DELETE trigger (plus a REVOKE on PostgreSQL). The template's
        /// <c>DatabaseProvider</c> switch selects which branch is emitted.</item>
        /// <item><b>Range partitioning</b> on <c>OccurredAt</c> - declared at CREATE TABLE time,
        /// with provider-specific syntax.</item>
        /// </list>
        /// Note on the trigger approach (PostgreSQL/Oracle): a BEFORE UPDATE/DELETE trigger blocks
        /// row modification but does NOT block <c>DROP/DETACH PARTITION</c> (that is DDL), so the
        /// archive-then-purge workflow still works. SQL Server's Ledger table is stronger but
        /// cannot be partition-switched, so on SQL Server the archive/purge path is not usable while
        /// LEDGER is on - see ADR-003.
        /// </summary>
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "Audit");

            // Small, non-partitioned bookkeeping table. Column types are left to the provider's
            // type mapper (no hardcoded "datetime2"/"nvarchar" strings) so it is portable.
            migrationBuilder.CreateTable(
                name: "AuditArchiveManifest",
                schema: "Audit",
                columns: table => new
                {
                    Id = table.Column<Guid>(nullable: false),
                    PartitionBoundary = table.Column<DateTime>(nullable: false),
                    FirstSequenceNumber = table.Column<long>(nullable: false),
                    LastSequenceNumber = table.Column<long>(nullable: false),
                    RecordCount = table.Column<long>(nullable: false),
                    FirstRecordHash = table.Column<string>(maxLength: 64, nullable: false),
                    LastRecordHash = table.Column<string>(maxLength: 64, nullable: false),
                    LedgerDigest = table.Column<string>(nullable: false),
                    ArchiveUri = table.Column<string>(maxLength: 2048, nullable: false),
                    ArchiveBlobHash = table.Column<string>(maxLength: 64, nullable: false),
                    ArchiveSizeBytes = table.Column<long>(nullable: false),
                    ArchivedAt = table.Column<DateTime>(nullable: false),
                    ArchivedBy = table.Column<string>(maxLength: 256, nullable: false),
                    PurgedAt = table.Column<DateTime>(nullable: true),
                    RetentionPolicy = table.Column<string>(maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditArchiveManifest", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditArchiveManifest_PartitionBoundary",
                schema: "Audit",
                table: "AuditArchiveManifest",
                column: "PartitionBoundary",
                unique: true);

            // Partitioned, append-only AuditLedger. One statement per array element so the same
            // loop works on every provider (Oracle rejects multi-statement batches).
            var months = GeneratePartitionMonths(monthsBack: 12, monthsForward: 24);

            ////#if (UsePostgreSql)
            //foreach (var statement in BuildPostgreSqlAuditLedger(months))
            //{
            //    migrationBuilder.Sql(statement);
            //}
            ////#elseif (UseOracle)
            //foreach (var statement in BuildOracleAuditLedger(months))
            //{
            //    migrationBuilder.Sql(statement);
            //}
            ////#else
            foreach (var statement in BuildSqlServerAuditLedger(months))
            {
                migrationBuilder.Sql(statement);
            }
            ////#endif
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditArchiveManifest",
                schema: "Audit");

            ////#if (UsePostgreSql)
            //migrationBuilder.Sql("DROP TABLE IF EXISTS \"Audit\".\"AuditLedger\" CASCADE;");
            //migrationBuilder.Sql("DROP FUNCTION IF EXISTS \"Audit\".audit_ledger_append_only();");
            ////#elseif (UseOracle)
            //migrationBuilder.Sql("BEGIN EXECUTE IMMEDIATE 'DROP TABLE \"Audit\".\"AuditLedger\" PURGE'; EXCEPTION WHEN OTHERS THEN NULL; END;");
            ////#else
            // Drop staging table first, then the ledger table, then the partition metadata.
            migrationBuilder.Sql("DROP TABLE IF EXISTS [Audit].[AuditLedger_Staging];");
            migrationBuilder.Sql("DROP TABLE IF EXISTS [Audit].[AuditLedger];");
            migrationBuilder.Sql("IF EXISTS (SELECT 1 FROM sys.partition_schemes WHERE name = 'AuditLedger_PS') DROP PARTITION SCHEME [AuditLedger_PS];");
            migrationBuilder.Sql("IF EXISTS (SELECT 1 FROM sys.partition_functions WHERE name = 'AuditLedger_PF') DROP PARTITION FUNCTION [AuditLedger_PF];");
            ////#endif
        }

        /// <summary>
        /// First-of-month boundaries from <paramref name="monthsBack"/> months ago to
        /// <paramref name="monthsForward"/> months ahead (inclusive), based on the current date.
        /// </summary>
        /// <remarks>
        /// This uses <see cref="DateTime.UtcNow"/>, so the partition layout depends on when the
        /// migration is applied. That non-determinism is pre-existing behaviour and is preserved
        /// here; the background service extends the window at runtime.
        /// </remarks>
        private static List<DateTime> GeneratePartitionMonths(int monthsBack, int monthsForward)
        {
            var now = DateTime.UtcNow;
            var start = new DateTime(now.Year, now.Month, 1).AddMonths(-monthsBack);

            return Enumerable
                .Range(0, monthsBack + monthsForward + 1)
                .Select(i => start.AddMonths(i))
                .ToList();
        }

        /// <summary>
        /// SQL Server: partitioned, native append-only Ledger table plus a matching staging table
        /// for partition switching. Append-only is enforced by <c>LEDGER = ON (APPEND_ONLY = ON)</c>.
        /// </summary>
        private static IEnumerable<string> BuildSqlServerAuditLedger(List<DateTime> months)
        {
            var boundaries = string.Join(", ", months.Select(m => $"'{m:yyyy-MM-dd}'"));

            const string columns = @"
                [SequenceNumber] bigint NOT NULL,
                [EventId] uniqueidentifier NOT NULL,
                [OccurredAt] datetime2 NOT NULL,
                [PreviousHash] nvarchar(64) NOT NULL,
                [Hash] nvarchar(64) NOT NULL,
                [UserId] uniqueidentifier NULL,
                [Username] nvarchar(256) NULL,
                [IpAddress] nvarchar(45) NULL,
                [UserAgent] nvarchar(512) NULL,
                [CorrelationId] nvarchar(128) NULL,
                [EventType] int NOT NULL,
                [Action] int NOT NULL,
                [EntityType] nvarchar(128) NULL,
                [EntityId] nvarchar(128) NULL,
                [OldValues] nvarchar(max) NULL,
                [NewValues] nvarchar(max) NULL,
                [AdditionalData] nvarchar(max) NULL,
                [Success] bit NOT NULL,
                [FailureReason] nvarchar(1024) NULL,
                [Dispatched] bit NOT NULL DEFAULT 0,
                [DispatchedAt] datetime2 NULL";

            yield return $@"
                CREATE PARTITION FUNCTION [AuditLedger_PF] (datetime2)
                AS RANGE RIGHT FOR VALUES ({boundaries});";

            yield return @"
                CREATE PARTITION SCHEME [AuditLedger_PS]
                AS PARTITION [AuditLedger_PF]
                ALL TO ([PRIMARY]);";

            // Unique/PK indexes on a partitioned table must include the partition column.
            yield return $@"
                CREATE TABLE [Audit].[AuditLedger] (
                    {columns},
                    CONSTRAINT [PK_AuditLedger] PRIMARY KEY CLUSTERED ([SequenceNumber], [OccurredAt])
                ) ON [AuditLedger_PS]([OccurredAt])
                WITH (LEDGER = ON (APPEND_ONLY = ON));";

            yield return "CREATE UNIQUE INDEX [IX_AuditLedger_EventId] ON [Audit].[AuditLedger] ([EventId], [OccurredAt]);";
            yield return "CREATE INDEX [IX_AuditLedger_UserId_OccurredAt] ON [Audit].[AuditLedger] ([UserId], [OccurredAt]);";
            yield return "CREATE INDEX [IX_AuditLedger_EntityType_EntityId] ON [Audit].[AuditLedger] ([EntityType], [EntityId]);";
            yield return "CREATE INDEX [IX_AuditLedger_Dispatched] ON [Audit].[AuditLedger] ([Dispatched]) WHERE [Dispatched] = 0;";

            // Staging table for partition switching (same schema, NOT a ledger table).
            yield return $@"
                CREATE TABLE [Audit].[AuditLedger_Staging] (
                    {columns},
                    CONSTRAINT [PK_AuditLedger_Staging] PRIMARY KEY CLUSTERED ([SequenceNumber], [OccurredAt])
                ) ON [AuditLedger_PS]([OccurredAt]);";
        }

        /// <summary>
        /// PostgreSQL: native range-partitioned table. Append-only is enforced by a
        /// BEFORE UPDATE/DELETE trigger (which propagates to partitions) plus a REVOKE. Dropping a
        /// partition to archive is DDL, so it is unaffected by the trigger.
        /// </summary>
        private static IEnumerable<string> BuildPostgreSqlAuditLedger(List<DateTime> months)
        {
            yield return @"
                CREATE TABLE ""Audit"".""AuditLedger"" (
                    ""SequenceNumber"" bigint NOT NULL,
                    ""EventId"" uuid NOT NULL,
                    ""OccurredAt"" timestamp with time zone NOT NULL,
                    ""PreviousHash"" varchar(64) NOT NULL,
                    ""Hash"" varchar(64) NOT NULL,
                    ""UserId"" uuid NULL,
                    ""Username"" varchar(256) NULL,
                    ""IpAddress"" varchar(45) NULL,
                    ""UserAgent"" varchar(512) NULL,
                    ""CorrelationId"" varchar(128) NULL,
                    ""EventType"" integer NOT NULL,
                    ""Action"" integer NOT NULL,
                    ""EntityType"" varchar(128) NULL,
                    ""EntityId"" varchar(128) NULL,
                    ""OldValues"" jsonb NULL,
                    ""NewValues"" jsonb NULL,
                    ""AdditionalData"" jsonb NULL,
                    ""Success"" boolean NOT NULL,
                    ""FailureReason"" varchar(1024) NULL,
                    ""Dispatched"" boolean NOT NULL DEFAULT false,
                    ""DispatchedAt"" timestamp with time zone NULL,
                    CONSTRAINT ""PK_AuditLedger"" PRIMARY KEY (""SequenceNumber"", ""OccurredAt"")
                ) PARTITION BY RANGE (""OccurredAt"");";

            foreach (var month in months)
            {
                var next = month.AddMonths(1);
                var name = $"AuditLedger_{month:yyyy_MM}";
                yield return $@"
                    CREATE TABLE ""Audit"".""{name}"" PARTITION OF ""Audit"".""AuditLedger""
                    FOR VALUES FROM ('{month:yyyy-MM-dd}') TO ('{next:yyyy-MM-dd}');";
            }

            // Catch-all so inserts outside the pre-created window never fail.
            yield return @"CREATE TABLE ""Audit"".""AuditLedger_default"" PARTITION OF ""Audit"".""AuditLedger"" DEFAULT;";

            yield return @"CREATE UNIQUE INDEX ""IX_AuditLedger_EventId"" ON ""Audit"".""AuditLedger"" (""EventId"", ""OccurredAt"");";
            yield return @"CREATE INDEX ""IX_AuditLedger_UserId_OccurredAt"" ON ""Audit"".""AuditLedger"" (""UserId"", ""OccurredAt"");";
            yield return @"CREATE INDEX ""IX_AuditLedger_EntityType_EntityId"" ON ""Audit"".""AuditLedger"" (""EntityType"", ""EntityId"");";
            yield return @"CREATE INDEX ""IX_AuditLedger_Dispatched"" ON ""Audit"".""AuditLedger"" (""Dispatched"") WHERE ""Dispatched"" = false;";

            yield return @"
                CREATE OR REPLACE FUNCTION ""Audit"".audit_ledger_append_only()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'AuditLedger is append-only; % is not permitted', TG_OP;
                END;
                $$;";

            yield return @"
                CREATE TRIGGER audit_ledger_no_modify
                BEFORE UPDATE OR DELETE ON ""Audit"".""AuditLedger""
                FOR EACH ROW EXECUTE FUNCTION ""Audit"".audit_ledger_append_only();";

            yield return @"REVOKE UPDATE, DELETE, TRUNCATE ON ""Audit"".""AuditLedger"" FROM PUBLIC;";
        }

        /// <summary>
        /// Oracle: native range-partitioned table. Append-only is enforced by a BEFORE UPDATE/DELETE
        /// trigger. Dropping a partition to archive is DDL, so it is unaffected by the trigger.
        /// </summary>
        private static IEnumerable<string> BuildOracleAuditLedger(List<DateTime> months)
        {
            var partitions = string.Join(",\n", months.Select(m =>
            {
                var next = m.AddMonths(1);
                return $@"    PARTITION ""AUDIT_{m:yyyy_MM}"" VALUES LESS THAN (TIMESTAMP '{next:yyyy-MM-dd} 00:00:00')";
            }));

            yield return $@"
                CREATE TABLE ""Audit"".""AuditLedger"" (
                    ""SequenceNumber"" NUMBER(19) NOT NULL,
                    ""EventId"" RAW(16) NOT NULL,
                    ""OccurredAt"" TIMESTAMP NOT NULL,
                    ""PreviousHash"" NVARCHAR2(64) NOT NULL,
                    ""Hash"" NVARCHAR2(64) NOT NULL,
                    ""UserId"" RAW(16),
                    ""Username"" NVARCHAR2(256),
                    ""IpAddress"" NVARCHAR2(45),
                    ""UserAgent"" NVARCHAR2(512),
                    ""CorrelationId"" NVARCHAR2(128),
                    ""EventType"" NUMBER(10) NOT NULL,
                    ""Action"" NUMBER(10) NOT NULL,
                    ""EntityType"" NVARCHAR2(128),
                    ""EntityId"" NVARCHAR2(128),
                    ""OldValues"" CLOB,
                    ""NewValues"" CLOB,
                    ""AdditionalData"" CLOB,
                    ""Success"" NUMBER(1) NOT NULL,
                    ""FailureReason"" NVARCHAR2(1024),
                    ""Dispatched"" NUMBER(1) DEFAULT 0 NOT NULL,
                    ""DispatchedAt"" TIMESTAMP,
                    CONSTRAINT ""PK_AuditLedger"" PRIMARY KEY (""SequenceNumber"", ""OccurredAt"")
                )
                PARTITION BY RANGE (""OccurredAt"") (
                {partitions},
                    PARTITION ""AUDIT_MAX"" VALUES LESS THAN (MAXVALUE)
                )";

            yield return @"CREATE UNIQUE INDEX ""Audit"".""IX_AuditLedger_EventId"" ON ""Audit"".""AuditLedger"" (""EventId"", ""OccurredAt"") LOCAL";
            yield return @"CREATE INDEX ""Audit"".""IX_AuditLedger_UserId_OccurredAt"" ON ""Audit"".""AuditLedger"" (""UserId"", ""OccurredAt"") LOCAL";
            yield return @"CREATE INDEX ""Audit"".""IX_AuditLedger_EntityType_EntityId"" ON ""Audit"".""AuditLedger"" (""EntityType"", ""EntityId"") LOCAL";
            yield return @"CREATE INDEX ""Audit"".""IX_AuditLedger_Dispatched"" ON ""Audit"".""AuditLedger"" (""Dispatched"") LOCAL";

            yield return @"
                CREATE OR REPLACE TRIGGER ""Audit"".""AUDIT_LEDGER_APPEND_ONLY""
                BEFORE UPDATE OR DELETE ON ""Audit"".""AuditLedger""
                BEGIN
                    RAISE_APPLICATION_ERROR(-20001, 'AuditLedger is append-only; modification not permitted');
                END;";
        }
    }
}