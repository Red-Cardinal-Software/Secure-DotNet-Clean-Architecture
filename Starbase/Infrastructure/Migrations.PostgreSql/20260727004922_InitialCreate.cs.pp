using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "Security");

            migrationBuilder.EnsureSchema(
                name: "Identity");

            migrationBuilder.EnsureSchema(
                name: "Audit");

            migrationBuilder.EnsureSchema(
                name: "Configuration");

            migrationBuilder.EnsureSchema(
                name: "Email");

            migrationBuilder.CreateTable(
                name: "AccountLockouts",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    FailedAttemptCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    IsLockedOut = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    LockedOutAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LockoutExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastFailedAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    LockoutReason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    LockedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountLockouts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditArchiveManifest",
                schema: "Audit",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PartitionBoundary = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FirstSequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                    LastSequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                    RecordCount = table.Column<long>(type: "bigint", nullable: false),
                    FirstRecordHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LastRecordHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    LedgerDigest = table.Column<string>(type: "text", nullable: false),
                    ArchiveUri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    ArchiveBlobHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ArchiveSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    ArchivedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ArchivedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PurgedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RetentionPolicy = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditArchiveManifest", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLedger",
                schema: "Audit",
                columns: table => new
                {
                    SequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                    EventId = table.Column<Guid>(type: "uuid", nullable: false),
                    OccurredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PreviousHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    Username = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    EventType = table.Column<int>(type: "integer", nullable: false),
                    Action = table.Column<int>(type: "integer", nullable: false),
                    EntityType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    EntityId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    OldValues = table.Column<string>(type: "jsonb", nullable: true),
                    NewValues = table.Column<string>(type: "jsonb", nullable: true),
                    AdditionalData = table.Column<string>(type: "jsonb", nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    FailureReason = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    Dispatched = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    DispatchedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLedger", x => x.SequenceNumber);
                });

            migrationBuilder.CreateTable(
                name: "BlacklistedPasswords",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    HashedPassword = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlacklistedPasswords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LoginAttempts",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    AttemptedUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    IpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    IsSuccessful = table.Column<bool>(type: "boolean", nullable: false),
                    FailureReason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    AttemptedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    Metadata = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoginAttempts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Organizations",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Active = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Organizations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OutboundEmails",
                schema: "Email",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    To = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Subject = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    HtmlBody = table.Column<string>(type: "text", nullable: false),
                    TextBody = table.Column<string>(type: "text", nullable: true),
                    TemplateKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    MaxAttempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 3),
                    NextAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ErrorMessage = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ProviderMessageId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    SentAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Priority = table.Column<int>(type: "integer", nullable: false, defaultValue: 10)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OutboundEmails", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Privileges",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Description = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    IsSystemDefault = table.Column<bool>(type: "boolean", nullable: false),
                    IsAdminDefault = table.Column<bool>(type: "boolean", nullable: false),
                    IsUserDefault = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Privileges", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppUsers",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Username = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: false),
                    FirstName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    LastName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ForceResetPassword = table.Column<bool>(type: "boolean", nullable: false),
                    Active = table.Column<bool>(type: "boolean", nullable: false),
                    LastLoginTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppUsers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AppUsers_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalSchema: "Identity",
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EmailTemplates",
                schema: "Configuration",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: true),
                    Subject = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    HtmlBody = table.Column<string>(type: "text", nullable: false),
                    TextBody = table.Column<string>(type: "text", nullable: true),
                    LayoutKey = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ModifiedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EmailTemplates_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalSchema: "Identity",
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Roles_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalSchema: "Identity",
                        principalTable: "Organizations",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "MfaMethods",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    Secret = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Metadata = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    VerifiedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaMethods", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaMethods_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "PasswordResetTokens",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AppUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Expiration = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedByIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ClaimedByIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ClaimedDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordResetTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordResetTokens_AppUsers_AppUserId",
                        column: x => x.AppUserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                schema: "Identity",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TokenFamily = table.Column<Guid>(type: "uuid", nullable: false),
                    AppUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Expires = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedByIp = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReplacedBy = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_AppUsers_AppUserId",
                        column: x => x.AppUserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AppUserRole",
                schema: "Identity",
                columns: table => new
                {
                    RolesId = table.Column<Guid>(type: "uuid", nullable: false),
                    UsersId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppUserRole", x => new { x.RolesId, x.UsersId });
                    table.ForeignKey(
                        name: "FK_AppUserRole_AppUsers_UsersId",
                        column: x => x.UsersId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AppUserRole_Roles_RolesId",
                        column: x => x.RolesId,
                        principalSchema: "Identity",
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RolePrivileges",
                schema: "Identity",
                columns: table => new
                {
                    PrivilegesId = table.Column<Guid>(type: "uuid", nullable: false),
                    RoleId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePrivileges", x => new { x.PrivilegesId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_RolePrivileges_Privileges_PrivilegesId",
                        column: x => x.PrivilegesId,
                        principalSchema: "Identity",
                        principalTable: "Privileges",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RolePrivileges_Roles_RoleId",
                        column: x => x.RoleId,
                        principalSchema: "Identity",
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaChallenges",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    ChallengeToken = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "uuid", nullable: true),
                    IsCompleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    IsInvalid = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    IpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Metadata = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAttemptAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaChallenges_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaChallenges_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalSchema: "Security",
                        principalTable: "MfaMethods",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "MfaPushDevices",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    DeviceId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DeviceName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Platform = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    PushToken = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    PublicKey = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    RegisteredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    TrustScore = table.Column<int>(type: "integer", nullable: false, defaultValue: 50)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaPushDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaPushDevices_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaPushDevices_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalSchema: "Security",
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaRecoveryCodes",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "uuid", nullable: false),
                    HashedCode = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaRecoveryCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaRecoveryCodes_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalSchema: "Security",
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CredentialId = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    PublicKey = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false, defaultValue: 0L),
                    AuthenticatorType = table.Column<int>(type: "integer", nullable: false),
                    Transports = table.Column<string>(type: "text", nullable: false),
                    SupportsUserVerification = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    AttestationType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Aaguid = table.Column<string>(type: "character varying(36)", maxLength: 36, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    RegistrationIpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    RegistrationUserAgent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalSchema: "Security",
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaEmailCodes",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MfaChallengeId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    EmailAddress = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    HashedCode = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    SentAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    IpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaEmailCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaEmailCodes_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaEmailCodes_MfaChallenges_MfaChallengeId",
                        column: x => x.MfaChallengeId,
                        principalSchema: "Security",
                        principalTable: "MfaChallenges",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaPushChallenges",
                schema: "Security",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    ChallengeCode = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    SessionId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    IpAddress = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    UserAgent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Location = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RespondedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    Response = table.Column<int>(type: "integer", nullable: true, defaultValue: 0),
                    ResponseSignature = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    ContextData = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaPushChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaPushChallenges_AppUsers_UserId",
                        column: x => x.UserId,
                        principalSchema: "Identity",
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaPushChallenges_MfaPushDevices_DeviceId",
                        column: x => x.DeviceId,
                        principalSchema: "Security",
                        principalTable: "MfaPushDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_IsLockedOut_LockoutExpiresAt",
                schema: "Security",
                table: "AccountLockouts",
                columns: new[] { "IsLockedOut", "LockoutExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LastFailedAttemptAt",
                schema: "Security",
                table: "AccountLockouts",
                column: "LastFailedAttemptAt");

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LockedByUserId",
                schema: "Security",
                table: "AccountLockouts",
                column: "LockedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LockoutExpiresAt",
                schema: "Security",
                table: "AccountLockouts",
                column: "LockoutExpiresAt");

            migrationBuilder.CreateIndex(
                name: "UX_AccountLockouts_UserId",
                schema: "Security",
                table: "AccountLockouts",
                column: "UserId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AppUserRole_UsersId",
                schema: "Identity",
                table: "AppUserRole",
                column: "UsersId");

            migrationBuilder.CreateIndex(
                name: "IX_AppUsers_OrganizationId",
                schema: "Identity",
                table: "AppUsers",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditArchiveManifest_PartitionBoundary",
                schema: "Audit",
                table: "AuditArchiveManifest",
                column: "PartitionBoundary",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_Dispatched",
                schema: "Audit",
                table: "AuditLedger",
                column: "Dispatched",
                filter: "\"Dispatched\" = false");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_EntityType_EntityId",
                schema: "Audit",
                table: "AuditLedger",
                columns: new[] { "EntityType", "EntityId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_EventId",
                schema: "Audit",
                table: "AuditLedger",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_UserId_OccurredAt",
                schema: "Audit",
                table: "AuditLedger",
                columns: new[] { "UserId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_Key",
                schema: "Configuration",
                table: "EmailTemplates",
                column: "Key");

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_Key_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates",
                columns: new[] { "Key", "OrganizationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_AttemptedAt",
                schema: "Security",
                table: "LoginAttempts",
                column: "AttemptedAt");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_AttemptedUsername",
                schema: "Security",
                table: "LoginAttempts",
                column: "AttemptedUsername");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_IpAddress",
                schema: "Security",
                table: "LoginAttempts",
                column: "IpAddress");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_IpAddress_IsSuccessful_AttemptedAt",
                schema: "Security",
                table: "LoginAttempts",
                columns: new[] { "IpAddress", "IsSuccessful", "AttemptedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId",
                schema: "Security",
                table: "LoginAttempts",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId_IsSuccessful_AttemptedAt",
                schema: "Security",
                table: "LoginAttempts",
                columns: new[] { "UserId", "IsSuccessful", "AttemptedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_ChallengeToken",
                schema: "Security",
                table: "MfaChallenges",
                column: "ChallengeToken",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_CreatedAt",
                schema: "Security",
                table: "MfaChallenges",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_ExpiresAt",
                schema: "Security",
                table: "MfaChallenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_MfaMethodId",
                schema: "Security",
                table: "MfaChallenges",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_UserId",
                schema: "Security",
                table: "MfaChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_UserId_IsCompleted",
                schema: "Security",
                table: "MfaChallenges",
                columns: new[] { "UserId", "IsCompleted" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_ChallengeId",
                schema: "Security",
                table: "MfaEmailCodes",
                column: "MfaChallengeId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_ExpiresAt",
                schema: "Security",
                table: "MfaEmailCodes",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_User_Status",
                schema: "Security",
                table: "MfaEmailCodes",
                columns: new[] { "UserId", "IsUsed", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_UserId",
                schema: "Security",
                table: "MfaEmailCodes",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId",
                schema: "Security",
                table: "MfaMethods",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_IsDefault",
                schema: "Security",
                table: "MfaMethods",
                columns: new[] { "UserId", "IsDefault" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_IsEnabled",
                schema: "Security",
                table: "MfaMethods",
                columns: new[] { "UserId", "IsEnabled" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_Type",
                schema: "Security",
                table: "MfaMethods",
                columns: new[] { "UserId", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_ChallengeCode",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "ChallengeCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_CreatedAt",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_DeviceId",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_ExpiresAt",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_SessionId",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_UserId",
                schema: "Security",
                table: "MfaPushChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_UserId_Status",
                schema: "Security",
                table: "MfaPushChallenges",
                columns: new[] { "UserId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_MfaMethodId",
                schema: "Security",
                table: "MfaPushDevices",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_PushToken",
                schema: "Security",
                table: "MfaPushDevices",
                column: "PushToken");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId",
                schema: "Security",
                table: "MfaPushDevices",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId_DeviceId",
                schema: "Security",
                table: "MfaPushDevices",
                columns: new[] { "UserId", "DeviceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId_IsActive",
                schema: "Security",
                table: "MfaPushDevices",
                columns: new[] { "UserId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_HashedCode",
                schema: "Security",
                table: "MfaRecoveryCodes",
                column: "HashedCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_MfaMethodId",
                schema: "Security",
                table: "MfaRecoveryCodes",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_MfaMethodId_IsUsed",
                schema: "Security",
                table: "MfaRecoveryCodes",
                columns: new[] { "MfaMethodId", "IsUsed" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Cleanup",
                schema: "Email",
                table: "OutboundEmails",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_CorrelationId",
                schema: "Email",
                table: "OutboundEmails",
                column: "CorrelationId");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_OrganizationId",
                schema: "Email",
                table: "OutboundEmails",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Queue",
                schema: "Email",
                table: "OutboundEmails",
                columns: new[] { "Status", "NextAttemptAt", "Priority" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Status",
                schema: "Email",
                table: "OutboundEmails",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetTokens_AppUserId",
                schema: "Identity",
                table: "PasswordResetTokens",
                column: "AppUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_AppUserId",
                schema: "Identity",
                table: "RefreshTokens",
                column: "AppUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RolePrivileges_RoleId",
                schema: "Identity",
                table: "RolePrivileges",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_OrganizationId",
                schema: "Identity",
                table: "Roles",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_CredentialId",
                schema: "Security",
                table: "WebAuthnCredentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_LastUsed",
                schema: "Security",
                table: "WebAuthnCredentials",
                column: "LastUsedAt");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_MfaMethodId",
                schema: "Security",
                table: "WebAuthnCredentials",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_User_Active",
                schema: "Security",
                table: "WebAuthnCredentials",
                columns: new[] { "UserId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_UserId",
                schema: "Security",
                table: "WebAuthnCredentials",
                column: "UserId");

            // Audit ledger append-only enforcement (PostgreSQL). A BEFORE UPDATE/DELETE trigger
            // blocks row modification while leaving INSERT and DROP PARTITION (archival) intact.
            // Tamper-evidence beyond this is provided by the application-layer SHA-256 hash chain.
            migrationBuilder.Sql(@"
                CREATE OR REPLACE FUNCTION ""Audit"".audit_ledger_append_only()
                RETURNS trigger LANGUAGE plpgsql AS $fn$
                BEGIN
                    RAISE EXCEPTION 'AuditLedger is append-only; % is not permitted', TG_OP;
                END;
                $fn$;");
            migrationBuilder.Sql(@"
                CREATE TRIGGER audit_ledger_no_modify
                BEFORE UPDATE OR DELETE ON ""Audit"".""AuditLedger""
                FOR EACH ROW EXECUTE FUNCTION ""Audit"".audit_ledger_append_only();");
            migrationBuilder.Sql(@"REVOKE UPDATE, DELETE, TRUNCATE ON ""Audit"".""AuditLedger"" FROM PUBLIC;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"DROP TRIGGER IF EXISTS audit_ledger_no_modify ON ""Audit"".""AuditLedger"";");
            migrationBuilder.Sql(@"DROP FUNCTION IF EXISTS ""Audit"".audit_ledger_append_only();");

            migrationBuilder.DropTable(
                name: "AccountLockouts",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "AppUserRole",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "AuditArchiveManifest",
                schema: "Audit");

            migrationBuilder.DropTable(
                name: "AuditLedger",
                schema: "Audit");

            migrationBuilder.DropTable(
                name: "BlacklistedPasswords",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "EmailTemplates",
                schema: "Configuration");

            migrationBuilder.DropTable(
                name: "LoginAttempts",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "MfaEmailCodes",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "MfaPushChallenges",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "MfaRecoveryCodes",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "OutboundEmails",
                schema: "Email");

            migrationBuilder.DropTable(
                name: "PasswordResetTokens",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "RefreshTokens",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "RolePrivileges",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "WebAuthnCredentials",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "MfaChallenges",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "MfaPushDevices",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "Privileges",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "Roles",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "MfaMethods",
                schema: "Security");

            migrationBuilder.DropTable(
                name: "AppUsers",
                schema: "Identity");

            migrationBuilder.DropTable(
                name: "Organizations",
                schema: "Identity");
        }
    }
}
