using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccountLockouts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    FailedAttemptCount = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 0),
                    IsLockedOut = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    LockedOutAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    LockoutExpiresAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    LastFailedAttemptAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false, defaultValueSql: "SYS_EXTRACT_UTC(SYSTIMESTAMP)"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false, defaultValueSql: "SYS_EXTRACT_UTC(SYSTIMESTAMP)"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false, defaultValueSql: "SYS_EXTRACT_UTC(SYSTIMESTAMP)"),
                    LockoutReason = table.Column<string>(type: "NVARCHAR2(1000)", maxLength: 1000, nullable: true),
                    LockedByUserId = table.Column<Guid>(type: "RAW(16)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountLockouts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditArchiveManifest",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    PartitionBoundary = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    FirstSequenceNumber = table.Column<long>(type: "NUMBER(19)", nullable: false),
                    LastSequenceNumber = table.Column<long>(type: "NUMBER(19)", nullable: false),
                    RecordCount = table.Column<long>(type: "NUMBER(19)", nullable: false),
                    FirstRecordHash = table.Column<string>(type: "NVARCHAR2(64)", maxLength: 64, nullable: false),
                    LastRecordHash = table.Column<string>(type: "NVARCHAR2(64)", maxLength: 64, nullable: false),
                    LedgerDigest = table.Column<string>(type: "CLOB", nullable: false),
                    ArchiveUri = table.Column<string>(type: "NCLOB", maxLength: 2048, nullable: false),
                    ArchiveBlobHash = table.Column<string>(type: "NVARCHAR2(64)", maxLength: 64, nullable: false),
                    ArchiveSizeBytes = table.Column<long>(type: "NUMBER(19)", nullable: false),
                    ArchivedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    ArchivedBy = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    PurgedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true),
                    RetentionPolicy = table.Column<string>(type: "NVARCHAR2(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditArchiveManifest", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLedger",
                columns: table => new
                {
                    SequenceNumber = table.Column<long>(type: "NUMBER(19)", nullable: false),
                    EventId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    OccurredAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    PreviousHash = table.Column<string>(type: "NVARCHAR2(64)", maxLength: 64, nullable: false),
                    Hash = table.Column<string>(type: "NVARCHAR2(64)", maxLength: 64, nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: true),
                    Username = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: true),
                    IpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "NVARCHAR2(512)", maxLength: 512, nullable: true),
                    CorrelationId = table.Column<string>(type: "NVARCHAR2(128)", maxLength: 128, nullable: true),
                    EventType = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    Action = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    EntityType = table.Column<string>(type: "NVARCHAR2(128)", maxLength: 128, nullable: true),
                    EntityId = table.Column<string>(type: "NVARCHAR2(128)", maxLength: 128, nullable: true),
                    OldValues = table.Column<string>(type: "CLOB", nullable: true),
                    NewValues = table.Column<string>(type: "CLOB", nullable: true),
                    AdditionalData = table.Column<string>(type: "CLOB", nullable: true),
                    Success = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    FailureReason = table.Column<string>(type: "NVARCHAR2(1024)", maxLength: 1024, nullable: true),
                    Dispatched = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    DispatchedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLedger", x => x.SequenceNumber);
                });

            migrationBuilder.CreateTable(
                name: "BlacklistedPasswords",
                columns: table => new
                {
                    Id = table.Column<int>(type: "NUMBER(10)", nullable: false)
                        .Annotation("Oracle:Identity", "START WITH 1 INCREMENT BY 1"),
                    HashedPassword = table.Column<string>(type: "NVARCHAR2(2000)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlacklistedPasswords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LoginAttempts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    AttemptedUsername = table.Column<string>(type: "NVARCHAR2(255)", maxLength: 255, nullable: false),
                    IpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "NVARCHAR2(1000)", maxLength: 1000, nullable: true),
                    IsSuccessful = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    FailureReason = table.Column<string>(type: "NVARCHAR2(500)", maxLength: 500, nullable: true),
                    AttemptedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false, defaultValueSql: "SYS_EXTRACT_UTC(SYSTIMESTAMP)"),
                    Metadata = table.Column<string>(type: "NCLOB", maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LoginAttempts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Organizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Name = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    Active = table.Column<bool>(type: "BOOLEAN", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Organizations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OutboundEmails",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    To = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    Subject = table.Column<string>(type: "NVARCHAR2(500)", maxLength: 500, nullable: false),
                    HtmlBody = table.Column<string>(type: "NVARCHAR2(2000)", nullable: false),
                    TextBody = table.Column<string>(type: "NVARCHAR2(2000)", nullable: true),
                    TemplateKey = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: true),
                    Status = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    Attempts = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 0),
                    MaxAttempts = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 3),
                    NextAttemptAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    ErrorMessage = table.Column<string>(type: "NVARCHAR2(2000)", maxLength: 2000, nullable: true),
                    ProviderMessageId = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: true),
                    SentAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "RAW(16)", nullable: true),
                    CorrelationId = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: true),
                    Priority = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 10)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OutboundEmails", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Privileges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Name = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    Description = table.Column<string>(type: "NVARCHAR2(200)", maxLength: 200, nullable: false),
                    IsSystemDefault = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    IsAdminDefault = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    IsUserDefault = table.Column<bool>(type: "BOOLEAN", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Privileges", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AppUsers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Username = table.Column<string>(type: "NVARCHAR2(200)", maxLength: 200, nullable: false),
                    PasswordHash = table.Column<string>(type: "NVARCHAR2(2000)", nullable: false),
                    FirstName = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    LastName = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    ForceResetPassword = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    Active = table.Column<bool>(type: "BOOLEAN", nullable: false),
                    LastLoginTime = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true),
                    OrganizationId = table.Column<Guid>(type: "RAW(16)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppUsers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AppUsers_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EmailTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Key = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    OrganizationId = table.Column<Guid>(type: "RAW(16)", nullable: true),
                    Subject = table.Column<string>(type: "NVARCHAR2(500)", maxLength: 500, nullable: false),
                    HtmlBody = table.Column<string>(type: "NVARCHAR2(2000)", nullable: false),
                    TextBody = table.Column<string>(type: "NVARCHAR2(2000)", nullable: true),
                    LayoutKey = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: true),
                    IsActive = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    ModifiedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EmailTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EmailTemplates_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Name = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    OrganizationId = table.Column<Guid>(type: "RAW(16)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Roles_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "MfaMethods",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Type = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    Secret = table.Column<string>(type: "NVARCHAR2(500)", maxLength: 500, nullable: true),
                    Metadata = table.Column<string>(type: "NVARCHAR2(2000)", maxLength: 2000, nullable: true),
                    Name = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: true),
                    IsEnabled = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    IsDefault = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    VerifiedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaMethods", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaMethods_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "PasswordResetTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    AppUserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Expiration = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    CreatedByIp = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    ClaimedByIp = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: true),
                    ClaimedDate = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordResetTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordResetTokens_AppUsers_AppUserId",
                        column: x => x.AppUserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    TokenFamily = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    AppUserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    Expires = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    CreatedByIp = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    CreatedDate = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    ReplacedBy = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_AppUsers_AppUserId",
                        column: x => x.AppUserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AppUserRole",
                columns: table => new
                {
                    RolesId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UsersId = table.Column<Guid>(type: "RAW(16)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppUserRole", x => new { x.RolesId, x.UsersId });
                    table.ForeignKey(
                        name: "FK_AppUserRole_AppUsers_UsersId",
                        column: x => x.UsersId,
                        principalTable: "AppUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AppUserRole_Roles_RolesId",
                        column: x => x.RolesId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RolePrivileges",
                columns: table => new
                {
                    PrivilegesId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    RoleId = table.Column<Guid>(type: "RAW(16)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RolePrivileges", x => new { x.PrivilegesId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_RolePrivileges_Privileges_PrivilegesId",
                        column: x => x.PrivilegesId,
                        principalTable: "Privileges",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RolePrivileges_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    ChallengeToken = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    Type = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "RAW(16)", nullable: true),
                    IsCompleted = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    IsInvalid = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    AttemptCount = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 0),
                    IpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "NVARCHAR2(500)", maxLength: 500, nullable: true),
                    Metadata = table.Column<string>(type: "NVARCHAR2(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    LastAttemptAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaChallenges_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaChallenges_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalTable: "MfaMethods",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "MfaPushDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    DeviceId = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    DeviceName = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    Platform = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    PushToken = table.Column<string>(type: "NCLOB", maxLength: 4000, nullable: false),
                    PublicKey = table.Column<string>(type: "NCLOB", maxLength: 2048, nullable: false),
                    RegisteredAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true),
                    IsActive = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: true),
                    TrustScore = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 50)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaPushDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaPushDevices_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaPushDevices_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaRecoveryCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    HashedCode = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    IsUsed = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaRecoveryCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaRecoveryCodes_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    MfaMethodId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    CredentialId = table.Column<string>(type: "NVARCHAR2(512)", maxLength: 512, nullable: false),
                    PublicKey = table.Column<string>(type: "NCLOB", maxLength: 2048, nullable: false),
                    SignCount = table.Column<long>(type: "NUMBER(10)", nullable: false, defaultValue: 0L),
                    AuthenticatorType = table.Column<int>(type: "NUMBER(10)", nullable: false),
                    Transports = table.Column<string>(type: "CLOB", nullable: false),
                    SupportsUserVerification = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    Name = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: true),
                    AttestationType = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: true),
                    Aaguid = table.Column<string>(type: "NVARCHAR2(36)", maxLength: 36, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    IsActive = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: true),
                    RegistrationIpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: true),
                    RegistrationUserAgent = table.Column<string>(type: "NVARCHAR2(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_MfaMethods_MfaMethodId",
                        column: x => x.MfaMethodId,
                        principalTable: "MfaMethods",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaEmailCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    MfaChallengeId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    EmailAddress = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    HashedCode = table.Column<string>(type: "NVARCHAR2(256)", maxLength: 256, nullable: false),
                    IsUsed = table.Column<bool>(type: "BOOLEAN", nullable: false, defaultValue: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    SentAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "TIMESTAMP(7) WITH TIME ZONE", nullable: true),
                    AttemptCount = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 0),
                    IpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaEmailCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaEmailCodes_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaEmailCodes_MfaChallenges_MfaChallengeId",
                        column: x => x.MfaChallengeId,
                        principalTable: "MfaChallenges",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaPushChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    UserId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    DeviceId = table.Column<Guid>(type: "RAW(16)", nullable: false),
                    ChallengeCode = table.Column<string>(type: "NVARCHAR2(50)", maxLength: 50, nullable: false),
                    SessionId = table.Column<string>(type: "NVARCHAR2(100)", maxLength: 100, nullable: false),
                    IpAddress = table.Column<string>(type: "NVARCHAR2(45)", maxLength: 45, nullable: false),
                    UserAgent = table.Column<string>(type: "NVARCHAR2(512)", maxLength: 512, nullable: false),
                    Location = table.Column<string>(type: "NVARCHAR2(200)", maxLength: 200, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: false),
                    RespondedAt = table.Column<DateTime>(type: "TIMESTAMP(7)", nullable: true),
                    Status = table.Column<int>(type: "NUMBER(10)", nullable: false, defaultValue: 0),
                    Response = table.Column<int>(type: "NUMBER(10)", nullable: true, defaultValue: 0),
                    ResponseSignature = table.Column<string>(type: "NVARCHAR2(1024)", maxLength: 1024, nullable: true),
                    ContextData = table.Column<string>(type: "NVARCHAR2(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaPushChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaPushChallenges_AppUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AppUsers",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_MfaPushChallenges_MfaPushDevices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "MfaPushDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_IsLockedOut_LockoutExpiresAt",
                table: "AccountLockouts",
                columns: new[] { "IsLockedOut", "LockoutExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LastFailedAttemptAt",
                table: "AccountLockouts",
                column: "LastFailedAttemptAt");

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LockedByUserId",
                table: "AccountLockouts",
                column: "LockedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_AccountLockouts_LockoutExpiresAt",
                table: "AccountLockouts",
                column: "LockoutExpiresAt");

            migrationBuilder.CreateIndex(
                name: "UX_AccountLockouts_UserId",
                table: "AccountLockouts",
                column: "UserId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AppUserRole_UsersId",
                table: "AppUserRole",
                column: "UsersId");

            migrationBuilder.CreateIndex(
                name: "IX_AppUsers_OrganizationId",
                table: "AppUsers",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditArchiveManifest_PartitionBoundary",
                table: "AuditArchiveManifest",
                column: "PartitionBoundary",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_Dispatched",
                table: "AuditLedger",
                column: "Dispatched");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_EntityType_EntityId",
                table: "AuditLedger",
                columns: new[] { "EntityType", "EntityId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_EventId",
                table: "AuditLedger",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditLedger_UserId_OccurredAt",
                table: "AuditLedger",
                columns: new[] { "UserId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_Key",
                table: "EmailTemplates",
                column: "Key");

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_Key_OrganizationId",
                table: "EmailTemplates",
                columns: new[] { "Key", "OrganizationId" },
                unique: true,
                filter: "\"OrganizationId\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_OrganizationId",
                table: "EmailTemplates",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_AttemptedAt",
                table: "LoginAttempts",
                column: "AttemptedAt");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_AttemptedUsername",
                table: "LoginAttempts",
                column: "AttemptedUsername");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_IpAddress",
                table: "LoginAttempts",
                column: "IpAddress");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_IpAddress_IsSuccessful_AttemptedAt",
                table: "LoginAttempts",
                columns: new[] { "IpAddress", "IsSuccessful", "AttemptedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId",
                table: "LoginAttempts",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_LoginAttempts_UserId_IsSuccessful_AttemptedAt",
                table: "LoginAttempts",
                columns: new[] { "UserId", "IsSuccessful", "AttemptedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_ChallengeToken",
                table: "MfaChallenges",
                column: "ChallengeToken",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_CreatedAt",
                table: "MfaChallenges",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_ExpiresAt",
                table: "MfaChallenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_MfaMethodId",
                table: "MfaChallenges",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_UserId",
                table: "MfaChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaChallenges_UserId_IsCompleted",
                table: "MfaChallenges",
                columns: new[] { "UserId", "IsCompleted" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_ChallengeId",
                table: "MfaEmailCodes",
                column: "MfaChallengeId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_ExpiresAt",
                table: "MfaEmailCodes",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_User_Status",
                table: "MfaEmailCodes",
                columns: new[] { "UserId", "IsUsed", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaEmailCodes_UserId",
                table: "MfaEmailCodes",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId",
                table: "MfaMethods",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_IsDefault",
                table: "MfaMethods",
                columns: new[] { "UserId", "IsDefault" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_IsEnabled",
                table: "MfaMethods",
                columns: new[] { "UserId", "IsEnabled" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaMethods_UserId_Type",
                table: "MfaMethods",
                columns: new[] { "UserId", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_ChallengeCode",
                table: "MfaPushChallenges",
                column: "ChallengeCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_CreatedAt",
                table: "MfaPushChallenges",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_DeviceId",
                table: "MfaPushChallenges",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_ExpiresAt",
                table: "MfaPushChallenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_SessionId",
                table: "MfaPushChallenges",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_UserId",
                table: "MfaPushChallenges",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushChallenges_UserId_Status",
                table: "MfaPushChallenges",
                columns: new[] { "UserId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_MfaMethodId",
                table: "MfaPushDevices",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId",
                table: "MfaPushDevices",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId_DeviceId",
                table: "MfaPushDevices",
                columns: new[] { "UserId", "DeviceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaPushDevices_UserId_IsActive",
                table: "MfaPushDevices",
                columns: new[] { "UserId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_HashedCode",
                table: "MfaRecoveryCodes",
                column: "HashedCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_MfaMethodId",
                table: "MfaRecoveryCodes",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaRecoveryCodes_MfaMethodId_IsUsed",
                table: "MfaRecoveryCodes",
                columns: new[] { "MfaMethodId", "IsUsed" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Cleanup",
                table: "OutboundEmails",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_CorrelationId",
                table: "OutboundEmails",
                column: "CorrelationId");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_OrganizationId",
                table: "OutboundEmails",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Queue",
                table: "OutboundEmails",
                columns: new[] { "Status", "NextAttemptAt", "Priority" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Status",
                table: "OutboundEmails",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_PasswordResetTokens_AppUserId",
                table: "PasswordResetTokens",
                column: "AppUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_AppUserId",
                table: "RefreshTokens",
                column: "AppUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RolePrivileges_RoleId",
                table: "RolePrivileges",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_OrganizationId",
                table: "Roles",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_CredentialId",
                table: "WebAuthnCredentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_LastUsed",
                table: "WebAuthnCredentials",
                column: "LastUsedAt");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_MfaMethodId",
                table: "WebAuthnCredentials",
                column: "MfaMethodId");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_User_Active",
                table: "WebAuthnCredentials",
                columns: new[] { "UserId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_UserId",
                table: "WebAuthnCredentials",
                column: "UserId");

            // Audit ledger append-only enforcement (Oracle). A BEFORE UPDATE/DELETE trigger blocks
            // row modification while leaving INSERT and DROP PARTITION (archival) intact.
            // Tamper-evidence beyond this is provided by the application-layer SHA-256 hash chain.
            migrationBuilder.Sql(@"
                CREATE OR REPLACE TRIGGER ""AUDIT_LEDGER_APPEND_ONLY""
                BEFORE UPDATE OR DELETE ON ""AuditLedger""
                BEGIN
                    RAISE_APPLICATION_ERROR(-20001, 'AuditLedger is append-only; modification not permitted');
                END;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"BEGIN EXECUTE IMMEDIATE 'DROP TRIGGER ""AUDIT_LEDGER_APPEND_ONLY""'; EXCEPTION WHEN OTHERS THEN NULL; END;");
            migrationBuilder.DropTable(
                name: "AccountLockouts");

            migrationBuilder.DropTable(
                name: "AppUserRole");

            migrationBuilder.DropTable(
                name: "AuditArchiveManifest");

            migrationBuilder.DropTable(
                name: "AuditLedger");

            migrationBuilder.DropTable(
                name: "BlacklistedPasswords");

            migrationBuilder.DropTable(
                name: "EmailTemplates");

            migrationBuilder.DropTable(
                name: "LoginAttempts");

            migrationBuilder.DropTable(
                name: "MfaEmailCodes");

            migrationBuilder.DropTable(
                name: "MfaPushChallenges");

            migrationBuilder.DropTable(
                name: "MfaRecoveryCodes");

            migrationBuilder.DropTable(
                name: "OutboundEmails");

            migrationBuilder.DropTable(
                name: "PasswordResetTokens");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "RolePrivileges");

            migrationBuilder.DropTable(
                name: "WebAuthnCredentials");

            migrationBuilder.DropTable(
                name: "MfaChallenges");

            migrationBuilder.DropTable(
                name: "MfaPushDevices");

            migrationBuilder.DropTable(
                name: "Privileges");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "MfaMethods");

            migrationBuilder.DropTable(
                name: "AppUsers");

            migrationBuilder.DropTable(
                name: "Organizations");
        }
    }
}
