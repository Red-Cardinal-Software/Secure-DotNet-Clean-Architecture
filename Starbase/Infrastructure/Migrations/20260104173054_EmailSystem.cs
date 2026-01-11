using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class EmailSystem : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsHtml",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.EnsureSchema(
                name: "Email");

            migrationBuilder.RenameColumn(
                name: "Body",
                schema: "Configuration",
                table: "EmailTemplates",
                newName: "HtmlBody");

            migrationBuilder.AlterColumn<string>(
                name: "Subject",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "Key",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CreatedAt",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "datetimeoffset",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<bool>(
                name: "IsActive",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "bit",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<string>(
                name: "LayoutKey",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ModifiedAt",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TextBody",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "OutboundEmails",
                schema: "Email",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    To = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Subject = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    HtmlBody = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TextBody = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    TemplateKey = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false),
                    Attempts = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    MaxAttempts = table.Column<int>(type: "int", nullable: false, defaultValue: 3),
                    NextAttemptAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ErrorMessage = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: true),
                    ProviderMessageId = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    SentAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                    CorrelationId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    Priority = table.Column<int>(type: "int", nullable: false, defaultValue: 10)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OutboundEmails", x => x.Id);
                });

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
                unique: true,
                filter: "[OrganizationId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_EmailTemplates_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Cleanup",
                schema: "Email",
                table: "OutboundEmails",
                columns: new[] { "Status", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_CorrelationId",
                schema: "Email",
                table: "OutboundEmails",
                column: "CorrelationId",
                filter: "[CorrelationId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_OrganizationId",
                schema: "Email",
                table: "OutboundEmails",
                column: "OrganizationId",
                filter: "[OrganizationId] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Queue",
                schema: "Email",
                table: "OutboundEmails",
                columns: new[] { "Status", "NextAttemptAt", "Priority" },
                filter: "[Status] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_OutboundEmails_Status",
                schema: "Email",
                table: "OutboundEmails",
                column: "Status");

            migrationBuilder.AddForeignKey(
                name: "FK_EmailTemplates_Organizations_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates",
                column: "OrganizationId",
                principalSchema: "Identity",
                principalTable: "Organizations",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_EmailTemplates_Organizations_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropTable(
                name: "OutboundEmails",
                schema: "Email");

            migrationBuilder.DropIndex(
                name: "IX_EmailTemplates_Key",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropIndex(
                name: "IX_EmailTemplates_Key_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropIndex(
                name: "IX_EmailTemplates_OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "IsActive",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "LayoutKey",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "ModifiedAt",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "OrganizationId",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.DropColumn(
                name: "TextBody",
                schema: "Configuration",
                table: "EmailTemplates");

            migrationBuilder.RenameColumn(
                name: "HtmlBody",
                schema: "Configuration",
                table: "EmailTemplates",
                newName: "Body");

            migrationBuilder.AlterColumn<string>(
                name: "Subject",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(500)",
                oldMaxLength: 500);

            migrationBuilder.AlterColumn<string>(
                name: "Key",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(100)",
                oldMaxLength: 100);

            migrationBuilder.AddColumn<bool>(
                name: "IsHtml",
                schema: "Configuration",
                table: "EmailTemplates",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }
    }
}
