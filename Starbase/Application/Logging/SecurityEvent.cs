using System.Security.Claims;
using Application.Common.Utilities;
using Microsoft.Extensions.Logging;

namespace Application.Logging;

/// <summary>
/// ECS-compliant security event logging using standard field names.
/// Maps to Elastic Common Schema (ECS) for SIEM compatibility.
/// </summary>
/// <remarks>
/// ECS Field Mappings:
/// - event.category: "authentication", "authorization", "iam", "configuration"
/// - event.type: "start", "end", "access", "change", "creation", "deletion"
/// - event.action: Specific action like "login", "logout", "user-created"
/// - event.outcome: "success", "failure", "unknown"
/// - user.name: Username of the actor
/// - user.id: User ID of the actor
/// - user.target.name: Target user (for admin actions)
/// </remarks>
public static class SecurityEvent
{
    /// <summary>
    /// ECS event categories for security events.
    /// </summary>
    public static class Category
    {
        public const string Authentication = "authentication";
        public const string Authorization = "authorization";
        public const string Iam = "iam";
        public const string Configuration = "configuration";
        public const string Session = "session";
        public const string Process = "process";
    }

    /// <summary>
    /// ECS event types.
    /// </summary>
    public static class Type
    {
        public const string Start = "start";
        public const string End = "end";
        public const string Access = "access";
        public const string Change = "change";
        public const string Creation = "creation";
        public const string Deletion = "deletion";
        public const string Info = "info";
        public const string Denied = "denied";
    }

    /// <summary>
    /// ECS event outcomes.
    /// </summary>
    public static class Outcome
    {
        public const string Success = "success";
        public const string Failure = "failure";
        public const string Unknown = "unknown";
    }

    /// <summary>
    /// Logs a security event with ECS-compliant field names.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="category">ECS event.category (e.g., "authentication", "iam").</param>
    /// <param name="type">ECS event.type (e.g., "start", "change").</param>
    /// <param name="action">ECS event.action (e.g., "login", "user-created").</param>
    /// <param name="outcome">ECS event.outcome ("success", "failure").</param>
    /// <param name="message">Human-readable log message.</param>
    /// <param name="user">Optional ClaimsPrincipal for user context.</param>
    /// <param name="targetUser">Optional target user for admin actions.</param>
    /// <param name="reason">Optional reason for failure.</param>
    public static void Log(
        ILogger logger,
        string category,
        string type,
        string action,
        string outcome,
        string message,
        ClaimsPrincipal? user = null,
        string? targetUser = null,
        string? reason = null)
    {
        Guid? userId = user != null ? RoleUtility.GetUserIdFromClaims(user) : null;
        var userName = user != null ? RoleUtility.GetUserNameFromClaim(user) : null;
        Guid? orgId = user != null ? RoleUtility.GetOrgIdFromClaims(user) : null;

        // Use LogLevel based on outcome
        var level = outcome switch
        {
            Outcome.Failure when category == Category.Authentication => LogLevel.Warning,
            Outcome.Failure => LogLevel.Warning,
            _ => LogLevel.Information
        };

        // Log with ECS field names as structured properties
        // These will be picked up by the ECS formatter
        logger.Log(level,
            "{Message} " +
            "{@event.category} {@event.type} {@event.action} {@event.outcome} " +
            "{@user.id} {@user.name} {@organization.id} " +
            "{@user.target.name} {@event.reason}",
            message,
            category, type, action, outcome,
            userId, userName, orgId,
            targetUser, reason);
    }

    /// <summary>
    /// Logs a successful authentication event.
    /// </summary>
    public static void AuthSuccess(ILogger logger, string action, string message, ClaimsPrincipal? user = null)
        => Log(logger, Category.Authentication, Type.Start, action, Outcome.Success, message, user);

    /// <summary>
    /// Logs a failed authentication event.
    /// </summary>
    public static void AuthFailure(ILogger logger, string action, string message, string? reason = null, ClaimsPrincipal? user = null)
        => Log(logger, Category.Authentication, Type.Start, action, Outcome.Failure, message, user, reason: reason);

    /// <summary>
    /// Logs an authentication denial (e.g., locked account, disabled user).
    /// </summary>
    public static void AuthDenied(ILogger logger, string action, string message, string reason, ClaimsPrincipal? user = null)
        => Log(logger, Category.Authorization, Type.Denied, action, Outcome.Failure, message, user, reason: reason);

    /// <summary>
    /// Logs a user management event (create, update, delete).
    /// </summary>
    public static void UserManagement(ILogger logger, string type, string action, string outcome, string message, ClaimsPrincipal? actor, string? targetUser = null)
        => Log(logger, Category.Iam, type, action, outcome, message, actor, targetUser);

    /// <summary>
    /// Logs a session event (logout, token refresh).
    /// </summary>
    public static void Session(ILogger logger, string type, string action, string outcome, string message, ClaimsPrincipal? user = null, string? reason = null)
        => Log(logger, Category.Session, type, action, outcome, message, user, reason: reason);

    /// <summary>
    /// Logs a suspicious or threatening activity.
    /// </summary>
    public static void Threat(ILogger logger, string action, string message, string reason, ClaimsPrincipal? user = null)
    {
        Guid? userId = user != null ? RoleUtility.GetUserIdFromClaims(user) : null;
        var userName = user != null ? RoleUtility.GetUserNameFromClaim(user) : null;

        logger.LogCritical(
            "THREAT: {Message} {@event.category} {@event.type} {@event.action} {@event.outcome} " +
            "{@user.id} {@user.name} {@threat.indicator.description}",
            message, Category.Authentication, Type.Denied, action, Outcome.Failure,
            userId, userName, reason);
    }
}