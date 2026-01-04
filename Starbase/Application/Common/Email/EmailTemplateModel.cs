namespace Application.Common.Email;

/// <summary>
/// Base class for email template models with common properties.
/// </summary>
public abstract class EmailTemplateModel
{
    /// <summary>
    /// The application name for branding.
    /// </summary>
    public string AppName { get; set; } = "Starbase";

    /// <summary>
    /// The current year for copyright notices.
    /// </summary>
    public int CurrentYear => DateTime.UtcNow.Year;

    /// <summary>
    /// Optional support email address.
    /// </summary>
    public string? SupportEmail { get; set; }

    /// <summary>
    /// Optional company name for footer.
    /// </summary>
    public string? CompanyName { get; set; }
}

/// <summary>
/// Model for password reset emails.
/// </summary>
public class PasswordResetEmailModel : EmailTemplateModel
{
    public required string FirstName { get; set; }
    public required string ResetLink { get; set; }
    public int ExpiresInMinutes { get; set; } = 60;
}

/// <summary>
/// Model for email verification emails.
/// </summary>
public class EmailVerificationModel : EmailTemplateModel
{
    public required string FirstName { get; set; }
    public required string VerificationLink { get; set; }
    public int ExpiresInMinutes { get; set; } = 60;
}

/// <summary>
/// Model for MFA verification code emails.
/// </summary>
public class MfaCodeEmailModel : EmailTemplateModel
{
    public required string Code { get; set; }
    public int ExpiresInMinutes { get; set; } = 5;
    public string? IpAddress { get; set; }
    public string? Location { get; set; }
}

/// <summary>
/// Model for MFA setup verification code emails.
/// </summary>
public class MfaSetupCodeEmailModel : EmailTemplateModel
{
    public required string Code { get; set; }
    public int ExpiresInMinutes { get; set; } = 10;
}

/// <summary>
/// Model for security alert emails.
/// </summary>
public class SecurityAlertEmailModel : EmailTemplateModel
{
    public required string FirstName { get; set; }
    public required string EventType { get; set; }
    public required string EventDescription { get; set; }
    public required DateTimeOffset Timestamp { get; set; }
    public string? IpAddress { get; set; }
    public string? Location { get; set; }
    public string? DeviceInfo { get; set; }
}

/// <summary>
/// Model for welcome emails.
/// </summary>
public class WelcomeEmailModel : EmailTemplateModel
{
    public required string FirstName { get; set; }
    public required string LoginLink { get; set; }
    public string? TemporaryPassword { get; set; }
    public bool MustChangePassword { get; set; }
}

/// <summary>
/// Model for account locked emails.
/// </summary>
public class AccountLockedEmailModel : EmailTemplateModel
{
    public required string FirstName { get; set; }
    public required DateTimeOffset UnlockTime { get; set; }
    public required string Reason { get; set; }
    public int FailedAttempts { get; set; }
    public string? IpAddress { get; set; }
}

/// <summary>
/// Model for user invitation emails.
/// </summary>
public class UserInvitationEmailModel : EmailTemplateModel
{
    public required string InviterName { get; set; }
    public required string OrganizationName { get; set; }
    public required string InvitationLink { get; set; }
    public int ExpiresInDays { get; set; } = 7;
    public string? PersonalMessage { get; set; }
}