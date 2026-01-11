---
title: Email
nav_order: 7
---

# Email Subsystem

Starbase includes a production-ready email system with templating, queuing, and multiple provider support.

## Quick Start

```csharp
public class MyService(IEmailTemplateRenderer templateRenderer)
{
    public async Task NotifyUser(string email, string name)
    {
        var model = new { FirstName = name, AppName = "MyApp" };

        await templateRenderer.RenderAndSendAsync("welcome", email, model);
    }
}
```

That's it. The system handles template rendering, queuing, and delivery automatically.

## Architecture

```
Your Code
    │
    ▼
IEmailTemplateRenderer.RenderAndSendAsync()
    │
    ▼
┌─────────────────────────────────────────┐
│  Template Resolution (HybridProvider)   │
│  1. Org-specific DB template            │
│  2. Global DB template                  │
│  3. Embedded file template              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Fluid/Liquid Rendering                 │
│  - Variable substitution                │
│  - Layout wrapping                      │
│  - Auto plain-text generation           │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Email Queue (Database)                 │
│  - Persisted for reliability            │
│  - Tracks attempts and status           │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Background Processor                   │
│  - Adaptive polling (1-30s)             │
│  - Batch processing                     │
│  - Automatic retries                    │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Email Provider (IEmailSender)          │
│  SendGrid │ AWS SES │ Postmark │        │
│  Mailgun │ Mailchimp │ SMTP │ Console   │
└─────────────────────────────────────────┘
```

## Templates

### Included Templates

| Key | Purpose |
|-----|---------|
| `welcome` | New user welcome |
| `password-reset` | Password reset link |
| `mfa-code` | MFA verification code |
| `mfa-setup-code` | MFA setup verification |
| `account-locked` | Account lockout notification |
| `security-alert` | Security warnings |
| `user-invitation` | User invitations |

### Template Resolution Order

Templates are resolved in order:

1. **Organization database** - Per-tenant customization
2. **Global database** - Admin customization without deployment
3. **Embedded files** - Default templates in `Infrastructure/Emailing/Templates/`

### Template Syntax (Liquid)

```html
<p>Hello {{ model.FirstName }},</p>

<p>Your verification code is:</p>
<div class="code-box">
    <span class="code">{{ model.Code }}</span>
</div>

{% if model.ExpiresInMinutes %}
<p class="text-muted">This code expires in {{ model.ExpiresInMinutes }} minutes.</p>
{% endif %}
```

### Custom Filters

| Filter | Usage | Output |
|--------|-------|--------|
| `mask_email` | `{{ model.Email \| mask_email }}` | `j***n@example.com` |
| `format_date` | `{{ model.Date \| format_date: "MMM d, yyyy" }}` | `Jan 4, 2025` |

### Adding a New Template

1. Create `Infrastructure/Emailing/Templates/my-template.html`
2. Create `Infrastructure/Emailing/Templates/my-template.subject.txt`
3. Use it:

```csharp
await templateRenderer.RenderAndSendAsync("my-template", email, model);
```

## Configuration

```json
{
  "Email": {
    "FromAddress": "noreply@example.com",
    "FromName": "My App",
    "Templates": {
      "EnableDatabaseTemplates": true,
      "EnableOrganizationTemplates": true,
      "DefaultLayout": "default",
      "CacheDurationMinutes": 15
    }
  },
  "EmailQueue": {
    "Enabled": true,
    "BatchSize": 10,
    "MaxAttempts": 3,
    "RetentionDays": 30
  }
}
```

| Setting | Description |
|---------|-------------|
| `Email:FromAddress` | Default sender address |
| `Email:FromName` | Default sender display name |
| `Email:Templates:EnableDatabaseTemplates` | Allow database template overrides |
| `Email:Templates:EnableOrganizationTemplates` | Allow per-organization templates |
| `Email:Templates:CacheDurationMinutes` | Template cache TTL |
| `EmailQueue:Enabled` | Enable background queue processor |
| `EmailQueue:BatchSize` | Emails processed per batch |
| `EmailQueue:MaxAttempts` | Retry attempts before marking failed |
| `EmailQueue:RetentionDays` | Days to keep sent/failed emails |

## Providers

Select your provider at project creation:

```bash
dotnet new starbase -n MyApi --EmailProvider SendGrid
```

| Provider | Configuration | Notes |
|----------|---------------|-------|
| None | - | Console logging (development) |
| Smtp | `Email:Smtp:Host`, `Port`, `Username`, `Password` | Traditional SMTP server |
| SendGrid | `Email:SendGrid:ApiKey` | Popular, good free tier |
| AwsSes | `Email:Ses:Region` | Cost-effective for AWS users |
| Postmark | `Email:Postmark:ServerToken` | Excellent deliverability |
| Mailgun | `Email:Mailgun:ApiKey`, `Domain` | REST API |
| Mailchimp | `Email:Mailchimp:ApiKey` | Mandrill transactional |

## Direct Sending (Skip Queue)

For immediate delivery without queuing, inject `IEmailSender` directly:

```csharp
public class MyService(IEmailSender emailSender)
{
    public async Task SendUrgent(string email)
    {
        var message = new EmailMessage
        {
            To = email,
            Subject = "Urgent",
            HtmlBody = "<p>This is urgent.</p>"
        };

        await emailSender.SendAsync(message);
    }
}
```

## Monitoring

### Database Queries

```sql
-- Queue depth by status
SELECT Status, COUNT(*) FROM OutboundEmails GROUP BY Status;

-- Recent failures
SELECT * FROM OutboundEmails
WHERE Status = 'Failed'
ORDER BY LastAttemptAt DESC;

-- Emails sent in last 24 hours
SELECT COUNT(*) FROM OutboundEmails
WHERE Status = 'Sent' AND SentAt > DATEADD(hour, -24, GETUTCDATE());
```

### Structured Logging

Logs include these fields for filtering:

| Field | Description |
|-------|-------------|
| `EmailId` | Database record ID |
| `To` | Recipient (masked for privacy) |
| `TemplateKey` | Template used |
| `Status` | Delivery status |
| `MessageId` | Provider's message ID |

## Privacy

Email addresses are automatically masked in logs using `EmailMaskingUtility`:

- `john.doe@example.com` → `j***e@example.com`
- Prevents PII leakage to log aggregators
- Use the `mask_email` filter in templates if displaying emails