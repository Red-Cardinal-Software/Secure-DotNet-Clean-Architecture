using Application.Common.Email;
using static Application.Common.Email.EmailMaskingUtility;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Domain.Entities.Email;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Emailing;

/// <summary>
/// Database-backed email queue for reliable email delivery.
/// </summary>
public class EmailQueue(
    IOutboundEmailRepository repository,
    IUnitOfWork unitOfWork,
    ILogger<EmailQueue> logger) : IEmailQueue
{
    /// <inheritdoc />
    public async Task<Guid> QueueAsync(
        string to,
        string subject,
        string htmlBody,
        string? textBody = null,
        string? templateKey = null,
        Guid? organizationId = null,
        string? correlationId = null,
        int priority = 10,
        CancellationToken cancellationToken = default)
    {
        var email = new OutboundEmail(
            to: to,
            subject: subject,
            htmlBody: htmlBody,
            textBody: textBody,
            templateKey: templateKey,
            organizationId: organizationId,
            correlationId: correlationId,
            priority: priority);

        await repository.AddAsync(email, cancellationToken);
        await unitOfWork.CommitAsync(cancellationToken);

        logger.LogInformation(
            "Email queued for delivery. Id: {EmailId}, To: {To}, Template: {TemplateKey}",
            email.Id, MaskEmail(to), templateKey ?? "none");

        return email.Id;
    }

    /// <inheritdoc />
    public async Task<Guid> QueueAsync(
        string to,
        RenderedEmailTemplate email,
        Guid? organizationId = null,
        string? correlationId = null,
        int priority = 10,
        CancellationToken cancellationToken = default)
    {
        return await QueueAsync(
            to: to,
            subject: email.Subject,
            htmlBody: email.HtmlBody,
            textBody: email.TextBody,
            templateKey: email.TemplateKey,
            organizationId: organizationId,
            correlationId: correlationId,
            priority: priority,
            cancellationToken: cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> CancelAsync(Guid emailId, CancellationToken cancellationToken = default)
    {
        var email = await repository.GetByIdAsync(emailId, cancellationToken);

        if (email == null)
        {
            logger.LogWarning("Attempted to cancel non-existent email: {EmailId}", emailId);
            return false;
        }

        if (email.Status == OutboundEmailStatus.Sent)
        {
            logger.LogWarning("Attempted to cancel already sent email: {EmailId}", emailId);
            return false;
        }

        if (email.Status == OutboundEmailStatus.Cancelled)
        {
            return true; // Already cancelled
        }

        email.Cancel();
        await unitOfWork.CommitAsync(cancellationToken);

        logger.LogInformation("Email cancelled: {EmailId}", emailId);
        return true;
    }

    /// <inheritdoc />
    public async Task<EmailQueueStatus?> GetStatusAsync(Guid emailId, CancellationToken cancellationToken = default)
    {
        var email = await repository.GetByIdAsync(emailId, cancellationToken);

        if (email == null)
            return null;

        return new EmailQueueStatus
        {
            Id = email.Id,
            To = email.To,
            Subject = email.Subject,
            Status = email.Status.ToString(),
            Attempts = email.Attempts,
            MaxAttempts = email.MaxAttempts,
            ErrorMessage = email.ErrorMessage,
            SentAt = email.SentAt,
            CreatedAt = email.CreatedAt,
            NextAttemptAt = email.NextAttemptAt
        };
    }
}