using Application.Common.Configuration;
using Application.Common.Email;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Domain.Entities.Email;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Services;

/// <summary>
/// Background service that processes the email queue and sends emails.
/// Uses adaptive polling: faster when busy, slower when idle.
/// </summary>
public class EmailQueueProcessor(
    IServiceProvider serviceProvider,
    IOptions<EmailQueueOptions> options,
    ILogger<EmailQueueProcessor> logger)
    : BackgroundService
{
    private readonly EmailQueueOptions _options = options.Value;

    // Adaptive polling intervals
    private static readonly TimeSpan MinPollingInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxPollingInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PollingStepUp = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            logger.LogInformation("Email queue processor is disabled");
            return;
        }

        logger.LogInformation(
            "Email queue processor started. BatchSize={BatchSize}, MaxPollingInterval={MaxInterval}s",
            _options.BatchSize,
            MaxPollingInterval.TotalSeconds);

        var currentInterval = MinPollingInterval;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processedCount = await ProcessBatchAsync(stoppingToken);

                // Adaptive polling: process faster when there's work
                if (processedCount > 0)
                {
                    currentInterval = MinPollingInterval;
                    logger.LogDebug("Processed {Count} emails, polling at minimum interval", processedCount);
                }
                else
                {
                    // Gradually slow down when idle
                    currentInterval = currentInterval + PollingStepUp;
                    if (currentInterval > MaxPollingInterval)
                        currentInterval = MaxPollingInterval;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing email queue batch");
                currentInterval = MaxPollingInterval; // Back off on errors
            }

            await Task.Delay(currentInterval, stoppingToken);
        }

        logger.LogInformation("Email queue processor stopped");
    }

    private async Task<int> ProcessBatchAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();

        var repository = scope.ServiceProvider.GetRequiredService<IOutboundEmailRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var emailSender = scope.ServiceProvider.GetRequiredService<IEmailSender>();

        var emails = await repository.GetPendingEmailsAsync(_options.BatchSize, cancellationToken);

        if (emails.Count == 0)
            return 0;

        logger.LogDebug("Processing batch of {Count} emails", emails.Count);

        var processedCount = 0;

        foreach (var email in emails)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            try
            {
                email.MarkProcessing();
                await unitOfWork.CommitAsync(cancellationToken);

                var message = new EmailMessage
                {
                    To = email.To,
                    Subject = email.Subject,
                    HtmlBody = email.HtmlBody,
                    TextBody = email.TextBody
                };

                var result = await emailSender.SendAsync(message, cancellationToken);

                if (result.Success)
                {
                    email.MarkSent(result.MessageId);
                    logger.LogInformation(
                        "Email sent successfully. Id={EmailId}, To={To}, MessageId={MessageId}",
                        email.Id, email.To, result.MessageId);
                }
                else
                {
                    email.RecordFailure(result.ErrorMessage ?? "Unknown error");
                    logger.LogWarning(
                        "Email delivery failed. Id={EmailId}, To={To}, Attempt={Attempt}/{MaxAttempts}, Error={Error}",
                        email.Id, email.To, email.Attempts, email.MaxAttempts, result.ErrorMessage);
                }

                await unitOfWork.CommitAsync(cancellationToken);
                processedCount++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "Unexpected error processing email. Id={EmailId}, To={To}",
                    email.Id, email.To);

                email.RecordFailure($"Exception: {ex.Message}");
                await unitOfWork.CommitAsync(cancellationToken);
            }
        }

        return processedCount;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Email queue processor stopping");
        await base.StopAsync(cancellationToken);
    }
}