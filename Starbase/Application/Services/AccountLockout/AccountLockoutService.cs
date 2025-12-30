using Application.Common.Configuration;
using Application.Common.Services;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Domain.Entities.Security;
using Microsoft.Extensions.Options;

namespace Application.Services.AccountLockout;

/// <summary>
/// Service implementation for managing account lockout functionality.
/// Provides methods for tracking login attempts, managing account lockout state,
/// and implementing security policies to protect against brute force attacks.
/// </summary>
public class AccountLockoutService(
    IAccountLockoutRepository accountLockoutRepository,
    ILoginAttemptRepository loginAttemptRepository,
    IUnitOfWork unitOfWork,
    IOptions<AccountLockoutOptions> accountLockoutOptions)
    : BaseAppService(unitOfWork), IAccountLockoutService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    /// <summary>
    /// Records a failed login attempt for the specified user and determines
    /// if the account should be locked based on configured policies.
    /// </summary>
    public async Task<bool> RecordFailedAttemptAsync(
        Guid userId,
        string username,
        string? ipAddress,
        string? userAgent,
        string failureReason,
        CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Record the failed attempt
        var failedAttempt = LoginAttempt.CreateFailed(
            userId,
            username,
            failureReason,
            ipAddress,
            userAgent);

        await loginAttemptRepository.AddAsync(failedAttempt, cancellationToken);

        // Only proceed with lockout logic if the attempt should count towards lockout
        if (!failedAttempt.ShouldCountTowardsLockout())
        {
            return false;
        }

        // Get lockout configuration from strongly typed options
        var lockoutConfig = accountLockoutOptions.Value;

        // Skip lockout if disabled
        if (!lockoutConfig.EnableAccountLockout)
        {
            return false;
        }

        // Get or create a lockout record
        var lockout = await accountLockoutRepository.GetOrCreateAsync(userId, cancellationToken);

        // Record the failed attempt and check if an account should be locked
        var wasLocked = lockout.RecordFailedAttempt(
            lockoutConfig.FailedAttemptThreshold,
            lockoutConfig.BaseLockoutDuration,
            lockoutConfig.MaxLockoutDuration,
            lockoutConfig.AttemptResetWindow);

        return wasLocked;
    }, () =>
    {
        // Concurrency conflict - another request updated the lockout count simultaneously.
        // The count was still incremented by the successful request, so return false
        // and let the next attempt see the correct state.
        return false;
    });

    /// <summary>
    /// Records a successful login attempt for the specified user,
    /// which resets the failed attempt counter and unlocks the account if it was
    /// locked due to failed attempts.
    /// </summary>
    public async Task RecordSuccessfulLoginAsync(
        Guid userId,
        string username,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        // Record the successful attempt if tracking is enabled
        var lockoutConfig = accountLockoutOptions.Value;
        if (lockoutConfig.TrackLoginAttempts)
        {
            var successfulAttempt = LoginAttempt.CreateSuccessful(
                userId,
                username,
                ipAddress,
                userAgent);

            await loginAttemptRepository.AddAsync(successfulAttempt, cancellationToken);
        }

        // Get an existing lockout record if it exists
        var lockout = await accountLockoutRepository.GetByUserIdAsync(userId, cancellationToken);
        if (lockout is not null)
        {
            // Reset failed attempts and unlock if locked due to failed attempts
            lockout.RecordSuccessfulLogin();
        }
    });

    /// <summary>
    /// Checks if the specified user account is currently locked out.
    /// </summary>
    public async Task<Domain.Entities.Security.AccountLockout?> GetAccountLockoutAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var lockout = await accountLockoutRepository.GetByUserIdAsync(userId, cancellationToken);

        // If no lockout record exists, the user is not locked
        if (lockout == null)
            return null;

        // Check if lockout has expired and auto-unlock if needed
        if (lockout.HasLockoutExpired() && lockout.IsLockedOut)
        {
            lockout.UnlockAccount(resetFailedAttempts: false);
            await _unitOfWork.CommitAsync(cancellationToken);
            return null;
        }

        return lockout.IsLockedOut ? lockout : null;
    }

    /// <summary>
    /// Determines if a user account is currently locked out.
    /// </summary>
    public async Task<bool> IsAccountLockedOutAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var lockout = await GetAccountLockoutAsync(userId, cancellationToken);
        return lockout?.IsLockedOut == true;
    }

    /// <summary>
    /// Manually locks a user account with the specified duration and reason.
    /// This is typically used by administrators for security or policy enforcement.
    /// </summary>
    public async Task LockAccountAsync(
        Guid userId,
        TimeSpan? duration,
        string reason,
        Guid lockedByUserId,
        CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var lockout = await accountLockoutRepository.GetOrCreateAsync(userId, cancellationToken);

        lockout.LockAccount(duration, reason, lockedByUserId);
    });

    /// <summary>
    /// Manually unlocks a user account and optionally resets the failed attempt counter.
    /// This is typically used by administrators to restore account access.
    /// </summary>
    public async Task UnlockAccountAsync(
        Guid userId,
        bool resetFailedAttempts = true,
        CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var lockout = await accountLockoutRepository.GetByUserIdAsync(userId, cancellationToken);
        lockout?.UnlockAccount(resetFailedAttempts);
    });

    /// <summary>
    /// Gets the remaining lockout duration for a user account.
    /// </summary>
    public async Task<TimeSpan?> GetRemainingLockoutDurationAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        var lockout = await GetAccountLockoutAsync(userId, cancellationToken);
        return lockout?.GetRemainingLockoutDuration();
    }

    /// <summary>
    /// Gets recent login attempts for a user within the specified time period.
    /// This can be used for security auditing and analysis.
    /// </summary>
    public async Task<IReadOnlyList<LoginAttempt>> GetRecentLoginAttemptsAsync(
        Guid userId,
        TimeSpan timePeriod,
        bool includeSuccessful = false,
        CancellationToken cancellationToken = default)
    {
        var since = DateTimeOffset.UtcNow.Subtract(timePeriod);
        return await loginAttemptRepository.GetRecentAttemptsAsync(userId, since, includeSuccessful, cancellationToken);
    }

    /// <summary>
    /// Performs cleanup of old login attempt records based on configured retention policies.
    /// This should be called periodically to prevent database growth.
    /// </summary>
    public async Task<int> CleanupOldLoginAttemptsAsync(
        TimeSpan retentionPeriod,
        CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var cutoffDate = DateTimeOffset.UtcNow.Subtract(retentionPeriod);
        return await loginAttemptRepository.DeleteOldAttemptsAsync(cutoffDate, cancellationToken);
    });

    /// <summary>
    /// Automatically unlocks accounts whose lockout period has expired.
    /// This should be called periodically to process automatic unlocks.
    /// Processes lockouts in batches to prevent memory issues.
    /// </summary>
    public async Task<int> ProcessExpiredLockoutsAsync(CancellationToken cancellationToken = default) => await RunWithCommitAsync(async () =>
    {
        var totalProcessed = 0;
        const int batchSize = 100;
        var currentPage = 1;

        // Process expired lockouts in batches to prevent memory issues
        while (true)
        {
            var expiredLockouts = await accountLockoutRepository.GetExpiredLockoutsAsync(currentPage, batchSize, cancellationToken);

            if (!expiredLockouts.Any())
                break;

            foreach (var lockout in expiredLockouts)
            {
                lockout.UnlockAccount(resetFailedAttempts: false);
            }

            totalProcessed += expiredLockouts.Count;
            currentPage++;

            // If we got fewer results than batch size, we've processed all
            if (expiredLockouts.Count < batchSize)
                break;
        }

        return totalProcessed;
    });

}