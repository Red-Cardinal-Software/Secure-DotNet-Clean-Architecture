using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Application.Common.Factories;
using Application.Common.Services;
using Application.DTOs.Audit;
using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Application.Interfaces.Services;
using Application.Models;
using AutoMapper;
using Domain.Entities.Audit;
using Microsoft.Extensions.Logging;

namespace Application.Services.Audit;

/// <summary>
/// Service implementation for the audit ledger with cryptographic hash chain.
/// </summary>
public class AuditLedgerService(
    IAuditLedgerRepository repository,
    IUnitOfWork unitOfWork,
    IMapper mapper,
    ILogger<AuditLedgerService> logger)
    : BaseAppService(unitOfWork), IAuditLedger
{
    /// <summary>
    /// Genesis hash for the first entry in the ledger.
    /// </summary>
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly SemaphoreSlim AppendLock = new(1, 1);

    /// <inheritdoc />
    public async Task<ServiceResponse<AuditEntryDto>> RecordAsync(CreateAuditEntryDto entry)
    {
        var result = await RecordBatchAsync([entry]);
        if (!result.Success || result.Data == null || result.Data.Count == 0)
        {
            return ServiceResponseFactory.Error<AuditEntryDto>(result.Message, result.Status);
        }

        return ServiceResponseFactory.Success(result.Data[0]);
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<List<AuditEntryDto>>> RecordBatchAsync(IEnumerable<CreateAuditEntryDto> entries)
    {
        await AppendLock.WaitAsync();
        try
        {
            return await RunWithCommitAsync(async () =>
            {
                var entryList = entries.ToList();
                if (entryList.Count == 0)
                {
                    return ServiceResponseFactory.Success(new List<AuditEntryDto>());
                }

                var nextSequence = await repository.GetNextSequenceNumberAsync();
                var previousHash = await repository.GetLastHashAsync();
                if (string.IsNullOrEmpty(previousHash))
                {
                    previousHash = GenesisHash;
                }

                var ledgerEntries = new List<AuditLedgerEntry>();
                var now = DateTime.UtcNow;

                foreach (var entry in entryList)
                {
                    var ledgerEntry = CreateLedgerEntry(entry, nextSequence, previousHash, now);
                    ledgerEntries.Add(ledgerEntry);

                    previousHash = ledgerEntry.Hash;
                    nextSequence++;
                }

                await repository.AppendAsync(ledgerEntries);

                logger.LogInformation(
                    "Recorded {Count} audit entries, sequences {First}-{Last}",
                    ledgerEntries.Count,
                    ledgerEntries.First().SequenceNumber,
                    ledgerEntries.Last().SequenceNumber);

                return ServiceResponseFactory.Success(mapper.Map<List<AuditEntryDto>>(ledgerEntries));
            });
        }
        finally
        {
            AppendLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<PagedResult<AuditEntryDto>>> QueryAsync(AuditQueryDto query)
    {
        var pageSize = Math.Min(Math.Max(query.PageSize, 1), 100);
        var page = Math.Max(query.Page, 1);
        var skip = (page - 1) * pageSize;

        var (items, totalCount) = await repository.QueryAsync(
            q => ApplyFilters(q, query),
            skip,
            pageSize);

        return ServiceResponseFactory.Success(new PagedResult<AuditEntryDto>
        {
            Items = mapper.Map<List<AuditEntryDto>>(items),
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize
        });
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<List<AuditEntryDto>>> GetEntityHistoryAsync(string entityType, string entityId)
    {
        var (items, _) = await repository.QueryAsync(
            q => q.Where(e => e.EntityType == entityType && e.EntityId == entityId)
                  .OrderByDescending(e => e.SequenceNumber),
            0,
            1000);

        return ServiceResponseFactory.Success(mapper.Map<List<AuditEntryDto>>(items));
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<List<AuditEntryDto>>> GetUserActivityAsync(
        Guid userId,
        DateTime? fromDate = null,
        DateTime? toDate = null)
    {
        var (items, _) = await repository.QueryAsync(
            q =>
            {
                var filtered = q.Where(e => e.UserId == userId);
                if (fromDate.HasValue)
                    filtered = filtered.Where(e => e.OccurredAt >= fromDate.Value);
                if (toDate.HasValue)
                    filtered = filtered.Where(e => e.OccurredAt <= toDate.Value);
                return filtered.OrderByDescending(e => e.SequenceNumber);
            },
            0,
            1000);

        return ServiceResponseFactory.Success(mapper.Map<List<AuditEntryDto>>(items));
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<LedgerVerificationResult>> VerifyIntegrityAsync(
        long? fromSequence = null,
        long? toSequence = null)
    {
        var (minSeq, maxSeq) = await repository.GetSequenceRangeAsync();

        if (minSeq == 0 && maxSeq == 0)
        {
            return ServiceResponseFactory.Success(new LedgerVerificationResult
            {
                IsValid = true,
                EntriesVerified = 0,
                FirstSequence = 0,
                LastSequence = 0
            });
        }

        var start = fromSequence ?? minSeq;
        var end = toSequence ?? maxSeq;

        var entries = await repository.GetRangeAsync(start, end);
        var issues = new List<LedgerIssue>();

        var previousHash = start == minSeq ? GenesisHash : null;

        if (start > minSeq && previousHash == null)
        {
            var prevEntries = await repository.GetRangeAsync(start - 1, start - 1);
            previousHash = prevEntries.FirstOrDefault()?.Hash ?? GenesisHash;
        }

        var expectedSequence = start;
        foreach (var entry in entries.OrderBy(e => e.SequenceNumber))
        {
            // Check for sequence gaps
            if (entry.SequenceNumber != expectedSequence)
            {
                issues.Add(new LedgerIssue
                {
                    SequenceNumber = expectedSequence,
                    IssueType = LedgerIssueType.SequenceGap,
                    Description = $"Expected sequence {expectedSequence}, found {entry.SequenceNumber}"
                });
            }

            // Verify hash chain
            var expectedHash = ComputeHash(entry, previousHash!);
            if (entry.Hash != expectedHash)
            {
                issues.Add(new LedgerIssue
                {
                    SequenceNumber = entry.SequenceNumber,
                    IssueType = LedgerIssueType.HashMismatch,
                    Description = $"Hash mismatch at sequence {entry.SequenceNumber}"
                });
            }

            previousHash = entry.Hash;
            expectedSequence = entry.SequenceNumber + 1;
        }

        var result = new LedgerVerificationResult
        {
            IsValid = issues.Count == 0,
            EntriesVerified = entries.Count,
            FirstSequence = start,
            LastSequence = end,
            Issues = issues
        };

        if (!result.IsValid)
        {
            logger.LogWarning(
                "Ledger integrity verification failed with {IssueCount} issues",
                issues.Count);
        }

        return ServiceResponseFactory.Success(result);
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<List<AuditEntryDto>>> GetUndispatchedAsync(int batchSize = 100)
    {
        var entries = await repository.GetUndispatchedAsync(batchSize);
        return ServiceResponseFactory.Success(mapper.Map<List<AuditEntryDto>>(entries));
    }

    /// <inheritdoc />
    public async Task<ServiceResponse<bool>> MarkDispatchedAsync(IEnumerable<long> sequenceNumbers)
    {
        return await RunWithCommitAsync(async () =>
        {
            await repository.MarkDispatchedAsync(sequenceNumbers);
            return ServiceResponseFactory.Success(true);
        });
    }

    #region Private Methods

    private AuditLedgerEntry CreateLedgerEntry(
        CreateAuditEntryDto dto,
        long sequenceNumber,
        string previousHash,
        DateTime occurredAt)
    {
        var entry = new AuditLedgerEntry
        {
            SequenceNumber = sequenceNumber,
            EventId = Guid.NewGuid(),
            OccurredAt = occurredAt,
            PreviousHash = previousHash,
            EventType = dto.EventType,
            Action = dto.Action,
            Success = dto.Success,
            FailureReason = dto.FailureReason,
            UserId = dto.UserId,
            Username = dto.Username,
            IpAddress = dto.IpAddress,
            UserAgent = dto.UserAgent,
            CorrelationId = dto.CorrelationId,
            EntityType = dto.EntityType,
            EntityId = dto.EntityId,
            OldValues = dto.OldValues,
            NewValues = dto.NewValues,
            AdditionalData = dto.AdditionalData,
            Dispatched = false
        };

        // Compute hash for this entry
        var hash = ComputeHash(entry, previousHash);

        // Return a new entry with the computed hash (since AuditLedgerEntry uses init properties)
        return new AuditLedgerEntry
        {
            SequenceNumber = entry.SequenceNumber,
            EventId = entry.EventId,
            OccurredAt = entry.OccurredAt,
            PreviousHash = entry.PreviousHash,
            Hash = hash,
            EventType = entry.EventType,
            Action = entry.Action,
            Success = entry.Success,
            FailureReason = entry.FailureReason,
            UserId = entry.UserId,
            Username = entry.Username,
            IpAddress = entry.IpAddress,
            UserAgent = entry.UserAgent,
            CorrelationId = entry.CorrelationId,
            EntityType = entry.EntityType,
            EntityId = entry.EntityId,
            OldValues = entry.OldValues,
            NewValues = entry.NewValues,
            AdditionalData = entry.AdditionalData,
            Dispatched = entry.Dispatched
        };
    }

    private static string ComputeHash(AuditLedgerEntry entry, string previousHash)
    {
        // Normalize OccurredAt to always have DateTimeKind.Utc for consistent JSON serialization.
        // SQL Server returns DateTime with Unspecified kind, but we store with Utc kind.
        // Without this normalization, "2025-01-01T12:00:00Z" vs "2025-01-01T12:00:00" would hash differently.
        var occurredAtUtc = DateTime.SpecifyKind(entry.OccurredAt, DateTimeKind.Utc);

        var hashInput = new
        {
            entry.SequenceNumber,
            entry.EventId,
            OccurredAt = occurredAtUtc,
            PreviousHash = previousHash,
            entry.EventType,
            entry.Action,
            entry.Success,
            entry.FailureReason,
            entry.UserId,
            entry.Username,
            entry.EntityType,
            entry.EntityId,
            entry.OldValues,
            entry.NewValues
        };

        var json = JsonSerializer.Serialize(hashInput, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private static IQueryable<AuditLedgerEntry> ApplyFilters(
        IQueryable<AuditLedgerEntry> query,
        AuditQueryDto filter)
    {
        if (filter.UserId.HasValue)
            query = query.Where(e => e.UserId == filter.UserId.Value);

        if (filter.EventType.HasValue)
            query = query.Where(e => e.EventType == filter.EventType.Value);

        if (filter.Action.HasValue)
            query = query.Where(e => e.Action == filter.Action.Value);

        if (!string.IsNullOrEmpty(filter.EntityType))
            query = query.Where(e => e.EntityType == filter.EntityType);

        if (!string.IsNullOrEmpty(filter.EntityId))
            query = query.Where(e => e.EntityId == filter.EntityId);

        if (filter.Success.HasValue)
            query = query.Where(e => e.Success == filter.Success.Value);

        if (filter.FromDate.HasValue)
            query = query.Where(e => e.OccurredAt >= filter.FromDate.Value);

        if (filter.ToDate.HasValue)
            query = query.Where(e => e.OccurredAt <= filter.ToDate.Value);

        return query.OrderByDescending(e => e.SequenceNumber);
    }

    #endregion
}