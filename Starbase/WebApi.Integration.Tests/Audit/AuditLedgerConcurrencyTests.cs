using Application.DTOs.Audit;
using Application.Interfaces.Services;
using Domain.Entities.Audit;
using FluentAssertions;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebApi.Integration.Tests.Fixtures;
using Xunit;

namespace WebApi.Integration.Tests.Audit;

/// <summary>
/// Regression tests for how the audit ledger append path interacts with the caller's unit of work
/// and with concurrent writers.
/// </summary>
/// <remarks>
/// These cover two defects that the happy-path ledger tests could not see, because both require
/// either a dirty audited entity in the caller's scope or genuine concurrency:
/// <list type="number">
/// <item>Appending re-entered itself through <c>AuditInterceptor</c> and self-deadlocked on a
/// non-reentrant static semaphore.</item>
/// <item>Appending committed the caller's unit of work, persisting unrelated in-flight changes.</item>
/// </list>
/// </remarks>
[Collection(IntegrationTestCollection.Name)]
public class AuditLedgerConcurrencyTests(SqlServerContainerFixture dbFixture) : IntegrationTestBase(dbFixture)
{
    /// <summary>
    /// Bounds every await in this file so a regression fails the run instead of hanging it.
    /// The original bug had no timeout and blocked forever.
    /// </summary>
    private static readonly TimeSpan DeadlockTimeout = TimeSpan.FromSeconds(60);

    private static CreateAuditEntryDto NewEntry(string username) => new()
    {
        EventType = AuditEventType.Authentication,
        Action = AuditAction.LoginSuccess,
        Username = username,
        IpAddress = "203.0.113.10",
        Success = true
    };

    [Fact]
    public async Task RecordAsync_WithDirtyAuditedEntityInSameScope_DoesNotDeadlock()
    {
        var user = await CreateTestUserAsync();

        // AppUser is [Audited]. Leaving it modified-but-unsaved in the same scope is what used to
        // make the ledger's own SaveChanges fire AuditInterceptor, which called back into
        // RecordBatchAsync and blocked forever on the static append lock.
        var append = WithScopeAsync(async serviceProvider =>
        {
            var dbContext = serviceProvider.GetRequiredService<AppDbContext>();
            var tracked = await dbContext.AppUsers.FirstAsync(u => u.Id == user.Id);
            tracked.ChangeFirstName("DirtyBeforeAudit");

            var auditLedger = serviceProvider.GetRequiredService<IAuditLedger>();
            var result = await auditLedger.RecordAsync(NewEntry("deadlock-probe@example.com"));

            result.Success.Should().BeTrue();
        });

        await append.WaitAsync(DeadlockTimeout);
    }

    [Fact]
    public async Task RecordAsync_DoesNotCommitCallersPendingChanges()
    {
        var user = await CreateTestUserAsync();
        var originalFirstName = user.FirstName;

        await WithScopeAsync(async serviceProvider =>
        {
            var dbContext = serviceProvider.GetRequiredService<AppDbContext>();
            var tracked = await dbContext.AppUsers.FirstAsync(u => u.Id == user.Id);
            tracked.ChangeFirstName("ShouldNeverBePersisted");

            var auditLedger = serviceProvider.GetRequiredService<IAuditLedger>();
            var result = await auditLedger.RecordAsync(NewEntry("isolation-probe@example.com"));

            result.Success.Should().BeTrue();
            // Deliberately no SaveChangesAsync - the scope is abandoned, as a failed request would.
        }).WaitAsync(DeadlockTimeout);

        // The audit write must not have flushed the caller's unsaved change.
        await WithDbContextAsync(async dbContext =>
        {
            var reloaded = await dbContext.AppUsers.AsNoTracking().FirstAsync(u => u.Id == user.Id);
            reloaded.FirstName.Should().Be(originalFirstName);
        });
    }

    [Fact]
    public async Task RecordAsync_UnderConcurrentWriters_ProducesAnUnbrokenChain()
    {
        const int writers = 12;

        var sequenceNumbersBefore = await WithDbContextAsync(async dbContext =>
            await dbContext.AuditLedger.AnyAsync()
                ? await dbContext.AuditLedger.MaxAsync(e => e.SequenceNumber)
                : 0L);

        // Each writer gets its own scope, mimicking concurrent requests. Sequence allocation and
        // tail-hash read must be atomic or these collide on the primary key / fork the chain.
        var appends = Enumerable.Range(0, writers).Select(i =>
            WithServiceAsync<IAuditLedger>(async auditLedger =>
            {
                var result = await auditLedger.RecordAsync(NewEntry($"concurrent-{i}@example.com"));
                result.Success.Should().BeTrue();
            }));

        await Task.WhenAll(appends).WaitAsync(DeadlockTimeout);

        await WithDbContextAsync(async dbContext =>
        {
            var appended = await dbContext.AuditLedger
                .AsNoTracking()
                .Where(e => e.SequenceNumber > sequenceNumbersBefore)
                .OrderBy(e => e.SequenceNumber)
                .ToListAsync();

            appended.Should().HaveCount(writers, "every concurrent append must land exactly once");

            appended.Select(e => e.SequenceNumber).Should().OnlyHaveUniqueItems();
            appended.Select(e => e.SequenceNumber).Should().BeInAscendingOrder();

            // Contiguous: no gaps introduced by a losing writer.
            var expected = Enumerable.Range(1, writers).Select(i => sequenceNumbersBefore + i);
            appended.Select(e => e.SequenceNumber).Should().Equal(expected);

            // Each entry must chain to its predecessor.
            for (var i = 1; i < appended.Count; i++)
            {
                appended[i].PreviousHash.Should().Be(
                    appended[i - 1].Hash,
                    "entry {0} must chain to entry {1}",
                    appended[i].SequenceNumber,
                    appended[i - 1].SequenceNumber);
            }
        });

        // And the ledger's own verifier must agree the chain is intact.
        await WithServiceAsync<IAuditLedger>(async auditLedger =>
        {
            var verification = await auditLedger.VerifyIntegrityAsync();
            verification.Success.Should().BeTrue();
            verification.Data!.IsValid.Should().BeTrue(
                "concurrent appends must not fork the hash chain");
        });
    }
}