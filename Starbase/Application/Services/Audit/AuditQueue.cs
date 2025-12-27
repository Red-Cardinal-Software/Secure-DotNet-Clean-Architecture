using System.Threading.Channels;
using Application.DTOs.Audit;
using Application.Interfaces.Services;

namespace Application.Services.Audit;

/// <summary>
/// In-memory queue for audit entries using Channel&lt;T&gt;.
/// Provides high-performance, thread-safe queueing for background processing.
/// </summary>
public class AuditQueue : IAuditQueue
{
    private readonly Channel<CreateAuditEntryDto> _channel = Channel.CreateUnbounded<CreateAuditEntryDto>(new UnboundedChannelOptions
    {
        SingleReader = true,  // Background service is the only reader
        SingleWriter = false  // Multiple threads may write
    });
    private int _count;

    // Unbounded channel - we don't want to drop audit entries
    // In production, consider bounded with a large capacity to prevent OOM
    // Background service is the only reader
    // Multiple threads may write

    /// <inheritdoc />
    public async ValueTask EnqueueAsync(CreateAuditEntryDto entry, CancellationToken cancellationToken = default)
    {
        await _channel.Writer.WriteAsync(entry, cancellationToken);
        Interlocked.Increment(ref _count);
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<CreateAuditEntryDto> DequeueAllAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await foreach (var entry in _channel.Reader.ReadAllAsync(cancellationToken))
        {
            Interlocked.Decrement(ref _count);
            yield return entry;
        }
    }

    /// <inheritdoc />
    public int Count => _count;
}