using Application.Common.Exceptions;
using Application.Interfaces.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

/// <summary>
/// The UnitOfWork class provides a unified mechanism for managing
/// database transactions and saving changes to the underlying data store
/// in an atomic manner. It coordinates work between multiple repositories
/// to maintain consistency and manage the application's database context.
/// </summary>
/// <remarks>
/// Implements the IUnitOfWork interface to enforce a standard contract
/// for Commit operation across the application infrastructure.
/// </remarks>
public class UnitOfWork(AppDbContext context) : IUnitOfWork
{
    public async Task<int> CommitAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            throw new ConcurrencyException("A concurrency conflict occurred during save.", ex);
        }
    }
}
