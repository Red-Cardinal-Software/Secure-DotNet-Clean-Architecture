using Domain.Entities.Identity;

namespace Application.Interfaces.Repositories;

/// <summary>
/// Repository for accessing organization data.
/// </summary>
public interface IOrganizationRepository
{
    /// <summary>
    /// Gets an organization by name.
    /// </summary>
    Task<Organization?> GetByNameAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an organization by ID.
    /// </summary>
    Task<Organization?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
}