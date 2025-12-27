using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Domain.Entities.Identity;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

/// <summary>
/// Repository for accessing organization data.
/// </summary>
public class OrganizationRepository(
    ICrudOperator<Organization> crudOperator)
    : IOrganizationRepository
{
    public Task<Organization?> GetByNameAsync(string name, CancellationToken cancellationToken = default) =>
        crudOperator.GetAll()
            .FirstOrDefaultAsync(o => o.Name == name, cancellationToken);

    public Task<Organization?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        crudOperator.GetAll()
            .FirstOrDefaultAsync(o => o.Id == id, cancellationToken);
}