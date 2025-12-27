using Domain.Constants;
using Domain.Entities.Identity;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence.Seeders;

/// <summary>
/// Seeds the default organization for the system.
/// Admin user creation is handled via the one-time /api/setup endpoint.
/// </summary>
[DbDataSeeder]
public class OrganizationSeeder : IEntitySeeder
{
    public void PerformSeeding(DbContext dbContext)
    {
        PerformSeedingAsync(dbContext).Wait();
    }

    public async Task PerformSeedingAsync(DbContext dbContext)
    {
        var orgSet = dbContext.Set<Organization>();

        // Ensure default organization exists
        var org = await orgSet.FirstOrDefaultAsync(o => o.Name == SystemDefaults.DefaultOrganizationName);
        if (org is null)
        {
            org = new Organization(SystemDefaults.DefaultOrganizationName);
            await orgSet.AddAsync(org);
            await dbContext.SaveChangesAsync();
        }
    }
}