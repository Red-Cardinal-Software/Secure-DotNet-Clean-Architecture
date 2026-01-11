using Application.Interfaces.Persistence;
using Application.Interfaces.Repositories;
using Domain.Entities.Configuration;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

/// <summary>
/// Repository for email templates with support for organization-specific overrides.
/// </summary>
public class EmailTemplateRepository(ICrudOperator<EmailTemplate> emailTemplateCrudOperator) : IEmailTemplateRepository
{
    /// <inheritdoc />
    public Task<EmailTemplate?> GetEmailTemplateByKeyAsync(string key) =>
        emailTemplateCrudOperator.GetAll()
            .Where(et => et.Key == key.ToLowerInvariant() && et.OrganizationId == null)
            .FirstOrDefaultAsync();

    /// <inheritdoc />
    public Task<EmailTemplate?> GetTemplateAsync(string key, Guid? organizationId = null)
    {
        var normalizedKey = key.ToLowerInvariant();

        return emailTemplateCrudOperator.GetAll()
            .Where(et => et.Key == normalizedKey && et.OrganizationId == organizationId && et.IsActive)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetAllTemplateKeysAsync()
    {
        return await emailTemplateCrudOperator.GetAll()
            .Where(et => et.IsActive)
            .Select(et => et.Key)
            .Distinct()
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<EmailTemplate>> GetTemplatesByOrganizationAsync(Guid organizationId)
    {
        return await emailTemplateCrudOperator.GetAll()
            .Where(et => et.OrganizationId == organizationId)
            .ToListAsync();
    }

    /// <inheritdoc />
    public async Task AddAsync(EmailTemplate template)
    {
        await emailTemplateCrudOperator.AddAsync(template);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(Guid id)
    {
        var template = await emailTemplateCrudOperator.GetAll()
            .FirstOrDefaultAsync(et => et.Id == id);

        if (template != null)
        {
            emailTemplateCrudOperator.Delete(template);
        }
    }
}
