using Domain.Entities.Configuration;

namespace Application.Interfaces.Repositories;

/// <summary>
/// Interface defining the contract for interacting with email templates in the system.
/// Supports global and organization-specific templates.
/// </summary>
public interface IEmailTemplateRepository
{
    /// <summary>
    /// Retrieves an email template by its unique key (global template only).
    /// </summary>
    /// <param name="key">The unique key identifying the email template to retrieve.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains the <see cref="EmailTemplate"/>
    /// matching the provided key. Null is returned if no matching template is found.
    /// </returns>
    Task<EmailTemplate?> GetEmailTemplateByKeyAsync(string key);

    /// <summary>
    /// Retrieves an email template by key with optional organization-specific override.
    /// </summary>
    /// <param name="key">The unique key identifying the email template.</param>
    /// <param name="organizationId">Optional organization ID for tenant-specific template.</param>
    /// <returns>The matching template, or null if not found.</returns>
    Task<EmailTemplate?> GetTemplateAsync(string key, Guid? organizationId = null);

    /// <summary>
    /// Gets all unique template keys in the database.
    /// </summary>
    /// <returns>List of all template keys.</returns>
    Task<IReadOnlyList<string>> GetAllTemplateKeysAsync();

    /// <summary>
    /// Gets all templates for a specific organization.
    /// </summary>
    /// <param name="organizationId">The organization ID.</param>
    /// <returns>List of templates for the organization.</returns>
    Task<IReadOnlyList<EmailTemplate>> GetTemplatesByOrganizationAsync(Guid organizationId);

    /// <summary>
    /// Adds a new email template.
    /// </summary>
    /// <param name="template">The template to add.</param>
    Task AddAsync(EmailTemplate template);

    /// <summary>
    /// Deletes an email template.
    /// </summary>
    /// <param name="id">The template ID to delete.</param>
    Task DeleteAsync(Guid id);
}
