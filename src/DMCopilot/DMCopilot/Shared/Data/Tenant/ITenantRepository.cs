using DMCopilot.Shared.Models;
using Microsoft.Graph.Models;

namespace DMCopilot.Shared.Data
{
    public interface ITenantRepository
    {
        Task<Tenant> GetTenantAsync(Guid id);
        Task<Tenant> GetTenantByNameAsync(String name);
        Task<Tenant> GetTenantByOwnerEmailAsync(EmailAddress ownerEmail);
        Task<IEnumerable<Tenant>> GetTenantsAsync();
        Task<IEnumerable<Tenant>> GetTenantsByOwnerEmailAsync(EmailAddress ownerEmail);
        Task<Tenant> CreateTenantAsync(Tenant tenant);
        Task<Tenant> UpdateTenantAsync(Guid id, Tenant tenant);
        Task<Boolean> DeleteTenantAsync(Guid id);
    }
}