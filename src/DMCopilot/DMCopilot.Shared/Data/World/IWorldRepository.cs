﻿using DMCopilot.Shared.Models;
using Microsoft.Azure.Cosmos;

namespace DMCopilot.Shared.Data
{
    public interface IWorldRepository
    {
        Task<World> GetWorldAsync(Guid id, Guid tenantId);
        Task<World> GetWorldByNameAsync(Guid tenantId, string name);
        Task<IEnumerable<World>> GetWorldsByTenantAsync(Guid tenantId);
        Task<World> CreateWorldAsync(World world);
        Task<World> UpdateWorldAsync(Guid id, World world);
        Task<Boolean> DeleteWorldAsync(Guid id, Guid tenantId);
    }
}