using DMCopilot.Shared.Models;
using Microsoft.AspNetCore.Components.Authorization;

namespace DMCopilot.Shared.Services
{
    public interface IAccessService
    {
        public Account Account { get; }
        public Tenant Tenant { get; }
        public Boolean IsLoaded { get; }
        public Task<Account> InitializeUsingContext(AuthenticationState context);
    }
}
