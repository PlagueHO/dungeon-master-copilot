using DMCopilot.Shared.Data;
using DMCopilot.Shared.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;

namespace DMCopilot.Shared.Services
{
    /// <summary>
    /// Service for managing user accounts and tenants.
    /// </summary>
    public class AccessService : IAccessService
    {
        public Account Account { get; private set; }
        public Tenant Tenant { get; private set; }
        public Boolean IsLoaded => Account != null && Tenant != null;
        private readonly IAccountRepository _accountRepository;
        private readonly ITenantRepository _tenantRepository;
        private readonly ILogger<AccessService> _logger;

        public AccessService(IAccountRepository accountRepository, ITenantRepository tenantRepository, ILogger<AccessService> logger)
        {
            _accountRepository = accountRepository;
            _tenantRepository = tenantRepository;
            _logger = logger;
            _logger.LogInformation("Creating Access Service");
        }

        /// <summary>
        /// Uses the authentication context to get or create the account and tenant for the user.
        /// </summary>
        /// <param name="context">The authentication state for the user.</param>
        /// <returns>The account details for the user.</returns>
        public async Task<Account> InitializeUsingContext(AuthenticationState context)
        {
            // If the authentication context for the user is null, then fail
            if (context.User == null || context.User.Identity?.Name == null)
            {
                throw new NotAuthenticatedException();
            }

            // Obtain the email address of the user from the authentication context
            var email = context.User.Identity.Name;

            try
            {
                // See if the account already exists
                Account = await _accountRepository.GetAccountAsync(email);
                try
                {
                    // The accounts exists, so check if the tenant matching the active tenant exists
                    Tenant = await _tenantRepository.GetTenantAsync(Account.ActiveTenantId);
                }
                catch (TenantNotFoundException)
                {
                    // The tenant does not exist, so create it
                    Tenant = await InitializeTenantAsync(context);
                }
            }
            catch (AccountNotFoundException)
            {
                // The account does not exist so create it
                Account = await InitializeAccountAsync(context);
            }

            return Account;
        }

        private async Task<Account> InitializeAccountAsync(AuthenticationState context)
        {
            // If the authentication context for the user is null, then fail
            if (context.User.Identity?.Name == null)
            {
                throw new NotAuthenticatedException();
            }

            // Create a new individual tenant for the account
            var tenant = await InitializeTenantAsync(context);

            if (tenant == null)
            {
                throw new TenantNotFoundException("Tenant could not be created.");
            }

            // Create the account for the user and associate the individual tenant with it
            var email = context.User.Identity.Name;
            var name = context.User.Claims.FirstOrDefault(c => c.Type == "name")?.Value ?? email;

            var tenantRoles = new List<AccountTenantRole> {
                new AccountTenantRole(tenant.Id, email, name, TenantType.Individual, TenantRole.Owner)
            };
            var account = new Account(email, name, tenant.Id, tenantRoles);
            await _accountRepository.CreateAccountAsync(account);
            
            _logger.LogInformation("Creating account for '{email}'.", email);
            
            return account;
        }

        private async Task<Tenant> InitializeTenantAsync(AuthenticationState context)
        {
            // If the authentication context for the user is null, then fail
            if (context.User.Identity?.Name == null)
            {
                throw new NotAuthenticatedException();
            }

            // Create a new individual tenant for the user account
            var email = context.User.Identity.Name;
            var name = context.User.Claims.FirstOrDefault(c => c.Type == "name")?.Value ?? email;
            var tenant = new Tenant(Guid.NewGuid(), name, email, TenantType.Individual);
            await _tenantRepository.CreateTenantAsync(tenant);
            
            _logger.LogInformation("Creating individual tenant for '{email}'.", email);
            
            return tenant;
        }
    }
}