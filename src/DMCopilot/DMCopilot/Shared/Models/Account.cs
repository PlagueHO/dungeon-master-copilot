using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace DMCopilot.Shared.Models
{
    /// <summary>
    /// Represents an account in the system.
    /// </summary>
    public class Account
    {
        /// <summary>
        /// Gets or sets the unique identifier for the account.
        /// This will be the email address of the user.
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public String Id { get; set; }

        /// <summary>
        /// Gets or sets the name of the account.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public String Name { get; set; }

        /// <summary>
        /// Gets or sets the active tenant for the account.
        /// </summary>
        [JsonProperty(PropertyName = "activetenantid")]
        public Guid ActiveTenantId { get; set; }

        /// <summary>
        /// Gets or sets the list of Tenant Roles associated with the account.
        /// </summary>
        [JsonProperty(PropertyName = "tenantroles")]

        public List<AccountTenantRole> TenantRoles { get; set; } = new List<AccountTenantRole>();

        /// <summary>
        /// Initializes a new instance of the <see cref="Account"/> class.
        /// </summary>
        /// <param name="id">The unique id for the account.</param>
        /// <param name="name">The name of the account.</param>
        /// <param name="email">The email address associated with the account.</param>
        /// <param name="activeTenantId">The currently active tenant.</param>
        /// <param name="tenantRoles">The roles the account has in any tenants.</param>
        public Account(String id, String name, Guid activeTenantId, List<AccountTenantRole> tenantRoles)
        {
            Id = id;
            Name = name;
            ActiveTenantId = activeTenantId;
            TenantRoles = tenantRoles;
        }

        public void AddTenantRole(AccountTenantRole tenantRole)
        {
            TenantRoles.Add(tenantRole);
        }
    }

    /// <summary>
    ///  The role of the account in a tenant.
    /// </summary>
    public enum TenantRole
    {
        Owner,
        Admin,
        Contributor,
        Reader
    }

    /// <summary>
    /// Represents the tenants that the account has access to and the role they have in the tenant.
    /// </summary>
    public class AccountTenantRole {
        [JsonProperty(PropertyName = "tenantid")]
        public Guid TenantId { get; set; }

        [JsonProperty(PropertyName = "email")]
        public String Email { get; set; }

        [JsonProperty(PropertyName = "name")]
        public String Name { get; set; }

        [JsonProperty(PropertyName = "type")]
        public TenantType Type { get; set; }

        [JsonProperty(PropertyName = "role")]
        public TenantRole Role { get; set; }

        public AccountTenantRole(Guid tenantId, String email, String name, TenantType type, TenantRole role)
        {
            TenantId = tenantId;
            Email = email;
            Name = name;
            Type = type;
            Role = role;
        }
    }
}
