using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DMCopilot.Shared.Models;

namespace DMCopilot.Shared.Data
{
    public interface IAccountRepository
    {
        Task<Account> GetAccountAsync(String id);
        Task<IEnumerable<Account>> GetAccountsAsync();
        Task<Account> CreateAccountAsync(Account account);
        Task<Account> UpdateAccountAsync(String id, Account account);
        Task<Boolean> DeleteAccountAsync(String ir);
    }
}
