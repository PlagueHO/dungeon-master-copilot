using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DMCopilot.Shared.Models;

namespace DMCopilot.Shared.Data
{
    public interface ICharacterRepository
    {
        Task<Character> GetCharacterAsync(Guid id);
        Task<IEnumerable<Character>> GetCharactersAsync();
        Task<Character> CreateCharacterAsync(Character character);
        Task<Character> UpdateCharacterAsync(Guid id, Character character);
        Task<Boolean> DeleteCharacterAsync(Guid id);
    }
}
