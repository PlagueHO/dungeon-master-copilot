using DMCopilot.Shared.Data;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Newtonsoft.Json;

namespace DMCopilot.Shared.Models
{
    /// <summary>
    /// Class to represent a character in the game.
    /// </summary>
    public class Character
    {
        /// <summary>
        /// The unique identifier for the character.
        /// </summary>
        [JsonProperty(PropertyName = "id")] 
        public Guid Id { get; set; }

        /// <summary>
        /// The name of the character.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public String Name { get; set; }

        /// <summary>
        /// The age of the character.
        /// </summary>
        [JsonProperty(PropertyName = "age")]
        public int? Age { get; set; }

        /// <summary>
        /// The class of the character.
        /// </summary>
        [JsonProperty(PropertyName = "class")]
        public String? Class { get; set; }

        /// <summary>
        /// The race of the character.
        /// </summary>
        [JsonProperty(PropertyName = "race")]
        public String? Race { get; set; }

        /// <summary>
        /// The height of the character.
        /// </summary>
        [JsonProperty(PropertyName = "height")]
        public Height? Height { get; set; }

        /// <summary>
        /// The weight of the character.
        /// </summary>
        [JsonProperty(PropertyName = "weight")]
        public Weight? Weight { get; set; }

        /// <summary>
        /// The physical characteristics of the character.
        /// </summary>
        [JsonProperty(PropertyName = "physicalcharacteristics")]
        public String? PhysicalCharacteristics { get; set; }

        /// <summary>
        /// The voice of the character.
        /// </summary>
        [JsonProperty(PropertyName = "voice")]
        public String? Voice { get; set; }

        /// <summary>
        /// The clothing of the character.
        /// </summary>
        [JsonProperty(PropertyName = "clothing")]
        public String? Clothing { get; set; }

        /// <summary>
        /// The personality traits of the character.
        /// </summary>
        [JsonProperty(PropertyName = "personalitytraits")]
        public String? PersonalityTraits { get; set; }

        /// <summary>
        /// The ideals of the character.
        /// </summary>
        [JsonProperty(PropertyName = "ideals")]
        public String? Ideals { get; set; }

        /// <summary>
        /// The bonds of the character.
        /// </summary>
        [JsonProperty(PropertyName = "bonds")]
        public String? Bonds { get; set; }

        /// <summary>
        /// The flaws of the character.
        /// </summary>
        [JsonProperty(PropertyName = "flaws")]
        public String? Flaws { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Character"/> class.
        /// </summary>
        public Character(Guid id)
        {
            Id = id;
        }
    }
}
