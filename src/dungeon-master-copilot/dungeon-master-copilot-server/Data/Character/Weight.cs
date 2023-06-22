﻿namespace dungeon_master_copilot_server.Data.Character
{
    /// <summary>
    /// Represents a weight measurement in grams.
    /// </summary>
    public class Weight
    {
        /// <summary>
        /// The weight value in grams.
        /// </summary>
        public double Value { get; set; }

        const double OUNCES_PER_GRAM = 0.03527396;
        const double POUNDS_PER_GRAM = 0.00220462;
        const double KILOGRAMS_PER_GRAM = 0.001;

        /// <summary>
        /// Returns the weight in ounces, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in ounces</returns>
        public double GetOunces()
        {
            return Value * OUNCES_PER_GRAM;
        }

        /// <summary>
        /// Returns the weight in pounds, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in pounds</returns>
        public double GetPounds()
        {
            return Value * POUNDS_PER_GRAM;
        }

        /// <summary>
        /// Returns the weight in kilograms, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in kilograms</returns>
        public double GetKilograms()
        {
            return Value * KILOGRAMS_PER_GRAM;
        }

        /// <summary>
        /// Returns a string representation of the weight measurement in grams.
        /// </summary>
        /// <returns>A string representation of the weight measurement in grams (e.g. "81600g")</returns>
        public override string ToString()
        {
            return $"{Value}g";
        }
    }
}
