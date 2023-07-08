using System.Security.Cryptography.X509Certificates;

namespace DMCopilot.Shared.Data
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
        /// Initializes a new instance of the <see cref="Weight"/> class.
        /// </summary>
        public Weight()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Weight"/> class with the specified weight in pounds.
        /// </summary>
        /// <param name="lbs">The weight in pounds.</param>
        public Weight(double lbs)
        {
            SetWeightPounds(lbs);
        }

        /// <summary>
        /// Sets the weight value in grams based on a weight value measured in pounds.
        /// </summary>
        /// <param name="lbs">The weight in pounds.</param>
        public void SetWeightPounds(double lbs)
        {
            Value = lbs / POUNDS_PER_GRAM;
        }

        /// <summary>
        /// Returns the weight in ounces, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in ounces</returns>
        public double ConvertToOunces()
        {
            return Value * OUNCES_PER_GRAM;
        }

        /// <summary>
        /// Returns the weight in pounds, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in pounds</returns>
        public double ConvertToPounds()
        {
            return Value * POUNDS_PER_GRAM;
        }

        /// <summary>
        /// Returns the weight in kilograms, calculated from the <see cref="Value"/> property.
        /// </summary>
        /// <returns>The weight in kilograms</returns>
        public double ConvertToKilograms()
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
