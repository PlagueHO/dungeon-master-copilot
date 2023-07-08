namespace DMCopilot.Shared.Data
{
    /// <summary>
    /// Represents the height of a character.
    /// </summary>
    public class Height
    {
        /// <summary>
        /// Gets or sets the height value in meters.
        /// </summary>
        public double Value { get; set; }

        private const double INCHES_PER_METRE = 39.37d;
        private const double FEET_PER_METRE = 3.281d;
        private const double INCHES_PER_FOOT = 12d;

        /// <summary>
        /// Initializes a new instance of the <see cref="Height"/> class.
        /// </summary>
        public Height()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Height"/> class with the specified feet and inches.
        /// </summary>
        /// <param name="feet">The height in feet.</param>
        /// <param name="inches">The height in inches.</param>
        public Height(double feet, double inches)
        {
            SetHeightFeetAndInches(feet, inches);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Height"/> class with the specified inches.
        /// </summary>
        /// <param name="inches">The height in inches.</param>
        public Height(double metres)
        {
            Value=metres;
        }

        /// <summary>
        /// Sets the height in feet and inches.
        /// </summary>
        /// <param name="feet">The height in feet.</param>
        /// <param name="inches">The height in inches.</param>
        public void SetHeightFeetAndInches(double feet, double inches)
        {
            Value = (feet / FEET_PER_METRE) + (inches / INCHES_PER_METRE);
        }

        /// <summary>
        /// Sets the height in inches.
        /// </summary>
        /// <param name="inches">The height in inches.</param>
        public void SetHeightInches(double inches)
        {
            Value = inches / INCHES_PER_METRE;
        }

        /// <summary>
        /// Converts the height to inches.
        /// </summary>
        /// <returns>The height in inches.</returns>
        public double ConvertToInches()
        {
            return Value * INCHES_PER_METRE;
        }

        /// <summary>
        /// Converts the height to feet and inches.
        /// </summary>
        /// <returns>The height in feet and inches (e.g. "6' 2\"").</returns>
        public string ConvertToFeetAndInches()
        {
            int feet = (int)(Value * FEET_PER_METRE);
            int inches = (int)(Value * INCHES_PER_METRE % INCHES_PER_FOOT);
            return $"{feet}' {inches}\"";
        }

        /// <summary>
        /// Returns a string that represents the current height in meters.
        /// </summary>
        /// <returns>A string that represents the current height in meters (e.g. "1.82m").</returns>
        public override string ToString()
        {
            return $"{Value}m";
        }
    }
}
