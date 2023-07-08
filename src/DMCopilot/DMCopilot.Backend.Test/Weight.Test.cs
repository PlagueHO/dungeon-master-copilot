using Microsoft.VisualStudio.TestTools.UnitTesting;
using DMCopilot.Shared.Data;

namespace DMCopilot.Backend.Test.Data.Character
{
    [TestClass]
    public class WeightTests
    {
        [TestMethod]
        public void Weight_Test_Default_Constructor()
        {
            // Arrange
            var expected = 0.0;
            var weight = new Weight();

            // Act
            var actual = weight.Value;

            // Assert
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Weight_Test_Constructor_With_Pounds()
        {
            // Arrange
            var expected = 81646.7236;
            var weight = new Weight(180);

            // Act
            var actual = weight.Value;

            // Assert
            Assert.AreEqual(expected, actual, 0.0001);
        }

        [TestMethod]
        public void Weight_SetWeightPounds()
        {
            // Arrange
            var expected = 81646.7236;
            var weight = new Weight();
            weight.SetWeightPounds(180);

            // Act
            var actual = weight.Value;

            // Assert
            Assert.AreEqual(expected, actual,0.0001);
        }

        [TestMethod]
        public void Weight_ConvertToOunces_Returns_Correct_Value()
        {
            var weight = new Weight { Value = 81600 };
            var expectedOunces = 2878.355136;

            Assert.AreEqual(expectedOunces, weight.ConvertToOunces(), 0.0001);
        }

        [TestMethod]
        public void Weight_GetPounds_Returns_Correct_Value()
        {
            var weight = new Weight { Value = 81600 };
            var expectedPounds = 179.896992;

            Assert.AreEqual(expectedPounds, weight.ConvertToPounds(), 0.0001);
        }

        [TestMethod]
        public void Weight_ConvertToKilograms_Returns_Correct_Value()
        {
            var weight = new Weight { Value = 81600 };
            var expectedKilograms = 81.6;

            Assert.AreEqual(expectedKilograms, weight.ConvertToKilograms(), 0.0001);
        }

        [TestMethod]
        public void Weight_ToString_Returns_CorrectValue()
        {
            var weight = new Weight { Value = 81600 };
            var expectedString = "81600g";

            Assert.AreEqual(expectedString, weight.ToString());
        }
    }
}