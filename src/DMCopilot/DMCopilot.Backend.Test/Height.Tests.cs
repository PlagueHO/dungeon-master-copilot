using Microsoft.VisualStudio.TestTools.UnitTesting;
using DMCopilot.Shared.Data;

namespace DMCopilot.Test.Data.Character
{
    [TestClass]
    public class HeightTests
    {
        [TestMethod]
        public void Height_Test_Default_Constructor()
        {
            // Arrange
            var expected = 0.0;
            var height = new Height();

            // Act
            var actual = height.Value;

            // Assert
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Height_Test_Constructor_With_Feet_And_Inches()
        {
            // Arrange
            var expected = 1.8288;
            var height = new Height(6, 0);

            // Act
            var actual = height.Value;

            // Assert
            Assert.AreEqual(expected, actual, 0.0001);
        }

        [TestMethod]
        public void Height_Test_SetHeightFeetAndInches()
        {
            // Arrange
            var expected = 1.8288;
            var height = new Height();
            height.SetHeightFeetAndInches(6, 0);

            // Act
            var actual = height.Value;

            // Assert
            Assert.AreEqual(expected, actual, 0.0001);
        }

        [TestMethod]
        public void Height_Test_SetHeightInches()
        {
            // Arrange
            var expected = 1.8288;
            var height = new Height();
            height.SetHeightInches(72);

            // Act
            var actual = height.Value;

            // Assert
            Assert.AreEqual(expected, actual, 0.0001);
        }

        [TestMethod]
        public void Height_ConvertToInches_Returns_Correct_Value()
        {
            // Arrange
            var expected = 71.6534;
            var height = new Height(1.82);

            // Act
            var actual = height.ConvertToInches();

            // Assert
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Height_ToString_Returns_Correct_Format()
        {
            // Arrange
            var expected = "3.175m";
            var height = new Height(3.175);

            // Act
            var actual = height.ToString();

            // Assert
            Assert.AreEqual(expected, actual);
        }
    }
}
