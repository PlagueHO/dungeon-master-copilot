using System.Runtime.Serialization;

namespace DMCopilot.Shared.Data
{
    [Serializable]
    internal class WorldNotFoundException : Exception
    {
        public WorldNotFoundException()
        {
        }

        public WorldNotFoundException(string? message) : base(message)
        {
        }

        public WorldNotFoundException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected WorldNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}