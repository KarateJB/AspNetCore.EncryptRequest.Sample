namespace AspNetCore.EncryptRequest.Util.Factory
{
    public class CustomHttpHeaderFactory
    {
        /// <summary>
        /// Http header name for keeping value of retried times
        /// </summary>
        /// <remarks>
        /// This header is used to check how many times the request had been retied.
        /// </remarks>
        public static string RetryTimes { get; } = "Retry-Times";

        /// <summary>
        /// Request cache's id
        /// </summary>
        public static string RequestCacheId { get; } = "Request-Cache-Id";

        /// <summary>
        /// Http header name for keeping public key of receiver
        /// </summary>
        /// <remarks>
        /// Put the header on response if receiver cannot decrypt data
        /// </remarks>
        public static string PublicKey { get; } = "Public-Key";
    }
}
