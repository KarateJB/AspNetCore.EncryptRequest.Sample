using System;
using System.Collections.Generic;
using AspNetCore.EncryptRequest.Util.Models;

namespace AspNetCore.EncryptRequest.Util.Factory
{
    /// <summary>
    /// Cache key factory
    /// </summary>
    public static class CacheKeyFactory
    {
        public const string KeyPrefixCipher = "Cipher";

        public const string KeyPrefixRequestCache = "RequestCache";

        /// <summary>
        /// Key for Secret key
        /// </summary>
        /// <return>Cache key</return>
        public static string GetKeyCipher(KeyTypeEnum keyType) => $"{KeyPrefixCipher}-{keyType.ToString()}";

        /// <summary>
        /// Key for temp request's payload (before encrypted)
        /// </summary>
        /// <return>Cache key</return>
        public static string GetKeyRequestCache() => $"{KeyPrefixRequestCache}-{Guid.NewGuid()}";
    }
}
