using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Util.Models;

namespace AspNetCore.EncryptRequest.Services
{
    /// <summary>
    /// Interface for KeyManager
    /// </summary>
    public interface IKeyManager
    {
        /// <summary>
        /// Get current working key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <returns>CipherKey object</returns>
        Task<CipherKey> GetKeyAsync(KeyTypeEnum keyType);

        /// <summary>
        /// Get my private key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <param name="me">Me</param>
        /// <returns>Private key</returns>
        Task<string> GetPrivateKeyAsync(KeyTypeEnum keyType);

        /// <summary>
        /// Get receiver's public key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <param name="receiver">Receiver</param>
        /// <returns>Public key</returns>
        Task<string> GetPublicKeyAsync(KeyTypeEnum keyType);

        /// <summary>
        /// Sync single key to the same memory cache key (Only on KeyTypeEnum.RSA)
        /// </summary>
        /// <param name="keyType">KeyTypeEnum</param>
        /// <param name="keys">CipherKey</param>
        Task SaveKeyAsync(CipherKey key);

        /// <summary>
        /// Create a default RSA public key
        /// </summary>
        /// <param name="isIncludePrivateKey">Is the key pair should include Private key (False for a sender, True for a receiver)</param>
        /// <returns>CipherKey object</returns>
        /// <remarks>This method will be used when cannot get receiver's public key from KMS</remarks>
        Task<CipherKey> CreateDefaultAsymmetricKey(KeyTypeEnum keyType, bool isIncludePrivateKey = true);
    }
}
