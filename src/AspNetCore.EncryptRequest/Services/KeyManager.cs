using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Services
{
    public class KeyManager : IKeyManager
    {
        private readonly IHttpClientFactory httpClientFactory = null;
        private readonly ILogger logger = null;
        private readonly IMemoryCache memoryCache = null;

        /// <summary>           
        /// Constructor
        /// </summary>
        /// <param name="httpClientFactory">HttpClientFactory</param>
        /// <param name="keyManager">KeyManager</param>
        /// <param name="memoryCache">MemoryCache</param>
        public KeyManager(
            IHttpClientFactory httpClientFactory,
            ILogger<KeyManager> logger,
            IMemoryCache memoryCache)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;
            this.memoryCache = memoryCache;
        }

        /// <summary>
        /// Get current working key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <returns>CipherKey object</returns>
        public async Task<CipherKey> GetKeyAsync(KeyTypeEnum keyType)
        {
            this.logger.LogDebug($"Start load my {keyType.ToString()} key from MemoryCache.");

            try
            {
                var key = this.memoryCache.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                this.logger.LogDebug($"Successfully load {keyType.ToString()} key from MemoryCache. {key.ToString()}");
                return await Task.FromResult(key);
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                return null;
            }
        }

        /// <summary>
        /// Get my private key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <param name="me">Me</param>
        /// <returns>Private key</returns>
        public async Task<string> GetPrivateKeyAsync(KeyTypeEnum keyType)
        {
            this.logger.LogDebug($"Start load {keyType.ToString()} private key from MemoryCache...");

            try
            {
                var key = this.memoryCache.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                if (key != null)
                {
                    this.logger.LogDebug($"Successfully load {keyType.ToString()} private key from MemoryCache. {key.ToString()}");
                    return await Task.FromResult(key?.PrivateKey);
                }
                else
                {
                    this.logger.LogWarning($"Failed to load {keyType.ToString()} private key from MemoryCache.");
                    throw new NullReferenceException($"No available {keyType.ToString()} private key");
                }
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                return string.Empty;
            }
        }

        /// <summary>
        /// Get receiver's public key
        /// </summary>
        /// <param name="keyType">Key type</param>
        /// <param name="receiver">Receiver</param>
        /// <returns>Public key</returns>
        public async Task<string> GetPublicKeyAsync(KeyTypeEnum keyType)
        {
            this.logger.LogDebug($"Start load {keyType.ToString()} public key from MemoryCache...");

            try
            {
                var key = this.memoryCache.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                if (key != null)
                {
                    this.logger.LogDebug($"Successfully load {keyType.ToString()} public key from MemoryCache. {key.ToString()}");
                    return await Task.FromResult(key?.PublicKey);
                }
                else
                {
                    this.logger.LogWarning($"Failed to load {keyType.ToString()} public key from MemoryCache.");
                    throw new NullReferenceException($"No available {keyType.ToString()} public key");
                }
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                throw;
            }
        }

        /// <summary>
        /// Sync a key in passive mode (from Server-side)
        /// </summary>
        public async Task SaveKeyAsync(CipherKey key)
        {
            if (key != null)
            {
                // Save to Memory Cache
                await this.SaveKeyAsync(key.KeyType, key);
            }
        }

        /// <summary>
        /// Create a default RSA public key
        /// </summary>
        /// <param name="receiver">The target receiver</param>
        /// <param name="isSender">Is </param>
        /// <returns>CipherKey object</returns>
        /// <remarks>This method will be used when cannot get receiver's public key from KMS</remarks>
        public async Task<CipherKey> CreateDefaultAsymmetricKey(KeyTypeEnum keyType, bool isIncludePrivateKey = true)
        {
            switch (keyType)
            {
                case KeyTypeEnum.RSA:
                    using (var rsa = new RsaService())
                    {
                        return await rsa.CreateKeyAsync();
                    }
                default:
                    throw new NotImplementedException();
            }
        }

        private async Task SaveKeyAsync<T>(KeyTypeEnum keyType, T key)
        {
            this.memoryCache.Set(CacheKeyFactory.GetKeyCipher(keyType), key);
            this.logger.LogDebug($"Successfully sync {keyType.ToString()} key(s) from KMS.");
            await Task.CompletedTask;
        }

        private async Task<List<ICacheEntry>> showAllSavedKeyTypes()
        {
            // CacheEtries
            var cacheEntries = new List<ICacheEntry>();

            var field = typeof(MemoryCache).GetProperty("EntriesCollection", BindingFlags.NonPublic | BindingFlags.Instance);

            var cacheEntriesCollection = field.GetValue(this.memoryCache) as dynamic;

            if (cacheEntriesCollection != null)
            {
                foreach (var cacheItem in cacheEntriesCollection)
                {
                    // Get the "Value" from the key/value pair which contains the cache entry
                    ICacheEntry cacheItemValue = cacheItem.GetType().GetProperty("Value").GetValue(cacheItem, null);

                    // Add the cache entry to the list
                    cacheEntries.Add(cacheItemValue);

                    // Logging
                    this.logger.LogDebug($"Saved key: {cacheItemValue.Key} and value: {JsonConvert.SerializeObject(cacheItemValue.Value)}");
                }
            }
            else
            {
                this.logger.LogDebug($"No saved key!");
            }

            return await Task.FromResult(cacheEntries);
        }
    }
}
