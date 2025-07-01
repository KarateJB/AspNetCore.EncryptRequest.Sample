using System.Reflection;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Services
{
    public class KeyManager : IKeyManager
    {
        private readonly IHttpClientFactory? httpClientFactory = null;
        private readonly ILogger? logger = null;
        private readonly IMemoryCache? memoryCache = null;

        public KeyManager(
            IHttpClientFactory httpClientFactory,
            ILogger<KeyManager> logger,
            IMemoryCache memoryCache)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;
            this.memoryCache = memoryCache;
        }

        public async Task<CipherKey?> GetKeyAsync(KeyTypeEnum keyType)
        {
            logger?.LogDebug($"Start load my {keyType.ToString()} key from MemoryCache.");

            try
            {
                var key = memoryCache?.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                logger?.LogDebug($"Successfully load {keyType.ToString()} key from MemoryCache.");
                return await Task.FromResult(key);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                return null;
            }
        }

        public async Task<string?> GetPrivateKeyAsync(KeyTypeEnum keyType)
        {
            logger?.LogDebug($"Start load {keyType.ToString()} private key from MemoryCache...");

            try
            {
                var key = memoryCache?.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                if (key != null)
                {
                    logger?.LogDebug($"Successfully load {keyType.ToString()} private key from MemoryCache.");
                    return await Task.FromResult(key?.PrivateKey);
                }
                else
                {
                    logger?.LogWarning($"Failed to load {keyType.ToString()} private key from MemoryCache.");
                    throw new NullReferenceException($"No available {keyType.ToString()} private key");
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                return string.Empty;
            }
        }

        public async Task<string?> GetPublicKeyAsync(KeyTypeEnum keyType)
        {
            logger?.LogDebug($"Start load {keyType.ToString()} public key from MemoryCache...");

            try
            {
                var key = memoryCache?.Get<CipherKey>(CacheKeyFactory.GetKeyCipher(keyType));

                if (key != null)
                {
                    logger?.LogDebug($"Successfully load {keyType.ToString()} public key from MemoryCache.");
                    return await Task.FromResult(key?.PublicKey);
                }
                else
                {
                    logger?.LogWarning($"Failed to load {keyType.ToString()} public key from MemoryCache.");
                    throw new NullReferenceException($"No available {keyType.ToString()} public key");
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, $"{nameof(KeyManager)} error");
                await this.showAllSavedKeyTypes();
                throw;
            }
        }

        public async Task SaveKeyAsync(CipherKey key)
        {
            if (key != null)
            {
                await this.SaveKeyAsync(key.KeyType, key);
            }
        }

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
            memoryCache?.Set(CacheKeyFactory.GetKeyCipher(keyType), key);
            logger?.LogDebug($"Successfully sync {keyType.ToString()} key(s) from KMS.");
            await Task.CompletedTask;
        }

        private async Task<List<ICacheEntry>> showAllSavedKeyTypes()
        {
            var cacheEntries = new List<ICacheEntry>();

            var field = typeof(MemoryCache).GetProperty("EntriesCollection", BindingFlags.NonPublic | BindingFlags.Instance);

            var cacheEntriesCollection = field?.GetValue(this.memoryCache) as dynamic;

            if (cacheEntriesCollection != null)
            {
                foreach (var cacheItem in cacheEntriesCollection)
                {
                    ICacheEntry cacheItemValue = cacheItem.GetType().GetProperty("Value").GetValue(cacheItem, null);

                    cacheEntries.Add(cacheItemValue);

                    logger?.LogDebug($"Saved key: {cacheItemValue.Key} and value: {JsonConvert.SerializeObject(cacheItemValue.Value)}");
                }
            }
            else
            {
                logger?.LogDebug($"No saved key!");
            }

            return await Task.FromResult(cacheEntries);
        }
    }
}
