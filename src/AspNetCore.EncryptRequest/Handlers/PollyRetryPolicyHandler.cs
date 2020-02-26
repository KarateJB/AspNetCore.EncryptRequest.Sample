using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Polly;

namespace AspNetCore.EncryptRequest.Handlers
{
    /// <summary>
    /// Polly Retry policy handler
    /// </summary>
    public class PollyRetryPolicyHandler
    {
        private const int DefaultMaxRetryTimes = 1;
        private readonly IKeyManager keyManager = null;
        private readonly IMemoryCache memoryCache = null;
        private readonly ILogger logger = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyManager">Key Manager</param>
        /// <param name="memoryCache">MemoryCache</param>
        /// <param name="logger"></param>
        public PollyRetryPolicyHandler(
            IKeyManager keyManager,
            IMemoryCache memoryCache,
            ILogger<PollyRetryPolicyHandler> logger)
        {
            this.keyManager = keyManager;
            this.memoryCache = memoryCache;
            this.logger = logger;
        }

        /// <summary>
        /// Create Retry policy hander instance
        /// </summary>
        /// <returns>PolicyBuilder of HttpResponseMessage</returns>
        public async Task<Polly.Retry.AsyncRetryPolicy<HttpResponseMessage>> CreateAsync(int maxRetryTimes = DefaultMaxRetryTimes)
        {
            var retryPolicy = Policy.HandleResult<HttpResponseMessage>(r => r.StatusCode.Equals(HttpStatusCode.UnprocessableEntity))
                .RetryAsync(maxRetryTimes, async (exception, retryCount) =>
                {
                    this.logger.LogWarning($"The encrypted data was rejected, update public key and will retry {retryCount}/{maxRetryTimes}(times/total)...");

                    var request = exception.Result.RequestMessage;
                    var response = exception.Result;

                    // Public key
                    response.Headers.TryGetValues(CustomHttpHeaderFactory.PublicKey, out IEnumerable<string> publicKeyValues);
                    var correctPublicKey = publicKeyValues.FirstOrDefault();

                    // RequestICached
                    response.Headers.TryGetValues(CustomHttpHeaderFactory.RequestCacheId, out IEnumerable<string> requestCacheIdValues);
                    var requestCacheId = requestCacheIdValues.FirstOrDefault();

                    if (string.IsNullOrEmpty(correctPublicKey))
                    {
                        this.logger.LogWarning($"The response does not have required header: \"{CustomHttpHeaderFactory.PublicKey}\". Stop retrying the request!");
                        throw new OperationCanceledException();
                    }
                    else if (string.IsNullOrEmpty(requestCacheId))
                    {
                        this.logger.LogWarning($"The response does not have required header: \"{CustomHttpHeaderFactory.RequestCacheId}\" on response. Stop retrying the request!");
                        throw new OperationCanceledException();
                    }
                    else
                    {
                        #region Get the original request
                        var cacheKey = requestCacheId;
                        this.memoryCache.TryGetValue(cacheKey, out string jsonPayload);
                        if (string.IsNullOrEmpty(jsonPayload))
                        {
                            this.logger.LogWarning($"Lost the original request in MemoryCache (Key: {cacheKey}). Stop retrying the request!");
                            throw new OperationCanceledException();
                        }

                        #endregion

                        #region Encrypt the original request by the new public key

                        using (var rsa = new RsaService())
                        {
                            string encryptedPayload = await rsa.EncryptAsync(correctPublicKey, jsonPayload);

                            // Replace the original content with the encrypted one
                            var newContent = new System.Net.Http.StringContent($"\"{encryptedPayload}\"", Encoding.UTF8, "application/json");
                            request.Content = newContent;

                            this.logger.LogDebug($"Successfully encrypting request.");
                        }
                        #endregion

                        #region Retry times incremental
                        request.Headers.Remove(CustomHttpHeaderFactory.RetryTimes);
                        request.Headers.Add(CustomHttpHeaderFactory.RetryTimes, retryCount.ToString());
                        #endregion

                        #region Update the correct public key with KeyManager

                        var key = (await this.keyManager.GetKeyAsync(KeyTypeEnum.RSA));
                        key.PublicKey = correctPublicKey;

                        await this.keyManager.SaveKeyAsync(key);
                        this.logger.LogWarning($"Updated the correct public key. Now start retrying sending request.");
                        #endregion
                    }
                });

            return await Task.FromResult(retryPolicy);
        }
    }
}
