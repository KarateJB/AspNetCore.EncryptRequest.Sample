using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Handlers
{
    public class EncryptHttpClientHandler : DelegatingHandler
    {
        private const int CacheRequestTimeout = 60; // Time(Seconds) to keeping the original request in MemoryCache
        private readonly IKeyManager keyManager = null;
        private readonly IMemoryCache memoryCache = null;
        private readonly ILogger logger;

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptHttpClientHandler(
            IKeyManager keyManager,
            IMemoryCache memoryCache,
            ILogger<EncryptHttpClientHandler> logger)
        {
            this.keyManager = keyManager;
            this.memoryCache = memoryCache;
            this.logger = logger;
        }

        /// <summary>
        /// Send the request
        /// </summary>
        /// <param name="request">Request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>HttpResponseMessage</returns>
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            #region Get receiver-name and retry-times from Http Header

            // Retry Times
            request.Headers.TryGetValues(CustomHttpHeaderFactory.RetryTimes, out IEnumerable<string> retryTimesValues);
            int retryTimes = 0;
            int.TryParse(retryTimesValues.FirstOrDefault(), out retryTimes);

            // RequestCacheId
            request.Headers.TryGetValues(CustomHttpHeaderFactory.RequestCacheId, out IEnumerable<string> requestCacheIdValues);
            var requestCacheId = requestCacheIdValues.FirstOrDefault();
            #endregion

            #region Encrypt the Http Request (Only in the first time)

            if (retryTimes.Equals(0))
            {
                this.logger.LogDebug($"Start encrypting request...");
                using (var rsa = new RsaService())
                {
                    #region Get public key
                    var publicKey = await this.keyManager.GetPublicKeyAsync(KeyTypeEnum.RSA);
                    #endregion

                    #region Get original payload

                    // Load payload
                    string content = await request.Content.ReadAsStringAsync();

                    // Remove escapted character, eq. "\"xxxxx\"" => "xxxxx"
                    var jsonPayload = JsonConvert.DeserializeObject<string>(content);
                    #endregion

                    #region Save the original payload before encrypted

                    var cacheKey = requestCacheId;
                    this.memoryCache.Set(cacheKey, jsonPayload, DateTimeOffset.Now.AddSeconds(CacheRequestTimeout));

                    this.logger.LogDebug($"Successfully caching original request to memory cache: {cacheKey}.");

                    #endregion

                    #region Encrypt

                    // Encrypt
                    string encryptedPayload = await rsa.EncryptAsync(publicKey, jsonPayload);

                    // Replace the original content with the encrypted one
                    var newContent = new System.Net.Http.StringContent($"\"{encryptedPayload}\"", Encoding.UTF8, "application/json");
                    ////newContent.Headers.ContentType.CharSet = string.Empty;
                    request.Content = newContent;

                    this.logger.LogDebug($"Successfully encrypting request.");
                    #endregion
                }
            }
            #endregion

            // base.SendAsync calls the inner handler
            var response = await base.SendAsync(request, cancellationToken);
            return response;
        }
    }
}
