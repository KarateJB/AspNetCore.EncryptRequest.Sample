using System.Text;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Handlers
{
    public class EncryptHttpClientHandler : DelegatingHandler
    {
        private const int CacheRequestTimeout = 60;
        private readonly IKeyManager? keyManager = null;
        private readonly IMemoryCache? memoryCache = null;
        private readonly ILogger? logger;

        public EncryptHttpClientHandler(
            IKeyManager keyManager,
            IMemoryCache memoryCache,
            ILogger<EncryptHttpClientHandler> logger)
        {
            this.keyManager = keyManager;
            this.memoryCache = memoryCache;
            this.logger = logger;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            request.Headers.TryGetValues(CustomHttpHeaderFactory.RetryTimes, out IEnumerable<string>? retryTimesValues);
            int retryTimes = 0;
            int.TryParse(retryTimesValues?.FirstOrDefault(), out retryTimes);

            request.Headers.TryGetValues(CustomHttpHeaderFactory.RequestCacheId, out IEnumerable<string>? requestCacheIdValues);
            var requestCacheId = requestCacheIdValues?.FirstOrDefault();

            if (retryTimes.Equals(0))
            {
                logger?.LogDebug($"Start encrypting request...");
                using (var rsa = new RsaService())
                {
                    var publicKey = await keyManager.GetPublicKeyAsync(KeyTypeEnum.RSA);

                    string content = await request.Content.ReadAsStringAsync();

                    var jsonPayload = JsonConvert.DeserializeObject<string>(content);

                    var cacheKey = requestCacheId;
                    memoryCache?.Set(cacheKey, jsonPayload, DateTimeOffset.Now.AddSeconds(CacheRequestTimeout));

                    logger?.LogDebug($"Successfully caching original request to memory cache: {cacheKey}.");

                    string encryptedPayload = await rsa.EncryptAsync(publicKey, jsonPayload);

                    var newContent = new System.Net.Http.StringContent($"\"{encryptedPayload}\"", Encoding.UTF8, "application/json");
                    request.Content = newContent;

                    logger?.LogDebug($"Successfully encrypting request.");
                }
            }

            var response = await base.SendAsync(request, cancellationToken);
            return response;
        }
    }
}
