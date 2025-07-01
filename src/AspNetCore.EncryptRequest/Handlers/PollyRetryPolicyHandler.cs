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
using Polly.Retry;

namespace AspNetCore.EncryptRequest.Handlers
{
    public class PollyRetryPolicyHandler
    {
        private const int DefaultMaxRetryTimes = 1;
        private readonly IKeyManager? keyManager = null;
        private readonly IMemoryCache? memoryCache = null;
        private readonly ILogger? logger = null;

        public PollyRetryPolicyHandler(
            IKeyManager keyManager,
            IMemoryCache memoryCache,
            ILogger<PollyRetryPolicyHandler> logger)
        {
            this.keyManager = keyManager;
            this.memoryCache = memoryCache;
            this.logger = logger;
        }

        public void ConfigurePipeline(ResiliencePipelineBuilder<HttpResponseMessage> builder, int maxRetryTimes = DefaultMaxRetryTimes)
        {
            builder.AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>().HandleResult(r => r.StatusCode == HttpStatusCode.UnprocessableEntity),
                MaxRetryAttempts = maxRetryTimes,
                OnRetry = async args =>
                {
                    logger?.LogWarning($"The encrypted data was rejected, update public key and will retry {args.AttemptNumber}/{maxRetryTimes}(times/total)...");

                    var request = args.Outcome.Result?.RequestMessage;
                    var response = args.Outcome.Result;

                    IEnumerable<string>? publicKeyValues = null;
                    response?.Headers.TryGetValues(CustomHttpHeaderFactory.PublicKey, out publicKeyValues);
                    var correctPublicKey = publicKeyValues?.FirstOrDefault();

                    IEnumerable<string>? requestCacheIdValues = null;
                    response?.Headers.TryGetValues(CustomHttpHeaderFactory.RequestCacheId, out requestCacheIdValues);
                    var requestCacheId = requestCacheIdValues?.FirstOrDefault();

                    if (string.IsNullOrEmpty(correctPublicKey))
                    {
                        logger?.LogWarning($"The response does not have required header: \"{CustomHttpHeaderFactory.PublicKey}\". Stop retrying the request!");
                        throw new OperationCanceledException();
                    }
                    else if (string.IsNullOrEmpty(requestCacheId))
                    {
                        logger?.LogWarning($"The response does not have required header: \"{CustomHttpHeaderFactory.RequestCacheId}\" on response. Stop retrying the request!");
                        throw new OperationCanceledException();
                    }
                    else
                    {
                        var cacheKey = requestCacheId;
                        string? jsonPayload = null;
                        memoryCache?.TryGetValue(cacheKey, out jsonPayload);
                        if (string.IsNullOrEmpty(jsonPayload))
                        {
                            logger?.LogWarning($"Lost the original request in MemoryCache (Key: {cacheKey}). Stop retrying the request!");
                            throw new OperationCanceledException();
                        }

                        using (var rsa = new RsaService())
                        {
                            string encryptedPayload = await rsa.EncryptAsync(correctPublicKey, jsonPayload);

                            var newContent = new System.Net.Http.StringContent($"\"{encryptedPayload}\"", Encoding.UTF8, "application/json");
                            if(request != null) request.Content = newContent;

                            logger?.LogDebug($"Successfully encrypting request.");
                        }

                        request?.Headers.Remove(CustomHttpHeaderFactory.RetryTimes);
                        request?.Headers.Add(CustomHttpHeaderFactory.RetryTimes, args.AttemptNumber.ToString());

                        var key = (await keyManager.GetKeyAsync(KeyTypeEnum.RSA));
                        if(key != null) key.PublicKey = correctPublicKey;

                        await keyManager.SaveKeyAsync(key);
                        logger?.LogWarning($"Updated the correct public key. Now start retrying sending request.");
                    }
                }
            });
        }
    }
}
