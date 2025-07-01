using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Util.Factory;

namespace AspNetCore.EncryptRequest.Handlers
{
    public class CustomHeaderHttpClientHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            const int Zero = 0;

            var isRetryTimesHeaderSet = request.Headers.TryGetValues(CustomHttpHeaderFactory.RetryTimes, out IEnumerable<string>? retryTimesValues);
            var isRequestCacheIdHeaderSet = request.Headers.TryGetValues(CustomHttpHeaderFactory.RequestCacheId, out IEnumerable<string>? requestCacheIdValues);

            if (!isRetryTimesHeaderSet || retryTimesValues?.Count() > 1)
            {
                request.Headers.Remove(CustomHttpHeaderFactory.RetryTimes);
                request.Headers.Add(CustomHttpHeaderFactory.RetryTimes, Zero.ToString());
            }

            if (!isRequestCacheIdHeaderSet || requestCacheIdValues?.Count() > 1)
            {
                request.Headers.Remove(CustomHttpHeaderFactory.RequestCacheId);
                request.Headers.Add(CustomHttpHeaderFactory.RequestCacheId, CacheKeyFactory.GetKeyRequestCache());
            }

            var response = await base.SendAsync(request, cancellationToken);
            return response;
        }
    }
}