using System;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AspNetCore.EncryptRequest.Services
{
    public class GetRsaKeyHostedService: IHostedService
    {
        private readonly IServiceProvider serviceProvider;

        public GetRsaKeyHostedService(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using (var scope = this.serviceProvider.CreateScope())
            {
                var logger = this.serviceProvider.GetService<ILogger<GetRsaKeyHostedService>>();
                var keyManager = this.serviceProvider.GetService<IKeyManager>();
                var key = await keyManager.CreateDefaultAsymmetricKey(KeyTypeEnum.RSA, isIncludePrivateKey: true);
                await keyManager.SaveKeyAsync(key);
                var savedKey = await keyManager.GetKeyAsync(KeyTypeEnum.RSA);
            }
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
        }
    }
}