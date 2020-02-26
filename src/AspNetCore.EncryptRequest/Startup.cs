using System;
using AspNetCore.EncryptRequest.Handlers;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AspNetCore.EncryptRequest
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers()
                .AddNewtonsoftJson()
                .SetCompatibilityVersion(CompatibilityVersion.Version_3_0);


            #region MemoryCache
            services.AddMemoryCache();
            #endregion

            #region KeyManager
            services.AddSingleton<IKeyManager, KeyManager>();
            #endregion

            #region Hosted Services
            services.AddHostedService<GetRsaKeyHostedService>();  // This must be after service injections
            #endregion

            #region HttpMessage Handlers and HttpClientFactory

            // TODO: Move the HttpClient setting to KMS-Client-SDK (ISSUE: https://cybersoft4u.atlassian.net/browse/CTIS-2017)
            services.AddTransient<CustomHeaderHttpClientHandler>();
            services.AddTransient<EncryptHttpClientHandler>();
            services.AddSingleton<PollyRetryPolicyHandler>();

            services.AddHttpClient(HttpClientNameEnum.CipherHttpClient.ToString(), x =>
            {
                x.BaseAddress = new Uri("https://localhost:5001");
                x.Timeout = TimeSpan.FromMinutes(1);
            })
            .AddHttpMessageHandler<CustomHeaderHttpClientHandler>()
            .AddHttpMessageHandler<EncryptHttpClientHandler>()
            .AddPolicyHandler((serviceProvider, request) =>
            {
                var pollyHandler = serviceProvider.GetService<PollyRetryPolicyHandler>();
                return pollyHandler.CreateAsync().Result;
            });
            #endregion
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
