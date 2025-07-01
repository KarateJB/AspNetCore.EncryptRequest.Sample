using AspNetCore.EncryptRequest.Handlers;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Models;
using NLog.Web;

var builder = WebApplication.CreateBuilder(args);

// NLog: Setup NLog for Dependency injection
builder.Host.UseNLog();

// Add services to the container.
builder.Services.AddControllers().AddNewtonsoftJson();

#region MemoryCache
builder.Services.AddMemoryCache();
#endregion

#region KeyManager
builder.Services.AddSingleton<IKeyManager, KeyManager>();
#endregion

#region Hosted Services
builder.Services.AddHostedService<GetRsaKeyHostedService>();  // This must be after service injections
#endregion

#region HttpMessage Handlers and HttpClientFactory

builder.Services.AddTransient<CustomHeaderHttpClientHandler>();
builder.Services.AddTransient<EncryptHttpClientHandler>();
builder.Services.AddSingleton<PollyRetryPolicyHandler>();

builder.Services.AddHttpClient(HttpClientNameEnum.CipherHttpClient.ToString(), x =>
{
    x.BaseAddress = new Uri("https://localhost:5001");
    x.Timeout = TimeSpan.FromMinutes(1);
})
.AddHttpMessageHandler<CustomHeaderHttpClientHandler>()
.AddHttpMessageHandler<EncryptHttpClientHandler>()
.AddResilienceHandler("retry-pipeline", (builder, context) =>
{
    var pollyHandler = context.ServiceProvider.GetRequiredService<PollyRetryPolicyHandler>();
    pollyHandler.ConfigurePipeline(builder);
});
#endregion

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
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

app.MapControllers();

app.Run();
