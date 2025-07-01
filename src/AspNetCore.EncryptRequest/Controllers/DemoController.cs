using AspNetCore.EncryptRequest.Filters;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class DemoController : ControllerBase
    {
        private readonly IHttpClientFactory? httpClientFactory = null;
        private readonly ILogger? logger = null;
        private readonly string? testData = null;

        public DemoController(
            IHttpClientFactory httpClientFactory,
            ILogger<DemoController> logger)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;

            var requestModel = new Bank()
            {
                Name = "AAA",
                Merchants = new List<Merchant>()
                   {
                    new Merchant{ Name="Merchant1", Address = "@#$#$%^&" },
                    new Merchant{ Name="Merchant2", Address = ")^%$(*&#" }
                   }
            };

            this.testData = JsonConvert.SerializeObject(requestModel);
        }

        [HttpPost]
        [Route("Send")]
        public async Task<IActionResult> SendAsync()
        {
            var httpClient = httpClientFactory?.CreateClient(HttpClientNameEnum.CipherHttpClient.ToString());

            var response = await httpClient.PostAsJsonAsync("api/Demo/Receive", this.testData);

            if (response.IsSuccessStatusCode)
            {
                return this.Ok();
            }
            else
            {
                return this.BadRequest();
            }
        }

        [HttpPost]
        [TypeFilter(typeof(DecryptRequestFilter))]
        [Route("Receive")]
        public async Task<IActionResult> ReceiveAsync([FromBody]string jsonStr)
        {
            var model = await Task.Run(() => JsonConvert.DeserializeObject<Bank>(jsonStr));

            this.logger.LogDebug($"Received data: '{jsonStr}'");

            if (string.IsNullOrEmpty(jsonStr))
            {
                return this.BadRequest();
            }

            if (jsonStr.Equals(this.testData))
            {
                return this.Ok();
            }
            else
            {
                return this.StatusCode(StatusCodes.Status409Conflict);
            }
        }
    }
}
