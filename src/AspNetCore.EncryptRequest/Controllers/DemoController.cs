using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Filters;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class DemoController : ControllerBase
    {
        private readonly IHttpClientFactory httpClientFactory = null;
        private readonly ILogger logger = null;
        private readonly string testData = null;

        public DemoController(
            IHttpClientFactory httpClientFactory,
            ILogger<DemoController> logger)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;

            var requestModel = new Bank()
            {
                Name = "NoMoney bank",
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
            var httpClient = this.httpClientFactory.CreateClient(HttpClientNameEnum.CipherHttpClient.ToString());
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
            // If DecryptRequestFilter does not add escape character ("\") on the stream,
            // We cannot bind the body'data to MVC action's model
            // The work-around is to read the stream directly from request's body
            ////using (var streamReader = new StreamReader(this.Request.Body))
            ////{
            ////    data = streamReader.ReadToEnd();
            ////}

            // (Optional)Deserialize to an object, array or something...
            var model = await Task.Run(() => JsonConvert.DeserializeObject<Bank>(jsonStr));

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
