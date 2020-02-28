using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Services;
using AspNetCore.EncryptRequest.Util.Crypto;
using AspNetCore.EncryptRequest.Util.Factory;
using AspNetCore.EncryptRequest.Util.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;

namespace AspNetCore.EncryptRequest.Filters
{
    /// <summary>
    /// Decrypt Requst Filter
    /// </summary>
    public class DecryptRequestFilter : Attribute, IAsyncResourceFilter
    {
        private readonly IKeyManager keyManager = null;
        private readonly ILogger logger = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="legalReceiver">The legal receiver</param>
        /// <param name="keyManager">Key manager</param>
        /// <param name="logger">Logger</param>
        public DecryptRequestFilter(
            IKeyManager keyManager,
            ILogger<DecryptRequestFilter> logger)
        {
            this.keyManager = keyManager;
            this.logger = logger;
        }

        /// <summary>
        /// OnResourceExecutionAsync
        /// </summary>
        /// <param name="context">ResourceExecutingContext</param>
        /// <param name="next">ResourceExecutionDelegate</param>
        public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            this.logger.LogDebug($"Start decrpt process from {nameof(DecryptRequestFilter)}");

            var isForwardRequestToApiAction = await this.OnBeforeActionAsync(context);

            if (isForwardRequestToApiAction)
            {
                await next();
            }

            this.logger.LogDebug($"End decrpt process from {nameof(DecryptRequestFilter)}");

            // HACK: remove this methods cus we cannot write Response after it's set by the action
            ////await this.OnAfterActionAsync(context);
        }

        /// <summary>
        /// OnActionExecutionAsync
        /// </summary>
        /// <param name="context">ActionExecutingContext</param>
        /// <param name="next">ActionExecutionDelegate</param>
        private async Task<bool> OnBeforeActionAsync(ResourceExecutingContext context)
        {
            var request = context.HttpContext.Request;
            var err = string.Empty;
            bool isForwardRequestToApiAction = true;

            // Get request's custom headers
            var retryTimes = int.Parse(this.GetHeaderSingleValue(request.Headers, CustomHttpHeaderFactory.RetryTimes) ?? "0");
            var requestCacheId = this.GetHeaderSingleValue(request.Headers, CustomHttpHeaderFactory.RequestCacheId);

            // Validate the Receiver value from header
            if (this.ValidateRequiredHeaders(requestCacheId, ref err))
            {
                var encryptedPayload = string.Empty;

                #region Reading body from Http request

                this.logger.LogDebug($"{nameof(DecryptRequestFilter)}: start reading encrypted content from Http request...");
                var initialBody = request.Body;
                try
                {
                    request.EnableBuffering();  // Use request.EnableRewind() instead before ASP.NET Core 3
                    using (var reader = new StreamReader(request.Body))
                    {
                        var content = await reader.ReadToEndAsync();

                        // Remove escapted character, eq. "\"xxxxx\"" => "xxxxx"
                        encryptedPayload = JsonConvert.DeserializeObject<string>(content);
                    }
                }
                catch (Exception ex)
                {
                    string loadBodyErr = $"{nameof(DecryptRequestFilter)}: cannot read request body!";
                    this.logger.LogError(ex, loadBodyErr);
                    isForwardRequestToApiAction = false;
                }
                finally
                {
                    // (Optional) Render the original body, since it was flushed by StreamReader,
                    // so that API action will be able to read body as well
                    request.Body = initialBody;
                }

                this.logger.LogDebug($"{nameof(DecryptRequestFilter)}: end reading encrypted content from Http request.");
                #endregion

                #region Decrypt the encrypted content

                this.logger.LogDebug($"{nameof(DecryptRequestFilter)}: start decrypting content from Http request...");
                if (string.IsNullOrEmpty(encryptedPayload))
                {
                    isForwardRequestToApiAction = false;
                }
                else
                {
                    using (var rsa = new RsaService())
                    {
                        try
                        {
                            #region Get public key 
                            var privateKey = await this.keyManager.GetPrivateKeyAsync(KeyTypeEnum.RSA);

                            // To test retry policy...
                            ////var privateKey = string.Empty;
                            ////if (retryTimes > 0)
                            ////   privateKey = await this.keyManager.GetPrivateKeyAsync(KeyTypeEnum.RSA);
                            ////else
                            ////   privateKey = (await this.keyManager.CreateDefaultAsymmetricKey(KeyTypeEnum.RSA, isIncludePrivateKey: true)).PrivateKey; // Set a incorrect private key to decrypt
                            #endregion

                            #region Decrypt and refactor to add escape charater for "\"

                            // Get decrypted string
                            var decryptedPayload = await rsa.DecryptAsync(privateKey, encryptedPayload);

                            // Add escape charater for "\"
                            var escaptedDecryptedPayload = decryptedPayload.Replace("\"", "\\\"");
                            escaptedDecryptedPayload = $"\"{escaptedDecryptedPayload}\"";
                            #endregion

                            #region Convert the decrypted payload to byte array and bind to HttpRequest's body

                            byte[] byteContent = Encoding.UTF8.GetBytes(escaptedDecryptedPayload);
                            request.EnableBuffering(); // Use request.EnableRewind() instead before ASP.NET Core 3
                            request.Body.Position = 0;
                            using (var reader = new StreamReader(request.Body))
                            {
                                request.Body = new MemoryStream(byteContent);
                                request.Headers.Remove("content-type");
                                request.Headers.Add("content-type", "application/json");
                            }
                            #endregion
                        }
                        catch (Exception ex) when (ex is FormatException || ex is CryptographicException)
                        {
                            /*
                             * FormatException occurs when the private key is incorrect RSA key
                             * CryptographicException occuers when the data is incorrect encrypted
                             */

                            var publicKey = await this.keyManager.GetPublicKeyAsync(KeyTypeEnum.RSA);

                            this.logger.LogWarning(ex, $"Cannot decrypt with private key!");
                            context.Result = new EmptyResult();
                            context.HttpContext.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
                            context.HttpContext.Response.Headers.Add(CustomHttpHeaderFactory.RequestCacheId, requestCacheId);
                            context.HttpContext.Response.Headers.Add(CustomHttpHeaderFactory.PublicKey, publicKey);

                            isForwardRequestToApiAction = false;
                        }
                        catch (Exception ex)
                        {
                            this.logger.LogError(ex, ex.Message);
                            context.Result = new EmptyResult();
                            context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
                            isForwardRequestToApiAction = false;
                        }
                    }
                }

                this.logger.LogDebug($"{nameof(DecryptRequestFilter)}: end decrypting content from Http request.");
                #endregion
            }

            if (!string.IsNullOrEmpty(err))
            {
                isForwardRequestToApiAction = false;
                await context.HttpContext.Response.WriteAsync(err);
            }

            return isForwardRequestToApiAction;
        }

        /// <summary>
        /// Get the first(single) value of a Http request's header
        /// </summary>
        /// <param name="headers">Http request's headers</param>
        /// <param name="header">Header's name</param>
        /// <returns>Value</returns>
        private string GetHeaderSingleValue(IHeaderDictionary headers, string header)
        {
            try
            {
                headers.TryGetValue(header, out StringValues values);
                return (values.Count > 0) ? values[0] : string.Empty;
            }
            catch (Exception ex)
            {
                this.logger.LogError(ex, ex.Message);
                return string.Empty;
            }
        }
        
        /// <summary>
        /// Validate the required headers
        /// </summary>
        /// <param name="requestCacheId">The value of header: Request-Cache-Id</param>
        /// <param name="receiverApp">The value of header: Receiver-App</param>
        /// <param name="err">Error message</param>
        /// <returns>True(Validate OK)/False(Validate NG)</returns>
        private bool ValidateRequiredHeaders(string requestCacheId, ref string err)
        {
            const bool isValidateOk = true;

            if (string.IsNullOrEmpty(requestCacheId))
            {
                err += $"{CustomHttpHeaderFactory.RequestCacheId} headers are required in a encrypted request! ";
            }

            // Other validation ....

            return string.IsNullOrEmpty(err) ? isValidateOk : !isValidateOk;
        }
    }
}
