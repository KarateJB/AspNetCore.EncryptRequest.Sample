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
    public class DecryptRequestFilter : Attribute, IAsyncResourceFilter
    {
        private readonly IKeyManager? keyManager = null;
        private readonly ILogger? logger = null;

        public DecryptRequestFilter(
            IKeyManager keyManager,
            ILogger<DecryptRequestFilter> logger)
        {
            this.keyManager = keyManager;
            this.logger = logger;
        }

        public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            logger?.LogDebug($"Start decrpt process from {nameof(DecryptRequestFilter)}");

            var isForwardRequestToApiAction = await this.OnBeforeActionAsync(context);

            if (isForwardRequestToApiAction)
            {
                await next();
            }

            logger?.LogDebug($"End decrpt process from {nameof(DecryptRequestFilter)}");
        }

        private async Task<bool> OnBeforeActionAsync(ResourceExecutingContext context)
        {
            var request = context.HttpContext.Request;
            var err = string.Empty;
            bool isForwardRequestToApiAction = true;

            var retryTimes = int.Parse(this.GetHeaderSingleValue(request.Headers, CustomHttpHeaderFactory.RetryTimes) ?? "0");
            var requestCacheId = this.GetHeaderSingleValue(request.Headers, CustomHttpHeaderFactory.RequestCacheId);

            if (this.ValidateRequiredHeaders(requestCacheId, ref err))
            {
                var encryptedPayload = string.Empty;

                #region Reading body from Http request

                logger?.LogDebug($"{nameof(DecryptRequestFilter)}: start reading encrypted content from Http request...");
                var initialBody = request.Body;
                try
                {
                    request.EnableBuffering();
                    using (var reader = new StreamReader(request.Body))
                    {
                        var content = await reader.ReadToEndAsync();

                        encryptedPayload = JsonConvert.DeserializeObject<string>(content);
                    }
                }
                catch (Exception ex)
                {
                    string loadBodyErr = $"{nameof(DecryptRequestFilter)}: cannot read request body!";
                    logger?.LogError(ex, loadBodyErr);
                    isForwardRequestToApiAction = false;
                }
                finally
                {
                    request.Body = initialBody;
                }

                logger?.LogDebug($"{nameof(DecryptRequestFilter)}: end reading encrypted content from Http request.");
                #endregion

                #region Decrypt the encrypted content

                logger?.LogDebug($"{nameof(DecryptRequestFilter)}: start decrypting content from Http request...");
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
                            var privateKey = await keyManager.GetPrivateKeyAsync(KeyTypeEnum.RSA);

                            var decryptedPayload = await rsa.DecryptAsync(privateKey, encryptedPayload);

                            var escaptedDecryptedPayload = decryptedPayload.Replace("\"", "\\\"");
                            escaptedDecryptedPayload = $"\"{escaptedDecryptedPayload}\"";

                            byte[] byteContent = Encoding.UTF8.GetBytes(escaptedDecryptedPayload);
                            request.EnableBuffering();
                            request.Body.Position = 0;
                            using (var reader = new StreamReader(request.Body))
                            {
                                request.Body = new MemoryStream(byteContent);
                                request.Headers.Remove("content-type");
                                request.Headers.Append("content-type", "application/json");
                            }
                        }
                        catch (Exception ex) when (ex is FormatException || ex is CryptographicException)
                        {
                            var publicKey = await keyManager.GetPublicKeyAsync(KeyTypeEnum.RSA);

                            logger?.LogWarning(ex, $"Cannot decrypt with private key!");
                            context.Result = new EmptyResult();
                            context.HttpContext.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
                            context.HttpContext.Response.Headers.Append(CustomHttpHeaderFactory.RequestCacheId, requestCacheId);
                            context.HttpContext.Response.Headers.Append(CustomHttpHeaderFactory.PublicKey, publicKey);

                            isForwardRequestToApiAction = false;
                        }
                        catch (Exception ex)
                        {
                            logger?.LogError(ex, ex.Message);
                            context.Result = new EmptyResult();
                            context.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
                            isForwardRequestToApiAction = false;
                        }
                    }
                }

                logger?.LogDebug($"{nameof(DecryptRequestFilter)}: end decrypting content from Http request.");
                #endregion
            }

            if (!string.IsNullOrEmpty(err))
            {
                isForwardRequestToApiAction = false;
                await context.HttpContext.Response.WriteAsync(err);
            }

            return isForwardRequestToApiAction;
        }

        private string? GetHeaderSingleValue(IHeaderDictionary headers, string header)
        {
            try
            {
                headers.TryGetValue(header, out StringValues values);
                return (values.Count > 0) ? values[0] : string.Empty;
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, ex.Message);
                return string.Empty;
            }
        }

        private bool ValidateRequiredHeaders(string? requestCacheId, ref string err)
        {
            const bool isValidateOk = true;

            if (string.IsNullOrEmpty(requestCacheId))
            {
                err += $"{CustomHttpHeaderFactory.RequestCacheId} headers are required in a encrypted request! ";
            }

            return string.IsNullOrEmpty(err) ? isValidateOk : !isValidateOk;
        }
    }
}