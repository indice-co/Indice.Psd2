using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Indice.Psd2.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Indice.Oba.AspNetCore.Middleware
{
    /// <summary>
    /// Http middleware that signs and validates Http signatures.
    /// </summary>
    public class HttpSignatureMiddleware
    {
        // The middleware delegate to call after this one finishes processing
        private readonly RequestDelegate _next;
        private readonly HttpSignatureOptions _options;

        /// <summary>
        /// construct the middleware
        /// </summary>
        /// <param name="next"></param>
        /// <param name="options"></param>
        public HttpSignatureMiddleware(RequestDelegate next, HttpSignatureOptions options) {
            _next = next;
            _options = options;
        }


        /// <summary>
        /// Invokes the middleware
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public async Task Invoke(HttpContext httpContext, ILogger<HttpSignatureMiddleware> logger) {
            var check = _options.TryMatch(httpContext.Request.Path, out var headerNames);
            if (check && httpContext.Request.Headers.ContainsKey(_options.SignatureHeaderName)) {
                var rawSignature = httpContext.Request.Headers[_options.SignatureHeaderName];
                var rawDigest = httpContext.Request.Headers[_options.DigestHeaderName];
                var rawCertificate = httpContext.Request.Headers[_options.SignatureCertificateHeaderName];
                
                if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawCertificate)) {
                    var error = $"Missing certificate in http header '{_options.SignatureCertificateHeaderName}'. Cannot validate signature.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                    return;
                }
                if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawDigest)) {
                    var error = $"Missing digest in http header '{_options.DigestHeaderName}'. Cannot validate signature.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                    return;
                }
                X509Certificate2 cert;
                try {
                    cert = new X509Certificate2(Convert.FromBase64String(rawCertificate));
                } catch {
                    var error = $"Signature Certificate not in a valid format. Expected a base64 encoded x509.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
                var validationKey = new X509SecurityKey(cert);
                var validatedToken = new HttpSignatureSecurityToken(rawDigest, rawSignature);

                var requestBody = new byte[0];
                switch (httpContext.Request.Method) {
                    case "GET":
                        requestBody = Encoding.UTF8.GetBytes(httpContext.Request.QueryString.ToString());
                        break;
                    case "POST":
                    case "PUT":
                        requestBody = await GetRequestBody(httpContext.Request);
                        break;
                    default:
                        break;
                }
                // validate the request.
                var disgestIsValid = validatedToken.Digest.Validate(requestBody);
                if (!disgestIsValid) {
                    var error = $"digest validation failed.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
                var signatureIsValid = validatedToken.Signature.Validate(validationKey, httpContext.Request.Headers);
                if (!signatureIsValid) {
                    var error = $"signature validation failed.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
                logger.LogInformation("Signature validated successfuly for path: '{0} {1}'", httpContext.Request.Method, httpContext.Request.Path);
                // Call the next middleware delegate in the pipeline 
            }
            await _next.Invoke(httpContext);
            if (check) {
                // polulate the response.
            }
        }

        private async Task<byte[]> GetRequestBody(HttpRequest request) {
            request.EnableBuffering();
            request.EnableRewind();
            using (var requestStream = new MemoryStream()) {
                await request.Body.CopyToAsync(requestStream);
                request.Body.Seek(0, SeekOrigin.Begin);
                return requestStream.ToArray();
            }
        }

        private static async Task WriteErrorResponse(HttpContext httpContext, ILogger<HttpSignatureMiddleware> logger, HttpStatusCode statusCode, string error) {
            httpContext.Response.StatusCode = (int)statusCode;
            httpContext.Response.ContentType = "application/json";
            logger.LogWarning(error);
            await httpContext.Response.WriteAsync(JsonConvert.SerializeObject(new ProblemDetails() {
                Status = httpContext.Response.StatusCode,
                Title = $"{statusCode}",
                Detail = error
            }));
        }
    }
}
