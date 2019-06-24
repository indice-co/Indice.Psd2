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
using Microsoft.Extensions.DependencyInjection;

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
            var headerNames = new List<string>();
            var check =  _options.RequestValidation && _options.TryMatch(httpContext.Request.Path, out headerNames);
            if (check && httpContext.Request.Headers.ContainsKey(HttpSignature.HTTPHeaderName)) {
                var rawSignature = httpContext.Request.Headers[HttpSignature.HTTPHeaderName];
                var rawDigest = httpContext.Request.Headers[HttpDigest.HTTPHeaderName];
                var rawCertificate = httpContext.Request.Headers[_options.RequestSignatureCertificateHeaderName];
                
                if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawCertificate)) {
                    var error = $"Missing certificate in http header '{_options.RequestSignatureCertificateHeaderName}'. Cannot validate signature.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                    return;
                }
                if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawDigest)) {
                    var error = $"Missing digest in http header '{HttpDigest.HTTPHeaderName}'. Cannot validate signature.";
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
                var signatureIsValid = validatedToken.Signature.Validate(validationKey, httpContext.Request);
                if (!signatureIsValid) {
                    var error = $"signature validation failed.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
                logger.LogInformation("Signature validated successfuly for path: '{0} {1}'", httpContext.Request.Method, httpContext.Request.Path);
                // Call the next middleware delegate in the pipeline 
            }

            if (check && _options.ResponseSigning == true) {
                using (var responseMemory = new MemoryStream()) {
                    var originalStream = httpContext.Response.Body;
                    httpContext.Response.Body = responseMemory;
                    await _next.Invoke(httpContext);


                    responseMemory.Seek(0, SeekOrigin.Begin);
                    var content = responseMemory.ToArray();
                    responseMemory.Seek(0, SeekOrigin.Begin);


                    // Apply logic here for deciding which headers to add
                    var signingCredentialsStore = httpContext.RequestServices.GetService<IHttpSigningCredentialsStore>();
                    var validationKeysStore = httpContext.RequestServices.GetService<IHttpValidationKeysStore>(); 
                    var signingCredentials = await signingCredentialsStore.GetSigningCredentialsAsync();
                    var validationKeys = await validationKeysStore.GetValidationKeysAsync();
                    var validationKey = validationKeys.First() as X509SecurityKey;
                    var includedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                        [HttpRequestTarget.HeaderName] = new HttpRequestTarget(httpContext.Request.Method, httpContext.Request.Path).ToString(),
                        [HttpDigest.HTTPHeaderName] = new HttpDigest(signingCredentials.Algorithm, content).ToString(),
                        ["Date"] = DateTime.UtcNow.ToString("r"),
                        [_options.ResponseIdHeaderName] = Guid.NewGuid().ToString()
                    };
                    foreach (var name in headerNames) {
                        if (httpContext.Response.Headers.ContainsKey(name)) {
                            if (includedHeaders.ContainsKey(name)) {
                                includedHeaders[name] = httpContext.Response.Headers[name];
                            } else {
                                includedHeaders.Add(name, httpContext.Response.Headers[name]);
                            }
                        } else if (name != HttpRequestTarget.HeaderName && includedHeaders.ContainsKey(name)) {
                            httpContext.Response.Headers.Add(name, includedHeaders[name]);
                        }
                    }
                    var signature = new HttpSignature(signingCredentials, includedHeaders, DateTime.UtcNow, null);
                    httpContext.Response.Headers.Add(HttpSignature.HTTPHeaderName, signature.ToString());
                    httpContext.Response.Headers.Add(_options.ResponseSignatureCertificateHeaderName, Convert.ToBase64String(validationKey.Certificate.Export(X509ContentType.Cert)));

                    // go on with life
                    await responseMemory.CopyToAsync(originalStream);
                    httpContext.Response.Body = originalStream;
                }
            } else {
                await _next.Invoke(httpContext);
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
