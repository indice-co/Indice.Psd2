using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Psd2.Cryptography.Tokens.HttpMessageSigning
{
    /// <summary>
    /// ogging sent requests and received responses can help diagnose issues. This can easily be done with a custom delegating handler:
    /// </summary>
    public class HttpSignatureDelegatingHandler : DelegatingHandler
    {
        /// <summary>
        /// The header name where the certificate used for signing the request will reside, in base64 encoding.  This header will be present in the request object if a signature is contained.
        /// </summary>
        public static string RequestSignatureCertificateHeaderName = "TTP-Signature-Certificate";

        /// <summary>
        /// The header name where the certificate used for validating the response will reside, in base64 encoding.  This header will be present in the request object if a signature is contained.
        /// </summary>
        public static string ResponseSignatureCertificateHeaderName = "ASPSP-Signature-Certificate";
        
        /// <summary>
        /// Signing credentials used to sign outgoing requests.
        /// </summary>
        protected SigningCredentials Credential { get; }

        /// <summary>
        /// Header names to include in the <see cref="HttpSignature"/>
        /// </summary>
        public string[] HeaderNames { get; }

        /// <summary>
        ///  Creates a new instance of the <see cref="HttpSignatureDelegatingHandler"/> class.
        /// </summary>
        public HttpSignatureDelegatingHandler(SigningCredentials credential, IEnumerable<string> headerNames) : base() {
            Credential = credential;
            HeaderNames = headerNames.ToArray();
        }

        /// <summary>
        /// Creates a new instance of the <see cref="HttpSignatureDelegatingHandler"/> class with a
        /// specific inner handler.
        /// </summary>
        /// <param name="credential">Signing credentials used to sign outgoing requests.</param>
        /// <param name="headerNames">Header names to include in the <see cref="HttpSignature"/></param>
        /// <param name="innerHandler">The inner handler which is responsible for processing the HTTP response messages.</param>
        public HttpSignatureDelegatingHandler(SigningCredentials credential, IEnumerable<string> headerNames, HttpMessageHandler innerHandler) : base (innerHandler) {
            Credential = credential;
            HeaderNames = headerNames.ToArray();
        }

        /// <summary>
        /// Sends an HTTP request to the inner handler to send to the server as an asynchronous
        /// operation.
        /// </summary>
        /// <param name="request">The HTTP request message to send to the server.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) {
            // Sign the request.
            await SignRequest(request);
            // base.SendAsync calls the inner handler
            var response = await base.SendAsync(request, cancellationToken);
            // Validate the response.
            await ValidateResponse(request, response);
            return response;
        }

        private static async Task ValidateResponse(HttpRequestMessage request, HttpResponseMessage response) {
            var rawSignature = response.Headers.GetValues(HttpSignature.HTTPHeaderName).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(rawSignature))
                return;
            var rawDigest = response.Headers.GetValues(HttpDigest.HTTPHeaderName).FirstOrDefault();
            var rawCertificate = response.Headers.GetValues(RequestSignatureCertificateHeaderName).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawCertificate)) {
                var error = $"Missing certificate in http header '{RequestSignatureCertificateHeaderName}'. Cannot validate signature.";
                throw new Exception(error);
            }
            if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawDigest)) {
                var error = $"Missing digest in http header '{HttpDigest.HTTPHeaderName}'. Cannot validate signature.";
                throw new Exception(error);
            }
            X509Certificate2 cert;
            try {
                cert = new X509Certificate2(Convert.FromBase64String(rawCertificate));
            } catch (Exception inner) {
                var error = $"Signature Certificate not in a valid format. Expected a base64 encoded x509.";
                throw new Exception(error, inner);
            }
            var validationKey = new X509SecurityKey(cert);
            var validatedToken = new HttpSignatureSecurityToken(rawDigest, rawSignature);

            var responseBody = await response.Content.ReadAsByteArrayAsync();
            // validate the request.
            var disgestIsValid = validatedToken.Digest.Validate(responseBody);
            if (!disgestIsValid) {
                var error = $"response digest validation failed.";
                throw new Exception(error);
            }
            var signatureIsValid = validatedToken.Signature.Validate(validationKey, request.RequestUri, request.Method.Method, response.Headers);
            if (!signatureIsValid) {
                var error = $"response signature validation failed.";
                throw new Exception(error);
            }
        }

        private async Task SignRequest(HttpRequestMessage request) {
            var content = new byte[0];
            switch (request.Method.Method) {
                case "GET":
                    content = Encoding.UTF8.GetBytes(request.RequestUri.Query.TrimStart('?'));
                    break;
                default:
                    content = await request.Content.ReadAsByteArrayAsync();
                    break;
            }
            var validationKey = Credential.Key as X509SecurityKey;
            var includedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                [HttpRequestTarget.HeaderName] = new HttpRequestTarget(request.Method.Method, request.RequestUri.PathAndQuery).ToString(),
                [HttpDigest.HTTPHeaderName] = new HttpDigest(Credential.Algorithm, content).ToString(),
                ["Date"] = (request.Headers.Date ?? DateTimeOffset.UtcNow).ToString("r")
            };
            foreach (var name in HeaderNames) {
                if (request.Headers.Contains(name)) {
                    var value = request.Headers.GetValues(name).FirstOrDefault();
                    if (includedHeaders.ContainsKey(name)) {
                        includedHeaders[name] = value;
                    } else {
                        includedHeaders.Add(name, value);
                    }
                } else if (name != HttpRequestTarget.HeaderName && includedHeaders.ContainsKey(name)) {
                    request.Headers.Add(name, includedHeaders[name]);
                }
            }
            var signature = new HttpSignature(Credential, includedHeaders, DateTime.UtcNow, null);
            request.Headers.Add(HttpSignature.HTTPHeaderName, signature.ToString());
            request.Headers.Add(ResponseSignatureCertificateHeaderName, Convert.ToBase64String(validationKey.Certificate.Export(X509ContentType.Cert)));
        }
    }
}
