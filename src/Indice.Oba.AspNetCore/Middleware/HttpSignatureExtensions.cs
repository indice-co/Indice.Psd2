using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Indice.Psd2.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Oba.AspNetCore.Middleware
{
    /// <summary>
    /// Extensions on <see cref="HttpSignature"/>
    /// </summary>
    public static class HttpSignatureExtensions
    {

        /// <summary>
        /// Validate the signature against the requested payload.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="key">The public key</param>
        /// <param name="httpRequest"></param>
        /// <returns></returns>
        public static bool Validate(this HttpSignature signature, SecurityKey key, HttpRequest httpRequest) {
            var headers = httpRequest.Headers.ToDictionary(x => x.Key, x => (string)x.Value);
            var rawTarget = httpRequest.HttpContext.Features.Get<IHttpRequestFeature>().RawTarget;
            headers.Add(HttpRequestTarget.HeaderName, new HttpRequestTarget(httpRequest.Method, rawTarget).ToString());
            return signature.Validate(key, headers);
        }

        /// <summary>
        /// Validate the signature against the requested payload.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="key">The public key</param>
        /// <param name="headers"></param>
        /// <returns></returns>
        public static bool Validate(this HttpSignature signature, SecurityKey key, IDictionary<string, StringValues> headers) {
            return signature.Validate(key, headers.ToDictionary(x => x.Key, x => (string)x.Value));
        }
    }
}
