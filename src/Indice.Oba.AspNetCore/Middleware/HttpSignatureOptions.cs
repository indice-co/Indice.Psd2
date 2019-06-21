using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Indice.Psd2.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Http;

namespace Indice.Oba.AspNetCore.Middleware
{
    /// <summary>
    /// Provides programmatic configuration for the <see cref="HttpSignatureMiddleware"/>.
    /// </summary>
    public class HttpSignatureOptions
    {
        /// <summary>
        /// Map of route paths and header names that will be included in the signatures.
        /// </summary>
        public Dictionary<string, List<string>> Mappings { get; set; } = new Dictionary<string, List<string>>(StringComparer.InvariantCultureIgnoreCase);

        /// <summary>
        /// The header name where the certificate used for signing the request will reside, in base64 encoding.  This header will be present in the request object if a signature is contained.
        /// </summary>
        public string SignatureCertificateHeaderName { get; set; } = "TTP-Signature-Certificate";

        /// <summary>
        /// The header name where the signature of the request will reside.
        /// </summary>
        public string DigestHeaderName { get; set; } = HttpDigest.HTTPHeaderName;

        /// <summary>
        /// The header name where the signature of the request will reside.
        /// </summary>
        public string SignatureHeaderName { get; set; } = HttpSignature.HTTPHeaderName;

        /// <summary>
        /// Adds a new map entry to the dictionary of mappings. This will be picked up by the <see cref="HttpSignatureMiddleware"/> 
        /// in order to determine which headers are included in each transmission.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="headerNames"></param>
        /// <returns></returns>
        public HttpSignatureOptions MapPath(PathString path, params string[] headerNames) {
            if (path.HasValue && path.Value.EndsWith("/", StringComparison.Ordinal)) {
                throw new ArgumentException("The path must not end with a '/'", nameof(path));
            }
            if (path.HasValue) {
                Mappings.Add(path.Value, new List<string>(headerNames));
            }
            return this;
        }

        /// <summary>
        /// Tries to find a matching path.
        /// </summary>
        /// <param name="path"></param>
        /// <param name="headerNames"></param>
        /// <returns></returns>
        public bool TryMatch(PathString path, out List<string> headerNames) {
            headerNames = null;
            if (Mappings.ContainsKey(path)) {
                headerNames = Mappings[path];
                return true;
            }
            var results = Mappings.Where(x => path.StartsWithSegments(x.Key));
            if (results.Any()) {
                headerNames = results.OrderByDescending(x => x.Key.Length).First().Value;
                return true;
            }
            return false;
        }
    }
}
