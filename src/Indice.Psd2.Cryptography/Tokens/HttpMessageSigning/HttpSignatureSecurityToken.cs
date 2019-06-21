using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Psd2.Cryptography.Tokens.HttpMessageSigning
{
    //https://developer.rabobank.nl/signing-requests-psd2-apis methodology
    //https://docs.microsoft.com/en-us/dotnet/framework/wcf/extending/how-to-create-a-custom-token
    /// <summary>
    /// Http <see cref="SecurityToken"/> for Signing HTTP Messages. RFC https://tools.ietf.org/html/draft-cavage-http-signatures-10
    /// </summary>
    public class HttpSignatureSecurityToken : SecurityToken
    {
        /// <summary>
        /// constructs the token for validating an incoming request.
        /// </summary>
        public HttpSignatureSecurityToken(string rawDigest, string rawSignature) {
            RawDigest = rawDigest;
            RawSignature = rawSignature;
            Digest = HttpDigest.Parse(rawDigest);
            Signature= HttpSignature.Parse(rawSignature);
        }


        /// <summary>
        /// constructs the token for sending a request with http signature.
        /// </summary>
        /// <param name="requestBody"></param>
        /// <param name="signingCredentials"></param>
        /// <param name="requestDate"></param>
        /// <param name="createdDate"></param>
        /// <param name="expirationDate"></param>
        /// <param name="requestId"></param>
        public HttpSignatureSecurityToken(SigningCredentials signingCredentials, byte[] requestBody, string requestId, DateTime? requestDate = null, DateTime? createdDate = null, DateTime? expirationDate = null) 
            : this(
                  signingCredentials, 
                  requestBody, 
                  new Dictionary<string, string> { ["X-Request-Id"] = requestId, ["Date"] = requestDate?.ToString("r") }, 
                  createdDate, 
                  expirationDate)
            {
        }

        /// <summary>
        /// constructs the token for sending a request with http signature.
        /// </summary>
        /// <param name="signingCredentials"></param>
        /// <param name="requestBody"></param>
        /// <param name="includedHeaders"></param>
        /// <param name="createdDate"></param>
        /// <param name="expirationDate"></param>
        public HttpSignatureSecurityToken(SigningCredentials signingCredentials, byte[] requestBody, IDictionary<string, string> includedHeaders, DateTime? createdDate = null, DateTime? expirationDate = null) {
            Digest = new HttpDigest(signingCredentials.Algorithm, requestBody);
            includedHeaders.Add(HttpDigest.HTTPHeaderName, Digest.ToString());
            Signature = new HttpSignature(signingCredentials, includedHeaders, createdDate, expirationDate);
            RequestId = includedHeaders["X-Request-Id"];
        }

        /// <summary>
        /// The signature part is 
        /// </summary>
        public override string Id => RequestId;

        /// <summary>
        /// The issuer
        /// </summary>
        public override string Issuer => (SigningCredentials as X509SigningCredentials)?.Certificate.Issuer;

        /// <summary>
        /// Gets the <see cref="SecurityKey"/>s for this instance.
        /// </summary>
        public override SecurityKey SecurityKey {
            get { return null; }
        }

        /// <summary>
        /// Gets or sets the <see cref="SigningKey"/> that signed this instance.
        /// </summary>
//        /// <remarks><see cref="HttpSecurityTokenHandler"/>.ValidateSignature(...) sets this value when a <see cref="SecurityKey"/> is used to successfully validate a signature.</remarks>
        public override SecurityKey SigningKey { get; set; }


        /// <summary>
        /// Gets the 'value' of the 'created' parameter
        /// </summary>
        /// <remarks>If the 'created' param is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidFrom {
            get {
                if (Signature != null)
                    return Signature.Created ?? DateTime.MinValue;
                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expires' parameter
        /// </summary>
        /// <remarks>If the 'expires' param  is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public override DateTime ValidTo {
            get {
                if (Signature != null)
                    return Signature.Expires ?? DateTime.MinValue;
                return DateTime.MinValue;
            }
        }

        /// <summary>
        /// The digest (hash) from the request body.
        /// </summary>
        public HttpDigest Digest { get; }

        /// <summary>
        /// The signature
        /// </summary>
        public HttpSignature Signature { get; }

        /// <summary>
        /// Gets the <see cref="SigningCredentials"/> to use when writing this token.
        /// </summary>
        public SigningCredentials SigningCredentials {
            get { return Signature?.SigningCredentials; }
        }

        /// <summary>
        /// The X-Request-Id Header
        /// </summary>
        public string RequestId { get; }

        /// <summary>
        /// The raw digest when reading the token
        /// </summary>
        public string RawDigest { get; }

        /// <summary>
        /// The raw signature when reading the token
        /// </summary>
        public string RawSignature { get; }
    }
}
