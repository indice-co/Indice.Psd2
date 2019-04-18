using System;
using System.Collections.Generic;
using System.Text;

namespace Indice.Psd2.IdenityServer4.Features.EF
{
    /// <summary>
    /// Database spesific entity that stores an issued certificate.
    /// </summary>
    public class DbCertificate
    {
        /// <summary>
        /// Base 64 Pem encoded cer
        /// </summary>
        public string EncodedCert { get; set; }
        /// <summary>
        /// Private key base64
        /// </summary>
        public string PrivateKey { get; set; }
        /// <summary>
        /// Subject Key Identifier
        /// </summary>
        public string KeyId { get; set; }
        /// <summary>
        /// Authority Subject Key Identifier (issuing certificate Subject Key Identifier)
        /// </summary>
        public string AuthorityKeyId { get; set; }
        /// <summary>
        /// SHA256WITHRSA
        /// </summary>
        public string Algorithm { get; set; }
        /// <summary>
        /// Indicates a revoked certificate.
        /// </summary>
        public bool Revoked { get; set; }
        /// <summary>
        /// Indicates the creation date.
        /// </summary>
        public DateTimeOffset CreatedDate { get; set; }
        /// <summary>
        /// Indicates the revoked date.
        /// </summary>
        public DateTimeOffset? RevokedDate { get; set; }
    }
}
