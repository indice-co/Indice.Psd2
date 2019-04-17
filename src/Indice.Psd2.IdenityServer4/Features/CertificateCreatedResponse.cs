using System;
using System.Collections.Generic;
using System.Text;

namespace Indice.Psd2.IdenityServer4.Features
{
    /// <summary>
    /// Certificate creation response.
    /// </summary>
    public class CertificateCreatedResponse
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
        /// SHA256WITHRSA
        /// </summary>
        public string Algorithm { get; set; }
    }
}
