using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Indice.Psd2.Cryptography
{
    /// <summary>
    /// Extension methods and utilities related to certificate generation and validation
    /// </summary>
    public static class CertificatesExtensions
    {
        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPEM(this X509Certificate cert) {
            var builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        /// <summary>
        /// Find the issuer certificate. 
        /// First checks if the leaf certificate's Subject and Issuer fields are not the same. 
        /// Otherwise, the certificate is the issuer (self-signed certificate)
        /// If different it instatniates a X509Chain object and passes leaf certificate to X509Chain.Build method.Examine ChainElements property (a collection) and element at index 1 is the issuer.
        /// </summary>
        /// <param name="leafCert"></param>
        /// <returns></returns>
        public static X509Certificate2 GetIssuer(X509Certificate2 leafCert) {
            if (leafCert.Subject == leafCert.Issuer) { return leafCert; }
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(leafCert);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1) {
                issuer = chain.ChainElements[1].Certificate;
            }
            chain.Reset();
            return issuer;
        }
    }
}
