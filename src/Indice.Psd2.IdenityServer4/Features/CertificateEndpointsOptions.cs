
namespace Indice.Psd2.IdenityServer4.Features
{
    /// <summary>
    /// Configuration options for certificate endpoints feature
    /// </summary>
    public class CertificateEndpointsOptions
    {
        /// <summary>
        /// path to where CA certificate should be stored/ retrieved
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// The domain name where this application is hosted. Ex https://example.com
        /// </summary>
        public string IssuerDomain { get; set; }

        /// <summary>
        /// The PFX passphrase for the issuer certs
        /// </summary>
        public string PfxPassphrase { get; set; }
    }
}
