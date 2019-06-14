using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Indice.Psd2.Cryptography.Validation
{
    /// <summary>
    /// When a cerificate is presented to be associated with a PSD2 third party provider it must be first validated. 
    /// 1. Check the AuthorityKeyIdentifier against NCA trusted issuer list for the country where the TPP operates.
    /// 2. Check the AuthorityInformationAccess extension in order to download the CA issuing certificate.
    /// 3. Check the CRLDistribution points to find the url of the Certificate Revocation List and check if this certificate has been revoked (check the serialnumber of this cert may be in the list).
    /// </summary>
    public class Psd2ClientCertificateValidator
    {
        /// <summary>
        /// Constructs the class.
        /// </summary>
        public Psd2ClientCertificateValidator() {

        }

        /// <summary>
        /// Validate the <see cref="X509Certificate2"/> for PSD2 compliance.
        /// </summary>
        /// <param name="certificate"></param>
        public void Validate(X509Certificate2 certificate) {
            var authorityKeyId = certificate.GetAuthorityKeyIdentifier();

            if (string.IsNullOrEmpty(authorityKeyId)) {
                throw new Exception("Missing authority Key Identifier extension");
            }
            var psd2Attributes = certificate.GetPsd2Attributes();
            if (psd2Attributes == null) {
                throw new Exception("This is not a valid QWAC or QCseal");
            }
            if (!psd2Attributes.Roles.Any()) {
                throw new Exception("There are no roles defined in this certificate");
            }
            if (!psd2Attributes.AuthorizationId.IsValid) {
                throw new Exception($"The NCAId is not in a valid format {psd2Attributes.AuthorizationId}");
            }
            var accessDescriptions = certificate.GetAuthorityInformationAccess();
            if (accessDescriptions == null || !accessDescriptions.Any()) {
                throw new Exception($"There is no Authority Information Access extension inside the certificate.");
            }
            foreach (var info in accessDescriptions) {
                // make a ping to see if the certificate if accessible. This points to the CA issuing cert.
                // we are only interested in CertificationAuthorityIssuer types of accessmethods according to spec.
                // also we are interested in endpoints that point to .cer or .crt files through http(s) and not their LDAP counterparts.
                // Could also download.
                if (info.AccessMethod == X509Certificates.AccessDescription.AccessMethodType.CertificationAuthorityIssuer) {
                    var uri = new Uri(info.AccessLocation);
                    if (uri.Scheme == "http" || uri.Scheme == "https") {
                        //var crt = 
                    }
                }
            }
            var crlDistributionPoints = certificate.GetCRLDistributionPoints();
            if (crlDistributionPoints == null || !crlDistributionPoints.Any()) {
                throw new Exception($"There is no CRL distribution points extension inside the certificate.");
            }
            // here are the revocation lists.
            // could do this also using the Cerificate chain.
            foreach (var point in crlDistributionPoints) {
                
            }

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.Build(certificate);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1) {
                issuer = chain.ChainElements[1].Certificate;
            }
            chain.Reset();

        }
    }
}
