using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Indice.Psd2.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Indice.Psd2.IdenityServer4.Features
{
    /// <summary>
    /// Creates an avatar based on a given name (first and last name) plus parameters
    /// </summary>
    [Route("certificates")]
    [ApiExplorerSettings(GroupName = "cert")]
    [ApiController]
    internal class CertificatesController : ControllerBase {

        public CertificatesController(CertificateEndpointsOptions options) {
            Options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public CertificateEndpointsOptions Options { get; }

        [Produces("application/x-x509-ca-cert")]
        [ProducesResponseType(statusCode:200, type: typeof(IFormFile))]
        [HttpGet("ca.crt")]
        public IActionResult GetIssuerCertificate() {
            var stream = System.IO.File.OpenRead(Path.Combine(Options.Path, "ca.cer"));
            return File(stream, "application/x-x509-ca-cert", "ca.cer");
        }

        [Produces("application/json")]
        [ProducesResponseType(statusCode: 200, type: typeof(CertificateCreatedResponse))]
        [HttpPost]
        public IActionResult CreateCertificate([FromBody] Psd2CertificateRequest request) {
            var response = new CertificateCreatedResponse();
#if NETCoreApp22
            var issuer = new X509Certificate2(Path.Combine(Options.Path, "ca.pfx"), Options.PfxPassphrase);
            var manager = new CertificateManager();
            var cert = manager.CreateQWACs(request, Options.IssuerDomain, issuer, out var privateKey);

            var certBase64 = cert.ExportToPEM();
            var publicBase64 = privateKey.ToSubjectPublicKeyInfo();
            var privateBase64 = privateKey.ToRSAPrivateKey();
            var keyId = cert.GetSubjectKeyIdentifier();
            response = new CertificateCreatedResponse {
                EncodedCert = certBase64,
                PrivateKey = privateBase64,
                KeyId = keyId.ToLower(),
                Algorithm = "SHA256WITHRSA"
            };
            cert.Dispose();
#endif
            return Ok(response);
        }
    }
}
