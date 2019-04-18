using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Indice.Psd2.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Indice.Psd2.IdenityServer4.Features
{
    /// <summary>
    /// Creates an avatar based on a given name (first and last name) plus parameters
    /// </summary>
    [Route("certificates")]
    [ApiExplorerSettings(GroupName = "cert")]
    [ApiController]
    internal class CertificatesController : ControllerBase {

        public CertificatesController(CertificateEndpointsOptions options, ICertificatesStore store) {
            Options = options ?? throw new ArgumentNullException(nameof(options));
            Store = store ?? throw new ArgumentNullException(nameof(store));
        }

        public CertificateEndpointsOptions Options { get; }
        public ICertificatesStore Store { get; }

        [Produces("application/x-x509-ca-cert")]
        [ProducesResponseType(statusCode: 200, type: typeof(IFormFile))]
        [HttpGet("ca.crt")]
        public IActionResult GetIssuerCertificate() {
            var stream = System.IO.File.OpenRead(Path.Combine(Options.Path, "ca.cer"));
            return File(stream, "application/x-x509-ca-cert", "ca.cer");
        }

        [Produces("application/json")]
        [ProducesResponseType(statusCode: 200, type: typeof(CertificateDetails))]
        [HttpPost]
        public async Task<IActionResult> CreateCertificate([FromBody] Psd2CertificateRequest request) {
            var response = new CertificateDetails();
#if NETCoreApp22
            var issuer = new X509Certificate2(Path.Combine(Options.Path, "ca.pfx"), Options.PfxPassphrase);
            var manager = new CertificateManager();
            var cert = manager.CreateQWACs(request, Options.IssuerDomain, issuer, out var privateKey);

            var certBase64 = cert.ExportToPEM();
            var publicBase64 = privateKey.ToSubjectPublicKeyInfo();
            var privateBase64 = privateKey.ToRSAPrivateKey();
            var keyId = cert.GetSubjectKeyIdentifier();
            var authkeyId = cert.GetAuthorityKeyIdentifier();
            response = new CertificateDetails {
                EncodedCert = certBase64,
                PrivateKey = privateBase64,
                KeyId = keyId.ToLower(),
                AuthorityKeyId = authkeyId.ToLower(),
                Algorithm = "SHA256WITHRSA"
            };
            cert.Dispose();
#endif
            await Store.Store(response);
            return Ok(response);
        }

        [Produces("application/json")]
        [ProducesResponseType(statusCode: 200, type: typeof(CertificateDetails))]
        [HttpGet("{keyId}")]
        public async Task<IActionResult> GetById([FromRoute] string keyId) {
            var response = await Store.GetById(keyId);
            if (response == null) {
                return NotFound();
            }
            return Ok(response);
        }

        [Produces("application/json")]
        [ProducesResponseType(statusCode: 204, type: typeof(void))]
        [HttpPut("{keyId}/revoke")]
        public async Task<IActionResult> Revoke([FromRoute] string keyId) {
            await Store.Revoke(keyId);
            return NoContent();
        }


        [Produces("application/json")]
        [ProducesResponseType(statusCode: 200, type: typeof(List<CertificateDetails>))]
        [HttpGet]
        public async Task<IActionResult> GetList([FromQuery]DateTime? notBefore = null, [FromQuery]bool? revoked = null, [FromQuery]string authorityKeyId = null) {
            var results = await Store.GetList(notBefore, revoked, authorityKeyId);
            return Ok(results);
        }
    }
}
