using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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
    [Route(".certificates")]
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
            var cert = default(X509Certificate2);
            var issuer = new X509Certificate2(Path.Combine(Options.Path, "ca.pfx"), Options.PfxPassphrase);
#if NETCoreApp22
            var manager = new CertificateManager();
            cert = manager.CreateQWACs(request, Options.IssuerDomain, issuer, out var privateKey);
#endif
            var response = await Store.Add(cert, request);
            cert.Dispose();
            return Ok(response);
        }

        [FormatFilter]
        [Produces("application/json", "application/x-x509-user-cert", "application/pkix-cert", "application/pkcs8", "application/x-pkcs12")]
        [ProducesResponseType(statusCode: 200, type: typeof(CertificateDetails))]
        [HttpGet("{keyId}.{format?}")]
        public async Task<IActionResult> Export([FromRoute] string keyId, [FromRoute] string format, [FromQuery] string password) {
            var response = await Store.GetById(keyId);
            if (response == null) {
                return NotFound();
            }
            if (format.ToLower() == "pfx" && string.IsNullOrEmpty(password)) {
                ModelState.AddModelError(nameof(password), "A password is required in order to export to pfx");
                return BadRequest(ModelState);
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

        [Produces("application/x-pkcs7-crl")]
        [ProducesResponseType(statusCode: 200, type: typeof(IFormFile))]
        [HttpGet("revoked.crl")]
        public async Task<IActionResult> RevokationList() {
            var results = await Store.GetList(null, revoked:true, null);

            return Ok(results);
        }
    }
}
