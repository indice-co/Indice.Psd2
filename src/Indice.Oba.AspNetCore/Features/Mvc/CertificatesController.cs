using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Indice.Psd2.Cryptography;
using Indice.Psd2.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Indice.Oba.AspNetCore.Features.Mvc;

/// <summary>
/// Controller that contains methods to manage PSD2 certificates.
/// </summary>
[Route(".certificates")]
[ApiExplorerSettings(GroupName = "cert")]
[ApiController]
internal class CertificatesController : ControllerBase
{
    public CertificatesController(CertificateEndpointsOptions options, ICertificatesStore store) {
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public CertificateEndpointsOptions Options { get; }
    public ICertificatesStore Store { get; }

    /// <summary>
    /// Get issuer certificate.
    /// </summary>
    /// <returns></returns>
    [Produces("application/x-x509-ca-cert")]
    [ProducesResponseType(statusCode: 200, type: typeof(IFormFile))]
    [HttpGet("ca.cer")]
    public IActionResult GetIssuerCertificate() {
        var stream = System.IO.File.OpenRead(Path.Combine(Options.Path, "ca.cer"));
        return File(stream, "application/x-x509-ca-cert", "ca.cer");
    }

    /// <summary>
    /// Generates an X509Certificate.
    /// </summary>
    /// <returns></returns>
    [Produces("application/json")]
    [ProducesResponseType(statusCode: 200, type: typeof(CertificateDetails))]
    [HttpPost]
    public async Task<IActionResult> CreateCertificate([FromBody] Psd2CertificateRequest request) {
        var issuer = new X509Certificate2(Path.Combine(Options.Path, "ca.pfx"), Options.PfxPassphrase, X509KeyStorageFlags.MachineKeySet);
        var manager = new CertificateManager();
        var cert = manager.CreateQWACs(request, Options.IssuerDomain, issuer, out _);
        var response = await Store.Add(cert, request);
        cert.Dispose();
        return Ok(response);
    }

    /// <summary>
    /// Exports a certificates. 
    /// </summary>
    /// <param name="keyId">The subject key identifier</param>
    /// <param name="format">The format can be any of the following file extensions *json*, *pfx*, *cer*, *crt*.</param>
    /// <param name="password">In case of selected format is that of a container chain we will also need a password (pfx). Otherwise this part is ignored.</param>
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

    /// <summary>
    /// Revoke a certificate.
    /// </summary>
    /// <param name="keyId"></param>
    [ApiExplorerSettings(GroupName = "cert", IgnoreApi = true)]
    [Produces("application/json")]
    [ProducesResponseType(statusCode: 204, type: typeof(void))]
    [HttpPut("{keyId}/revoke")]
    public async Task<IActionResult> Revoke([FromRoute] string keyId) {
        await Store.Revoke(keyId);
        return NoContent();
    }

    /// <summary>
    /// List all available certificates.
    /// </summary>
    /// <param name="notBefore">The issued date from which to search.</param>
    /// <param name="revoked">If true searches only for revoked certificates.</param>
    /// <param name="authorityKeyId">The issuing certificate subject key id.</param>
    [Produces("application/json")]
    [ProducesResponseType(statusCode: 200, type: typeof(List<CertificateDetails>))]
    [HttpGet]
    public async Task<IActionResult> GetList([FromQuery] DateTime? notBefore = null, [FromQuery] bool? revoked = null, [FromQuery] string authorityKeyId = null) {
        var results = await Store.GetList(notBefore, revoked, authorityKeyId);
        return Ok(results);
    }

    /// <summary>
    /// Certificate revocation list.
    /// </summary>
    [Produces("application/x-pkcs7-crl")]
    [ProducesResponseType(statusCode: 200, type: typeof(IFormFile))]
    [HttpGet("revoked.crl")]
    public async Task<IActionResult> RevokationList() {
        var issuer = new X509Certificate2(Path.Combine(Options.Path, "ca.pfx"), Options.PfxPassphrase);
        var results = await Store.GetRevocationList();
        var crl = new CertificateRevocationList {
            AuthorizationKeyId = issuer.GetSubjectKeyIdentifier().ToLower(),
            Country = "GR",
            Organization = "Sample Authority",
            IssuerCommonName = "Some Cerification Authority CA",
            CrlNumber = 234,
            EffectiveDate = DateTime.UtcNow.AddDays(-2),
            NextUpdate = DateTime.UtcNow.AddDays(1),
            Items = results.Select(x => new RevokedCertificate {
                ReasonCode = RevokedCertificate.CRLReasonCode.Superseded,
                RevocationDate = x.RevocationDate,
                SerialNumber = x.SerialNumber
            })
            .ToList()
        };
        var crlSeq = new CertificateRevocationListSequence(crl);
        var data = crlSeq.SignAndSerialize(issuer.GetRSAPrivateKey());
        return File(data, "application/x-pkcs7-crl", "revoked.crl");
    }
}