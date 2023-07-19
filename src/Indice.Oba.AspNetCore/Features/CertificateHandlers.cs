#if NET7_0_OR_GREATER
#nullable enable 

using Indice.Psd2.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Indice.Oba.AspNetCore.Features;
internal static class CertificateHandlers
{
    public static FileStreamHttpResult GetIssuerCertificate(CertificateEndpointsOptions options) {
        var file = new FileInfo(Path.Combine(options.Path, "ca.cer"));
        return TypedResults.File(file.OpenRead(), contentType: "application/x-x509-ca-cert", fileDownloadName: "ca.cer", lastModified: file.LastWriteTimeUtc);
    }

    public static async Task<Ok<CertificateDetails>> CreateCertificate(
            ICertificatesStore store, 
            CertificateEndpointsOptions options, 
            Psd2CertificateRequest request) {
        var issuer = new X509Certificate2(Path.Combine(options.Path, "ca.pfx"), options.PfxPassphrase, X509KeyStorageFlags.MachineKeySet);
        var manager = new CertificateManager();
        var cert = manager.CreateQWACs(request, options.IssuerDomain, issuer, out _);
        var response = await store.Add(cert, request);
        cert.Dispose();
        return TypedResults.Ok(response);
    }

    public static async Task<Results<CertificateHttpResult, NotFound, ValidationProblem>> Export(
            ICertificatesStore store,
            CertificateEndpointsOptions options,
            string keyId, string format, string? password) {
        var response = await store.GetById(keyId);
        if (response == null) {
            return TypedResults.NotFound();
        }
        if (format.ToLower() == "pfx" && string.IsNullOrEmpty(password)) {
            var errors = new Dictionary<string, string[]> {
                [nameof(password)] = new[] { "A password is required in order to export to pfx" } 
            };
            return TypedResults.ValidationProblem(errors);
        }
        return Results.Extensions.Certificate(response, format, password);
    }

    public static async Task<Ok<List<CertificateDetails>>> GetList(
            ICertificatesStore store,
            DateTimeOffset? notBefore, bool? revoked, string? authorityKeyId) {
        var results = await store.GetList(notBefore, revoked, authorityKeyId);
        return TypedResults.Ok(results);
    }
}
#nullable disable
#endif