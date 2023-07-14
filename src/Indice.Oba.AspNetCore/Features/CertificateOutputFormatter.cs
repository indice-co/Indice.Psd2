using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Extensions.Logging;

namespace Indice.Oba.AspNetCore.Features;

/// <summary>
/// <see cref="OutputFormatter"/> for converting <seealso cref="CertificateDetails"/> to PEM format.
/// </summary>
public class CertificateOutputFormatter : OutputFormatter
{
    /// <summary>
    /// the constructor
    /// </summary>
    public CertificateOutputFormatter() {
        SupportedMediaTypes.Add("application/x-x509-user-cert");
        SupportedMediaTypes.Add("application/pkix-cert");
        SupportedMediaTypes.Add("application/pkcs8");
        SupportedMediaTypes.Add("application/x-pkcs12");
    }

    /// <summary>
    /// Determines if the given <paramref name="type"/> can be formatted.
    /// </summary>
    /// <param name="type"></param>
    /// <returns></returns>
    protected override bool CanWriteType(Type type) {
        if (typeof(CertificateDetails).IsAssignableFrom(type)) {
            return base.CanWriteType(type);
        }
        return false;
    }

    /// <summary>
    /// Makes the actual convertion to the output format.
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async override Task WriteResponseBodyAsync(OutputFormatterWriteContext context) {
        var serviceProvider = context.HttpContext.RequestServices;
        var logger = serviceProvider.GetService(typeof(ILogger<CertificateOutputFormatter>)) as ILogger;
        var response = context.HttpContext.Response;
        var certificateDetails = context.Object as CertificateDetails;
        if (certificateDetails != null) {
            byte[] buffer;
            switch (context.ContentType.Value) {
                case "application/x-x509-user-cert":
                case "application/pkix-cert":
                    buffer = Encoding.ASCII.GetBytes(certificateDetails.EncodedCert);
                    await response.Body.WriteAsync(buffer, 0, buffer.Length);
                    break;
                case "application/pkcs8":
                    buffer = Encoding.ASCII.GetBytes(certificateDetails.PrivateKey);
                    await response.Body.WriteAsync(buffer, 0, buffer.Length);
                    break;
                case "application/x-pkcs12":
                    var password = context.HttpContext.Request.Query["password"][0];
                    var cert = new X509Certificate2(Encoding.ASCII.GetBytes(certificateDetails.EncodedCert));
                    var privateKey = certificateDetails.PrivateKey.ReadAsRSAKey();
                    buffer = cert.CopyWithPrivateKey(RSA.Create(privateKey)).Export(X509ContentType.Pkcs12, password);
                    cert.Dispose();
                    response.Headers.Add("Content-Disposition", "attachment; filename=certificate.pfx");
                    await response.Body.WriteAsync(buffer, 0, buffer.Length);
                    break;
            }
        }
        logger.LogInformation($"Writing certificate {certificateDetails.KeyId}");
    }
}
