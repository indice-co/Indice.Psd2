using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Indice.Oba.AspNetCore.Features;
using Indice.Oba.AspNetCore.Features.EF;
using Indice.Psd2.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Indice.Oba.AspNetCore.Features.Mvc;

/// <summary>
/// Adds feature extensions to the MvcBuilder.
/// </summary>
public static class CertificatesFeatureExtensions
{
    
    /// <summary>
    /// Add the Certificate endpoints feature to MVC.
    /// </summary>
    /// <param name="mvcBuilder">An interface for configuring MVC services.</param>
    /// <returns></returns>
    public static IMvcBuilder AddCertificateEndpoints(this IMvcBuilder mvcBuilder) {
        mvcBuilder.ConfigureApplicationPartManager(apm => apm.FeatureProviders.Add(new CertificatesFeatureProvider()));
        mvcBuilder.AddFormatterMappings(mappings => {
            mappings.SetMediaTypeMappingForFormat("crt", "application/x-x509-user-cert"); // The CRT extension is used for certificates. The certificates may be encoded as binary DER or as ASCII PEM.
            mappings.SetMediaTypeMappingForFormat("cer", "application/pkix-cert"); // Alternate form of .crt (Microsoft Convention). You can use MS to convert .crt to .cer (.both DER encoded .cer, or base64[PEM] encoded .cer)
            mappings.SetMediaTypeMappingForFormat("key", "application/pkcs8"); // The KEY extension is used both for public and private PKCS#8 keys. The keys may be encoded as binary DER or as ASCII PEM.
            mappings.SetMediaTypeMappingForFormat("pfx", "application/x-pkcs12"); // PFX.
        });
        mvcBuilder.AddMvcOptions(mvc => {
            mvc.OutputFormatters.Add(new CertificateOutputFormatter());
        });
        
        return mvcBuilder;
    }
}
