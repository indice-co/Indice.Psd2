using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Indice.Psd2.Cryptography;
using Indice.Oba.AspNetCore.Features;
using Indice.Oba.AspNetCore.Features.EF;
using Microsoft.AspNetCore.Hosting;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Adds feature extensions to the MvcBuilder.
    /// </summary>
    public static class CertificatesFeatureExtensions
    {
        /// <summary>
        /// Add the Certificate endpoints feature to MVC.
        /// </summary>
        /// <param name="mvcBuilder"></param>
        /// <param name="configureAction">Configuration</param>
        /// <returns></returns>
        public static IMvcBuilder AddCertificateEndpoints(this IMvcBuilder mvcBuilder, Action<CertificateEndpointsOptions> configureAction = null) {
            mvcBuilder.ConfigureApplicationPartManager(apm =>
                apm.FeatureProviders.Add(new CertificatesFeatureProvider()));
            mvcBuilder.AddFormatterMappings(mappings => {
                mappings.SetMediaTypeMappingForFormat("crt", "application/x-x509-user-cert"); //The CRT extension is used for certificates.The certificates may be encoded as binary DER or as ASCII PEM
                mappings.SetMediaTypeMappingForFormat("cer", "application/pkix-cert"); //alternate form of .crt (Microsoft Convention) You can use MS to convert .crt to .cer (.both DER encoded .cer, or base64[PEM] encoded .cer)
                mappings.SetMediaTypeMappingForFormat("key", "application/pkcs8"); //The KEY extension is used both for public and private PKCS#8 keys. The keys may be encoded as binary DER or as ASCII PEM.
                mappings.SetMediaTypeMappingForFormat("pfx", "application/x-pkcs12"); // pfx
            });
            mvcBuilder.AddMvcOptions(mvc => {
                mvc.OutputFormatters.Add(new CertificateOutputFormatter());
            });
            var options = new CertificateEndpointsOptions() {
                IssuerDomain = "www.example.com",
                PfxPassphrase = "???"
            };

            options.Services = mvcBuilder.Services;
            configureAction?.Invoke(options);
            options.Services = null;
            if (options.Path == null) {
                var serviceProvider = mvcBuilder.Services.BuildServiceProvider();
                var hostingEnvironment = serviceProvider.GetRequiredService<IWebHostEnvironment>();
                options.Path = Path.Combine(hostingEnvironment.ContentRootPath, "App_Data", "certs");
            }
            mvcBuilder.Services.AddSingleton(options);

            if (!Directory.Exists(options.Path)) {
                Directory.CreateDirectory(options.Path);
            }
            if (!File.Exists(Path.Combine(options.Path, "ca.pfx"))) {
                var serviceProvider = mvcBuilder.Services.BuildServiceProvider();
                var manager = new CertificateManager();
                var issuingCert = manager.CreateRootCACertificate(options.IssuerDomain);
                var certBase64 = issuingCert.ExportToPEM();
                var pfxBytes = issuingCert.Export(X509ContentType.Pfx, options.PfxPassphrase);
                File.WriteAllBytes(Path.Combine(options.Path, "ca.pfx"), pfxBytes);
                File.WriteAllText(Path.Combine(options.Path, "ca.cer"), certBase64);
                var store = serviceProvider.GetService<ICertificatesStore>();
                store.Add(issuingCert, null);
            }
            return mvcBuilder;
        }

        /// <summary>
        /// Backs up the Certificates into a database.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="configureAction"></param>
        public static void AddEntityFrameworkStore(this CertificateEndpointsOptions options, Action<CertificatesStoreOptions> configureAction) {
            var storeOptions = new CertificatesStoreOptions() {
                DefaultSchema = "cert",
            };
            configureAction?.Invoke(storeOptions);
            options.Services.AddSingleton(storeOptions);
            if (storeOptions.ResolveDbContextOptions != null) {
                options.Services.AddDbContext<CertificatesDbContext>(storeOptions.ResolveDbContextOptions);
            } else {
                options.Services.AddDbContext<CertificatesDbContext>(storeOptions.ConfigureDbContext);
            }
            options.Services.AddTransient<ICertificatesStore, DbCertificatesStore>();
        }
    }
}
