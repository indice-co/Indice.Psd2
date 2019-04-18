using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Indice.Psd2.Cryptography;
using Indice.Psd2.IdenityServer4.Features;
using Indice.Psd2.IdenityServer4.Features.EF;
using Microsoft.AspNetCore.Hosting;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Adds feature extensions to the MvcBuilder.
    /// </summary>
    public static class CertificatesFeatureExtensions
    {
        /// <summary>
        /// Add the Avatar feature to MVC.
        /// </summary>
        /// <param name="mvcBuilder"></param>
        /// <param name="configureAction">Configuration</param>
        /// <returns></returns>
        public static IMvcBuilder AddCertificateEndpoints(this IMvcBuilder mvcBuilder, Action<CertificateEndpointsOptions> configureAction = null) {
            mvcBuilder.ConfigureApplicationPartManager(apm =>
                apm.FeatureProviders.Add(new CertificatesFeatureProvider()));

            var options = new CertificateEndpointsOptions() {
                IssuerDomain = "www.example.com",
                PfxPassphrase = "???"
            };

            options.Services = mvcBuilder.Services;
            configureAction?.Invoke(options);
            options.Services = null;
            if (options.Path == null) {
                var serviceProvider = mvcBuilder.Services.BuildServiceProvider();
                var hostingEnvironment = serviceProvider.GetRequiredService<IHostingEnvironment>();
                options.Path = Path.Combine(hostingEnvironment.ContentRootPath, "App_Data", "certs");
            }
            mvcBuilder.Services.AddSingleton(options);

            if (!Directory.Exists(options.Path)) {
                Directory.CreateDirectory(options.Path);
            }
            if (!File.Exists(Path.Combine(options.Path, "ca.pfx"))) { 
#if NETCoreApp22
            var manager = new CertificateManager();
            var issuingCert = manager.CreateRootCACertificate(options.IssuerDomain);
            var certBase64 = issuingCert.ExportToPEM();
            var pfxBytes = issuingCert.Export(X509ContentType.Pfx, options.PfxPassphrase);
            File.WriteAllBytes(Path.Combine(options.Path, "ca.pfx"), pfxBytes);
            File.WriteAllText(Path.Combine(options.Path, "ca.cer"), certBase64);
#endif
            }
            return mvcBuilder;
        }

        /// <summary>
        /// Backs up the Certificates into a database.
        /// </summary>
        /// <param name="options"></param>
        /// <param name="configureAction"></param>
        public static void AddEntitiyFrameworkStore(this CertificateEndpointsOptions options, Action<CertificatesStoreOptions> configureAction) {
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
