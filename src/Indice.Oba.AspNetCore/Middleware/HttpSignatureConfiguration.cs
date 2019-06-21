using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Indice.Oba.AspNetCore.Middleware;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions related to configuring the <see cref="HttpSignatureMiddleware"/> on the <seealso cref="IServiceCollection"/>
    /// </summary>
    public static class HttpSignatureConfiguration
    {
        /// <summary>
        /// Adds Http signature related services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="setupAction"></param>
        /// <returns></returns>
        public static IServiceCollection AddHttpSignatures(this IServiceCollection services, Action<HttpSignatureOptions> setupAction = null) {
            var existingService = services.Where(x => x.ServiceType == typeof(HttpSignatureOptions)).LastOrDefault();
            if (existingService == null) {
                var options = new HttpSignatureOptions();
                // reflect to find controller actions. 
                setupAction?.Invoke(options);
                services.AddSingleton(options);
            }
            return services;
        }
    }
}
