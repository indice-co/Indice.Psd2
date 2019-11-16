using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Indice.Oba.AspNetCore.Features
{
    /// <summary>
    /// Certificates feature implementation for <see cref="IApplicationFeatureProvider{ControllerFeature}"/>
    /// </summary>
    public class CertificatesFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
    {
        /// <summary>
        /// Populates the feature for the current aspnet app.
        /// </summary>
        /// <param name="parts">The list of parts of an MVC application.</param>
        /// <param name="feature">The list of controllers types in an MVC application.</param>
        public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature) {
            var type = typeof(CertificatesController).GetTypeInfo();
            if (!feature.Controllers.Any(t => t == type)) {
                feature.Controllers.Add(type);
            }
        }
    }
}
