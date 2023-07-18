#if NET7_0_OR_GREATER
#nullable enable 
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder;
/// <summary>
/// Maps the certificate store endpoints
/// </summary>
public static class CertificateApi
{
    /// <summary>
    ///  Maps the certificate store endpoints
    /// </summary>
    /// <param name="routes">The <see cref="IEndpointRouteBuilder"/></param>
    /// <returns>The builder</returns>
    public static IEndpointRouteBuilder MapCertificateStore(this IEndpointRouteBuilder routes) {
        var group = routes.MapGroup(".certificates");

        return routes;
    }
}
#nullable disable
#endif