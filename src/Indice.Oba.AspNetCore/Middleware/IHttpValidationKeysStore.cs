using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Oba.AspNetCore.Middleware;

/// <summary>
/// Interface for the validation key store
/// </summary>
public interface IHttpValidationKeysStore
{
    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<SecurityKey>> GetValidationKeysAsync();
}
