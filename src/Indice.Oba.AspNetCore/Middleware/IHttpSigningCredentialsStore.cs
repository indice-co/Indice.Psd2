using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Indice.Psd2.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Oba.AspNetCore.Middleware;

/// <summary>
/// Interface for a signing credential store for <see cref="HttpSignature"/>
/// </summary>
public interface IHttpSigningCredentialsStore
{
    /// <summary>
    /// Gets the signing credentials.
    /// </summary>
    /// <returns></returns>
    Task<SigningCredentials> GetSigningCredentialsAsync();
}
