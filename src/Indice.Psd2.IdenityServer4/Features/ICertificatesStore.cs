using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Indice.Psd2.IdenityServer4.Features
{
    /// <summary>
    /// Certificate store used to persist the issued certificates.
    /// </summary>
    public interface ICertificatesStore
    {
        /// <summary>
        /// Stores the certificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns>the stored certificate</returns>
        Task<CertificateDetails> Store(CertificateDetails certificate);
        /// <summary>
        /// Revokes a certificate by key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <returns></returns>
        Task Revoke(string keyId);
        /// <summary>
        /// Retrieves a stored certificate by Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <returns></returns>
        Task<CertificateDetails> GetById(string keyId);
        /// <summary>
        /// Gets list of certificates by parameters
        /// </summary>
        /// <param name="notBefore"></param>
        /// <param name="revoked"></param>
        /// <param name="authorityKeyId"></param>
        /// <returns></returns>
        Task<List<CertificateDetails>> GetList(DateTime? notBefore = null, bool? revoked = null, string authorityKeyId = null);
    }
}
