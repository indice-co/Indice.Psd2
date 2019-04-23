using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Indice.Psd2.IdentityServer4.Features
{
    internal class CertificatesStoreInMemory : ICertificatesStore
    {
        public Task<CertificateDetails> Add(CertificateDetails certificate, string subject, string thumbprint, object metadata, bool isCA) {
            throw new NotImplementedException();
        }

        public Task<CertificateDetails> GetById(string keyId) {
            throw new NotImplementedException();
        }

        public Task<List<CertificateDetails>> GetList(DateTime? notBefore = null, bool? revoked = null, string authorityKeyId = null) {
            throw new NotImplementedException();
        }

        public Task<List<RevokedCertificateDetails>> GetRevocationList(DateTime? notBefore = null) {
            throw new NotImplementedException();
        }

        public Task Revoke(string keyId) {
            throw new NotImplementedException();
        }
    }
}
