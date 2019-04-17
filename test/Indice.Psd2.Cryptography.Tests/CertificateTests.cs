using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IdentityModel;
using Indice.Psd2.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Xunit;

namespace Indice.Psd2.Cryptography.Tests
{
    public class CertificateTests
    {
        [Fact]
        public void Generate_QWACs() {
            var data = Psd2CertificateRequest.Example();
            var manager = new CertificateManager();
            var privateKey = default(RSA);
            var cert = manager.CreateQWACs(data, "identityserver.gr", out privateKey);
            var certBase64 = cert.ExportToPEM();
            var publicBase64 = privateKey.ToSubjectPublicKeyInfo();
            var privateBase64 = privateKey.ToRSAPrivateKey();
            var pfxBytes = cert.Export(X509ContentType.Pfx, "111");
            var keyId = cert.GetSubjectKeyIdentifier();
            File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.cer"), certBase64);
            File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.public.key"), publicBase64);
            File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.private.key"), privateBase64);
            File.WriteAllBytes(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.pfx"), pfxBytes);
            File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.json"), JsonConvert.SerializeObject(new {
                encodedCert = certBase64,
                privateKey = privateBase64,
                keyId = keyId.ToLower(),
                algorithm = "SHA256WITHRSA"
            }));
            Assert.True(true);
        }

        [Fact]
        public void ImportBase64Certificate() {
            var qwacBase64 = "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";
            var qwacCert = new X509Certificate2(Encoding.UTF8.GetBytes(qwacBase64), "", X509KeyStorageFlags.Exportable);
            var type = default(Psd2Attributes);
            var accessDescriptions = default(AccessDescription[]);
            var distributionPoints = default(CRLDistributionPoint[]);
            var keyId = string.Empty;
            var authoritykeyId = string.Empty;
            foreach (var extension in qwacCert.Extensions) {
                if (extension.Oid.Value == QualifiedCertificateStatementsExtension.Oid_QC_Statements) {
                    var qcStatements = new QualifiedCertificateStatementsExtension(extension, extension.Critical);
                    type = qcStatements.Psd2Type;
                }
                if (extension.Oid.Value == AuthorityInformationAccessExtension.Oid_AuthorityInformationAccess) {
                    var aia = new AuthorityInformationAccessExtension(extension, extension.Critical);
                    accessDescriptions = aia.AccessDescriptions;
                }
                if (extension.Oid.Value == CRLDistributionPointsExtension.Oid_CRLDistributionPoints) {
                    var crl = new CRLDistributionPointsExtension(extension, extension.Critical);
                    distributionPoints = crl.DistributionPoints;
                }
                if (extension.Oid.Value == AuthorityKeyIdentifierExtension.Oid_AuthorityKeyIdentifier) {
                    var authkey = new AuthorityKeyIdentifierExtension(extension, extension.Critical);
                    authoritykeyId = authkey.AuthorityKeyIdentifier;
                }
                if (extension.Oid.Value == AuthorityKeyIdentifierExtension.Oid_SubjectKeyIdentifier) {
                    keyId = ((X509SubjectKeyIdentifierExtension)extension).SubjectKeyIdentifier;
                }
            }
            Assert.Equal("GR", type.AuthorizationId.CountryCode);
            Assert.Equal("BOG", type.AuthorizationId.SupervisionAuthority);
            Assert.Equal("800000005", type.AuthorizationId.AuthorizationNumber);
            Assert.Equal("838852D2F347686E152CA6A34CACAE17509DBC35", authoritykeyId);
            Assert.Equal("02D324A59192A2E6C6EED29E7AC69FB05073C745", keyId);
            //Assert.Equal("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml", accessDescriptions[0].ToString());
        }
    }
}
