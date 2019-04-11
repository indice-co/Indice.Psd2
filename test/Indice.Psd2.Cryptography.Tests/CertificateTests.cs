using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

namespace Indice.Psd2.Cryptography.Tests
{
    public class CertificateTests
    {
        //[Fact]
        //public void Generate_QWACs() {
        //    var data = Psd2CertificateRequest.Example();
        //    var manager = new CertificateManager();
        //    var cert = manager.CreateQWACsCertificate(data);
        //    //manager.ExportCertificate(cert, Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.cer"), false, "123abc!");
        //    var pem = cert.ExportToPEM();
        //    File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), $"{data.AuthorizationNumber}.cer"), pem);
        //    Assert.True(true);
        //}

        //[Fact]
        //public void Generate_QsealCs() {

        //    Assert.True(true);
        //}




        [Fact]
        public void ImportBase64Certificate() {
            var trustedRootCABase64 = "MIIFJDCCBAygAwIBAgIQHC/9ut45MxRLIscCQhfbaDANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMCR1IxPjA8BgNVBAoTNUhlbGxlbmljIFB1YmxpYyBBZG1pbmlzdHJhdGlvbiBDZXJ0aWZpY2F0aW9uIFNlcnZpY2VzMQ8wDQYDVQQLEwZIUEFSQ0ExRTBDBgNVBAMTPEhlbGxlbmljIFB1YmxpYyBBZG1pbmlzdHJhdGlvbiBmb3IgTGVnYWwgRW50aXRpZXMgSXNzdWluZyBDQTAeFw0xNjA2MjMwMDAwMDBaFw0yMTAzMjIyMzU5NTlaMIGtMQswCQYDVQQGEwJFTDEPMA0GA1UEBxQGQXRoZW5zMT4wPAYDVQQKFDVIZWxsZW5pYyBUZWxlY29tbXVuaWNhdGlvbnMgYW5kIFBvc3QgQ29tbWlzc2lvbiwgRUVUVDENMAsGA1UECxQERUVUVDE+MDwGA1UEAxM1SGVsbGVuaWMgVGVsZWNvbW11bmljYXRpb25zIGFuZCBQb3N0IENvbW1pc3Npb24sIEVFVFQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZMJ5AkBRXgfSa0uinelv0RdAYvpgrFstUfegJLUymKIS95WTerluheJv3hHH3btz93JWcwLIAK+5SQlJXrYWidcM4IPsZiJzFUWyDfEOev8SVhLYS2/fpdODvla7PInop1sZ2eFtBOvOmnb1iywyrnIFdwFI2JgVFPf2vWL+KU/bPqoaO/syTJ8aTnSh/ZHK05o2xqwAeMVrSgA85BL7sroYGPE5JdCsId5fp0tlItkyBv/60FjKjtIxQHR/xlIDz0fzIhuPXt2q0aygO75PbWuZ/5GqF5pRuMubWqZsCRbcBk0F8QCFWG7dN4SQhfuG5F/2aiuZM/1F49u1HgiXfAgMBAAGjggFEMIIBQDAJBgNVHRMEAjAAMFEGA1UdIARKMEgwRgYMKoIsAIbbMQEHAQEHMDYwNAYIKwYBBQUHAgEWKGh0dHBzOi8vcGtpLmVybWlzLmdvdi5nci9yZXBvc2l0b3J5Lmh0bWwwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5lcm1pcy5nb3YuZ3IvSFBBUkNBTGVnYWxFbnRpdGllcy9MYXRlc3RDUkwuY3JsMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUw4lWvFCzRzsC+rLxJ6NpYtWVIbUwHwYDVR0jBBgwFoAUhMvuIoCeLUg3UxsSB3MebzNyO80wEQYDVR0lBAowCAYGBACRNwMAMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZXJtaXMuZ292LmdyMA0GCSqGSIb3DQEBCwUAA4IBAQDB8PFBlykkN3mvF6Bv0JBTsP4VnBkeix/VH0qS5omhMPhBLQCvmDS/LdW60miGCyNaSJIOZag2Nubnp4pAyeWNsTMy1HVraYPGYkty0oW4dPx6VQJdKRD2IUZMT7jaQZ1hbtLQItl0C4L5raQNoN3T3giDqlwnMjNAqbrR/mHaV+kui+vojiUQeeNK0FuhHM8zrEXwrt9uSGVTldR98fdGavQ5kfZo79I95jnJhvQLRrivV8kAQh6AOVaCVj7HLdWLKmhq/ecc2t+zS5iUlwWe73oxNPGIc8juzyVav2bHtoF1nJ+QYheDPy+O5U4OcWB6xzpNv4DiAmdI/FR6PZIk";
            var trustedRootCACert = new X509Certificate2(Encoding.UTF8.GetBytes(trustedRootCABase64), "", X509KeyStorageFlags.Exportable);
            var qwacBase64 = "MIIEOzCCAyOgAwIBAgIVAK6MTxvwfxWX8i/nlayRzW6x76CXMA0GCSqGSIb3DQEBCwUAMIGRMQswCQYDVQQGEwJHUjEPMA0GA1UECBMGQXR0aWtpMQ8wDQYDVQQHEwZBdGhlbnMxFTATBgNVBAoTDEF1dGhvcml0eSBDQTELMAkGA1UECxMCSVQxITAfBgNVBAMTGEF1dGhvcml0eSBDQSBEb21haW4gTmFtZTEZMBcGCSqGSIb3DQEJARYKY2FAdGVzdC5ncjAeFw0xOTA0MTAxMDUxNDlaFw0yMDA0MTAxMDUxNDlaMIGHMRYwFAYDVQQDEw13d3cuaW5kaWNlLmdyMRIwEAYDVQQKEwlJTkRJQ0UgT0UxDDAKBgNVBAsTA1dFQjELMAkGA1UEBhMCR1IxDzANBgNVBAgTBkF0dGlraTEPMA0GA1UEBxMGQXRoZW5zMRwwGgYDVQRhExNQU0RHUi1CT0ctODAwMDAwMDA1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyH+Ai81mfR3gZv17lorvU1Gxuyhpd7A1qoGPQmWAOklHz3UKoFuAC4QqR1ZWrkfA58CgbOb38ExD1I2YpO8TLDtpNzLdtry0yxvdZI7iB5XxBvqm6fORfOD8kHvQr58khdZsI50arL1utELf0PeDoOgVb5TSkVlXa5AVLOKCDYGrFxoGKLh87yc2BdhR1l0nl0ZwcBkVPyeRW894/I1AiH38I8NgotMxWrGZ17bZDc0p7DAZC1RpyXvCjfUQWtG2NftQP166gjnDVKhiPxS1oes85aEjeZWNyqjXa2416owDk/fjDUv9uz/3EM2fXoMJfTH/rY2pC/bBhWiWeiPVcQIDAQABo4GRMIGOMIGLBggrBgEFBQcBAwR/MH0GBgQAgZgnAjBzMEwwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSTARBgcEAIGYJwEDDAZQU1BfQUkwEQYHBACBmCcBBAwGUFNQX0lDDA5CYW5rIG9mIEdyZWVjZQwTUFNER1ItQk9HLTgwMDAwMDAwNTANBgkqhkiG9w0BAQsFAAOCAQEAujf3FxDieYXbfoeGauThzrXUzYz7RJ6NsIWWhiqM8u9ftFSrbE4rwoy57cUox/gH2Ga7ZFjwANLT0s+mfzbncHw5y8P6ex2NXnjJEo+a5OfKazlPTi7Y+rPNo8pme0NZ9eOqTxPA3bVyqdNDI2g+pDBPWTWiTXWzM79JbQKILvAaqvGPRQk+FFDi+qjYN6Mc2uXZXUuvBr7xhvPO2acQUSZ/F73KAlzb+vIeS3In75lZiBQYqVMFuF6VHv2mqSrP2zW0C7Xm4DY81PF30QY82h+krUIYI8uPzTHXQtkUZeNIksHM32SwQhuBjFENkDkp9pr/Mcfv/bSNcq8sbo0rMw==";
            var qwacCert = new X509Certificate2(Encoding.UTF8.GetBytes(qwacBase64), "", X509KeyStorageFlags.Exportable);
            var type = default(Psd2CertificateAttributes);
            foreach (var extension in qwacCert.Extensions) {
                if (extension.Oid.Value == QualifiedCertificateStatementsExtension.Oid_QC_Statements) {
                    var qcStatements = new QualifiedCertificateStatementsExtension(extension, extension.Critical);
                    type = qcStatements.Psd2Type;
                    break;
                }
            }
            Assert.Equal("GR", type.AuthorizationNumber.CountryCode);
            Assert.Equal("BOG", type.AuthorizationNumber.SupervisionAuthority);
            Assert.Equal("800000005", type.AuthorizationNumber.AuthorizationNumber);
        }
    }
}
