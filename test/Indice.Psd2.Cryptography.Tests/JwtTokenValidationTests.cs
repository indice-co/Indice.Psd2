using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Xunit;

namespace Indice.Psd2.Cryptography.Tests
{
    public class JwtTokenValidationTests
    {
        private const string ValidAudience = "identity.indice.gr";
        private const string ValidIssuer = "www.indice.gr";
        private const string ValidSubject = "PSDGR-BOG-800000005";
        private const string TEST_X509_PublicKey_2048 = "MIIEOzCCAyOgAwIBAgIVAI93JFXYN3IP9r1IBCgX9sV8fxGMMA0GCSqGSIb3DQEBCwUAMIGRMQswCQYDVQQGEwJHUjEPMA0GA1UECBMGQXR0aWtpMQ8wDQYDVQQHEwZBdGhlbnMxFTATBgNVBAoTDEF1dGhvcml0eSBDQTELMAkGA1UECxMCSVQxITAfBgNVBAMTGEF1dGhvcml0eSBDQSBEb21haW4gTmFtZTEZMBcGCSqGSIb3DQEJARYKY2FAdGVzdC5ncjAeFw0xOTA0MTExMTQzMjJaFw0yMDA0MTExMTQzMjJaMIGHMRYwFAYDVQQDEw13d3cuaW5kaWNlLmdyMRIwEAYDVQQKEwlJTkRJQ0UgT0UxDDAKBgNVBAsTA1dFQjELMAkGA1UEBhMCR1IxDzANBgNVBAgTBkF0dGlraTEPMA0GA1UEBxMGQXRoZW5zMRwwGgYDVQRhExNQU0RHUi1CT0ctODAwMDAwMDA1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0WxZl1rEkW+5pfB4cDhkWewLUprD5ZjryaNlneJci08Mml3OHqiOUY2ngFE5WqSCk6/UI8c90W+hb4lpP+uy3vOUVb6VpqgdDUz7HqAKFkFV9ai4CuVEd+vweUv7oC4rnQ3z3jNJWd41gEcVmlq5w7WAruSooWPUeALQBDLSyXwHf+LsZU6juuh3JgpZMbxeMKyb1Vav6yZBFJDkCRFaXyfKhaOAl075QVex4PszXQDfZ1FgmQMzpQ3cuM97l8DmNMl/VZyPyjpDawgQyoQyHqapJksGL9Y1HtcAgtv4ZMZyh8LEqSSPk/7yusTFYi5PIod6Ht3VZWyG13sajuH82QIDAQABo4GRMIGOMIGLBggrBgEFBQcBAwR/MH0GBgQAgZgnAjBzMEwwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSTARBgcEAIGYJwEDDAZQU1BfQUkwEQYHBACBmCcBBAwGUFNQX0lDDA5CYW5rIG9mIEdyZWVjZQwTUFNER1ItQk9HLTgwMDAwMDAwNTANBgkqhkiG9w0BAQsFAAOCAQEAliukROnrUhcDspfls3FOKqsmtjswuPCD+ob8xwhvbPSxBfn1b1toVmQ148d97icPJiOkCtKkCPJJAj32jCSPOrCY6r4XaY6PeK34DKpkEx9vxQ6rE1qObgC4E61s19yeIEfbNdsDpNX+LTpNVYeXeSKs/wZeOPjsKDpycFIry5PiLzyCdxvGNb7SfumVPWCEOy1/ExJRUUxut3y++DAN4C2PaYh8Mir3EOEVnkkH6m/7B+G+IaCuxWhX/NZ8GAq418wzSpqY2x333eMPFMWwNUg4zVjxg/DyNoJA8VWf2oZRRS23iZNmwJeOjkylYU7M61P8/oEt3yN8xse7ADHqxA==";
        private const string PrivateKeyId = "fd70ad0fe3949a471278c9dee9199adf";
        private const string TEST_RSA_PrivateKey_256 = @"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0WxZl1rEkW+5pfB4cDhkWewLUprD5ZjryaNlneJci08Mml3O
HqiOUY2ngFE5WqSCk6/UI8c90W+hb4lpP+uy3vOUVb6VpqgdDUz7HqAKFkFV9ai4
CuVEd+vweUv7oC4rnQ3z3jNJWd41gEcVmlq5w7WAruSooWPUeALQBDLSyXwHf+Ls
ZU6juuh3JgpZMbxeMKyb1Vav6yZBFJDkCRFaXyfKhaOAl075QVex4PszXQDfZ1Fg
mQMzpQ3cuM97l8DmNMl/VZyPyjpDawgQyoQyHqapJksGL9Y1HtcAgtv4ZMZyh8LE
qSSPk/7yusTFYi5PIod6Ht3VZWyG13sajuH82QIDAQABAoIBAQCibiZi9VzG7OAS
K5xOdf6nnCQAEtfkKaKgB2LWfW6IAmzlAeLP9q5D5NnI9bbFbhl1EQg6I9v3qFyP
FQYUNOzMbiJcCvEpjPTTjySq0ThhoJVab10n3kEnvlEK03s79vOO4faHHkJDOM1I
TFoeGUZB3HINtH5yhuqRlqTezMieynNeey/tK6aYozMpSpqM77MGQxNqiquPvhDd
eXw1v9ypZ7NxLnMahKtU75EsPcj0h/fAb4Yzr2wd/p3L2VmQ1hPs01wsyDFynTD8
BwZgQ/EgMePovKMKuu1LRHlPPMqFYICXeEAjk/Lhu7Z5hF1XYU4N3tneE6yzhjhb
UM7am08NAoGBANkeOmPYL2/SZK6+cOvWr43hXEyt9e+WbPVcdUkJR7TdLFiLON9X
l7bS2wLJxNiwJjwIL4opFgwOZEiuv63/lhujNa70VkTIfUhCdgSiMrE9KDzFbZ/K
YcQMqL2r+6BJwT9xXaQJMYGdiISqejawdkiyMFPTSvyZ+ybWgLeF1dNPAoGBAPbt
WjJg4AdUnrKj73Kqjos7b1gvklFo01cnZKNtwoh/UPEyFVBGhWLEQCrRfr1qTgiN
xudy4nQZDGbLwH6UObw0pCRDidaxye+8LJq37osUIjvBO0w9sDuDmWpcUpVtOP40
3YwZqUKqBhRFNVr1Js+5Pw/zE/+vGVdVanGQHsNXAoGBANeBM3/LIzqg4KK6EKdm
TpZLbCwIN6Z57uiTvy6hcXVKWyv/9JFrBgHHxO89io9yOGE51sYSBfothsjF+ygg
GsSP+UcQ61gWkJPas/3haOOXyoqXhDoozWWlExBA1t/AlXn9cm7RWTxIOytDc085
VA7QHzv06+dSh4GDQ/vlcdntAoGAEqWH2ygPot4UAd95VIpmq0L4vIsTHIyy8PDr
m5/NQeuDXENw8pfwuK2jPtiFHp6pd+Hk9FNroGLH2fdm+OgOmBTNlGN5RDo2yqDG
KYTcQapqj2KfLLm31jaw3iRMpDYUSLYLSOojKwKV5O/5AH5kyOjvRzAPAY7idgLg
P+UnPY8CgYA4muVDED/i44ATAGUGPQalOnnx+D97tVoSlIUllicLE+WCOs2zPF7A
uHhPvkzTq5qXFn4s635w32I7xalg/L4g5kffZ/HkQQrF1uNb3BP3fymmWtTvDlB5
59eKROVXeYUTerE08BpQAGTSMrZ67iOFg76JAg488ferJ6HnDTPl0w==
-----END RSA PRIVATE KEY-----
";

        [Fact]
        public void JwtTokenValidationTest() {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            // create jwt client authentication payload.
            var claims = new[] {
                new  Claim(JwtClaimTypes.Subject, ValidSubject),
            };
            var privateKey = TEST_RSA_PrivateKey_256.ReadAsRSAKey();
            var securityKey = new RsaSecurityKey(privateKey);
            securityKey.KeyId = PrivateKeyId;
            var signInCred = new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSha256Signature);
            var token = new JwtSecurityToken(
                issuer: ValidIssuer,
                audience: ValidAudience,
                expires: DateTime.Now.AddMinutes(3),
                claims: claims,                      
                signingCredentials: signInCred
            );
            //End of custom claims
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            // validate
            SecurityToken validatedToken;
            var validationParameters = new TokenValidationParameters();
            validationParameters.IssuerSigningKey = new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(TEST_X509_PublicKey_2048)));
            validationParameters.ValidAudience = ValidAudience;
            validationParameters.ValidIssuer = ValidIssuer;

            var principal = new JwtSecurityTokenHandler().ValidateToken(jwt, validationParameters, out validatedToken);

            //Assert.AreEqual("expectedClaimKeyValue", principal.FindFirst("claimKey").Value);
        }
    }




    public class JwtTokenValidation
    {
        public async Task<Dictionary<string, X509Certificate2>> FetchGoogleCertificates() {
            using (var http = new HttpClient()) {
                var response = await http.GetAsync("https://www.googleapis.com/oauth2/v1/certs");
                var json = await response.Content.ReadAsStringAsync();
                var dictionary = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                return dictionary.ToDictionary(x => x.Key, x => new X509Certificate2(Encoding.UTF8.GetBytes(x.Value)));
            }
        }

        private string CLIENT_ID = "xxxx.apps.googleusercontent.com";

        public async Task<ClaimsPrincipal> ValidateToken(string idToken) {
            var certificates = await FetchGoogleCertificates();

            var validationParameters = new TokenValidationParameters() {
                ValidateActor = false, // check the profile ID

                ValidateAudience = true, // check the client ID
                ValidAudience = CLIENT_ID,

                ValidateIssuer = true, // check token came from Google
                ValidIssuers = new List<string> { "accounts.google.com", "https://accounts.google.com" },

                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                IssuerSigningKeys = certificates.Values.Select(x => new X509SecurityKey(x)),
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) => {
                    return certificates
                    .Where(x => x.Key.ToUpper() == kid.ToUpper())
                    .Select(x => new X509SecurityKey(x.Value));
                },
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromHours(13)
            };

            var handler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            var principal = handler.ValidateToken(idToken, validationParameters, out validatedToken);
            return principal;
        }
    }
}
