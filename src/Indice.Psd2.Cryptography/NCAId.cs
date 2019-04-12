using System;
using System.Text.RegularExpressions;

namespace Indice.Psd2.Cryptography
{
    /// <summary>
    /// National Competent Authority Id
    /// PSD2 Authorization Number or other recognized identifier 
    /// Examples "PSDPL-PFSA-1234567890" "PSDFI-FINFSA-1234567-8"  "PSDMT-MFSA-A 12345"
    /// </summary>
    public struct NCAId
    {
        private const string REGEX_PATTERN = "PSD([A-Z]{2})(-|_)([A-Z]{2,8})(-|_)(.+)";

        /// <summary>
        /// Construct from the distinct parts.
        /// </summary>
        /// <param name="twoLetterISOCountryCode"></param>
        /// <param name="supervisionAuthority"></param>
        /// <param name="pSPIdentifier"></param>
        public NCAId(string twoLetterISOCountryCode, string supervisionAuthority, string pSPIdentifier) {
            CountryCode = twoLetterISOCountryCode;
            SupervisionAuthority = supervisionAuthority;
            AuthorizationNumber = pSPIdentifier;
        }

        /// <summary>
        /// Checks to see if the code was parsed correctly
        /// </summary>
        public bool IsValid => !string.IsNullOrEmpty(CountryCode) && !string.IsNullOrEmpty(SupervisionAuthority) && !string.IsNullOrEmpty(AuthorizationNumber);

        /// <summary>
        /// 2 character ISO 3166-1 [8] country code representing the NCA country
        /// </summary>
        public string CountryCode { get; }
        /// <summary>
        /// 2-8 character NCA identifier without country code (A-Z uppercase only, no separator); 
        /// </summary>
        public string SupervisionAuthority { get; }
        /// <summary>
        /// PSP identifier (authorization number as specified by the NCA. There are no restrictions on the characters used). 
        /// </summary>
        public string AuthorizationNumber   { get; }

        /// <summary>
        ///  PSP Identifier can contain prefix, followed by colon ":", including type of institution, as listed in
        ///  Credit institution – CI
        ///  Payment institution – PI 
        ///  Electronic money institution (or e-money institution) – EMI 
        ///  Account information service provider exempted under Article 33 of PSD2 – RAISP 
        /// </summary>
        public string InstitutionType {
            get {
                return AuthorizationNumber.StartsWith("CI:") ? "CI" :
                       AuthorizationNumber.StartsWith("PI:") ? "PI" :
                       AuthorizationNumber.StartsWith("EMI:") ? "EMI" : string.Empty;
            }
        }
        
        /// <summary>
        /// Discription for Type of institytion.
        /// PSP Identifier can contain prefix, followed by colon ":", including type of institution, as listed in
        /// Credit institution – CI
        /// Payment institution – PI 
        /// Electronic money institution (or e-money institution) – EMI 
        /// Account information service provider exempted under Article 33 of PSD2 – RAISP 
        /// </summary>
        public string InstitutionTypeDescription {
            get {
                switch (InstitutionType) {
                    case "CI": return "Credit institution";
                    case "PI": return "Payment institution";
                    case "EMI": return "Electronic money institution (or e-money institution)";
                    default: return string.Empty;
                }
            }
        }

        /// <summary>
        /// Convert back to string. Combining all parts.
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            if (IsValid)
                return $"PSD{CountryCode}-{SupervisionAuthority}-{AuthorizationNumber}";
            else
                return AuthorizationNumber;
        }

        /// <summary>
        /// Parses a text representation of National Competent Authority Id
        /// Examples: "PSDPL-PFSA-1234567890" "PSDFI-FINFSA-1234567-8"  "PSDMT-MFSA-A 12345"
        /// </summary>
        /// <param name="text">The input</param>
        /// <param name="throwOnError">When true the method will throw a <see cref="FormatException"/> if the <paramref name="text"/> 
        /// is not formated according to spec. Otherwize it will populate only the PSP identitfier part.</param>
        /// <returns></returns>
        public static NCAId Parse(string text, bool throwOnError = true) {
            var regex = new Regex(REGEX_PATTERN);
            if (!regex.IsMatch(text)) {
                if (throwOnError) { 
                    throw new FormatException("Invalid PSD2 Authorization Number");
                } else {
                    return new NCAId(null, null, text);
                }
            }
            var match = regex.Match(text);
            return new NCAId(match.Groups[1].Value, match.Groups[3].Value, match.Groups[5].Value);
        }

    }
}

