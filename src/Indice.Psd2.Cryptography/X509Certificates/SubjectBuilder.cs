using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Indice.Psd2.Cryptography.X509Certificates
{
    /// <summary>
    /// Helps build a the subject for the <see cref="X500DistinguishedName"/> extention.
    /// </summary>
    public class SubjectBuilder
    {
        private Dictionary<string, string> Data { get; } = new Dictionary<string, string>();

        /// <summary>
        /// Helps build a the subject for the <see cref="X500DistinguishedName"/> extention. Using fluent configuration.
        /// </summary>
        public SubjectBuilder() {

        }

        /// <summary>
        /// Add whatever you like. Use with caution.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public SubjectBuilder Add(string key, string value) {
            Data.Add(key, value);
            return this;
        }

        /// <summary>
        /// Adds CN 
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public SubjectBuilder AddCommonName(string value) {
            Data.Add("CN", value);
            return this;
        }

        /// <summary>
        /// Ands O and OU
        /// </summary>
        /// <param name="organizationName"></param>
        /// <param name="organizationUnit"></param>
        /// <returns></returns>
        public SubjectBuilder AddOrganization(string organizationName, string organizationUnit) {
            Data.Add("O", organizationName);
            Data.Add("OU", organizationUnit);
            return this;
        }

        /// <summary>
        /// Adds C S &amp; L
        /// </summary>
        /// <param name="countryCode"></param>
        /// <param name="state"></param>
        /// <param name="city"></param>
        /// <returns></returns>
        public SubjectBuilder AddLocation(string countryCode, string state = null, string city = null) {
            Data.Add("C", countryCode);
            if (!string.IsNullOrEmpty(state))
                Data.Add("S", state);
            if (!string.IsNullOrEmpty(city))
                Data.Add("L", city);
            return this;
        }

        /// <summary>
        /// Adds Email E
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public SubjectBuilder AddEmail(string email) {
            Data.Add("E", email);
            return this;
        }

        /// <summary>
        /// Add User Identifier UID
        /// </summary>
        /// <param name="userIdentifier"></param>
        /// <returns></returns>
        public SubjectBuilder AddUserIdentifier(string userIdentifier) {
            Data.Add("UID", userIdentifier);
            return this;
        }

        /// <summary>
        /// Add server domain component DC
        /// </summary>
        /// <param name="domainComponent"></param>
        /// <returns></returns>
        public SubjectBuilder AddDomainComponent(string domainComponent) {
            Data.Add("DC", domainComponent);
            return this;
        }

        /// <summary>
        /// adds Organization identifier as it is identified by the 2.5.4.97 Oid
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public SubjectBuilder AddOrganizationIdentifier(string id) {
            Data.Add("2.5.4.97", id);
            return this;
        }

        /// <summary>
        /// adds SERIALNUMBER (2.5.4.5 Oid)
        /// </summary>
        /// <param name="serialNumber"></param>
        /// <returns></returns>
        public SubjectBuilder AddSerialNumber(string serialNumber) {
            Data.Add("SERIALNUMBER", serialNumber);
            return this;
        }

        /// <summary>
        /// Generate the <see cref="X500DistinguishedName"/>
        /// </summary>
        /// <param name="flags">Controls the delimiter</param>
        /// <returns></returns>
        public X500DistinguishedName Build(X500DistinguishedNameFlags flags = X500DistinguishedNameFlags.UseNewLines) {
            var delimiter = '\n';
            if (flags.HasFlag(X500DistinguishedNameFlags.UseNewLines)) {
                delimiter = '\n';
            } else if (flags.HasFlag(X500DistinguishedNameFlags.UseCommas)) {
                delimiter = ',';
            } else if (flags.HasFlag(X500DistinguishedNameFlags.UseSemicolons)) {
                delimiter = ';';
            }
#if NETCOREAPP22
            var name = string.Join(delimiter, Data.Select(x => $"{x.Key}={x.Value}").ToArray());
#else
            var name = string.Join(delimiter.ToString(), Data.Select(x => $"{x.Key}={x.Value}").ToArray());
#endif
            return new X500DistinguishedName(name, flags);
        }
    }
}
