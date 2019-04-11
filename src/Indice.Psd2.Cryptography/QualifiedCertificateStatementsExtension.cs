using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DerConverter.Asn;
using DerConverter.Asn.KnownTypes;

namespace Indice.Psd2.Cryptography
{
    /// <summary>
    /// QCStatement (rfc3739)
    /// 
    /// Class for standard X509 certificate extension. 
    /// This extension have some basics defined in RFC 3739, but the majority of fields are used in EU purposes 
    /// and specified in EU standards.
    /// ETSI EN 319 412-5 (v2.1.1, 2016-02 or later)
    /// https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf
    /// ETSI TS 101 862 (v1.3.3, 2006-01 or later)
    /// https://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.03_60/ts_101862v010303p.pdf
    /// ETSI TS 119 495 (v1.1.2, 2018-07 or later)
    /// https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf
    /// 
    /// qcStatements  EXTENSION ::= {
    ///        SYNTAX             QCStatements
    ///        IDENTIFIED BY      id-pe-qcStatements }
    /// id-pe-qcStatements     OBJECT IDENTIFIER ::= { id-pe 3 }
    /// 
    ///    QCStatements ::= SEQUENCE OF QCStatement
    ///    QCStatement ::= SEQUENCE {
    ///        statementId   QC-STATEMENT.&amp;Id({SupportedStatements}),
    ///        statementInfo QC-STATEMENT.&amp;Type
    ///        ({SupportedStatements}{@statementId}) OPTIONAL }
    /// 
    ///    SupportedStatements QC-STATEMENT ::= { qcStatement-1,...}
    /// </summary>
    public class QualifiedCertificateStatementsExtension : X509Extension
    {
        /// <summary>
        /// Qualified Certificate Statements Oid (X509 v3)
        /// </summary>
        public const string Oid_QC_Statements = "1.3.6.1.5.5.7.1.3";

        /// <summary>
        /// Used to create the extension from typed model
        /// </summary>
        /// <param name="psd2Type"></param>
        /// <param name="critical"></param>
        public QualifiedCertificateStatementsExtension(Psd2CertificateAttributes psd2Type, bool critical) {
            Oid = new Oid(Oid_QC_Statements, "Qualified Certificate Statements");
            Critical = critical;
            var encoder = new DefaultDerAsnEncoder();
            RawData = encoder.Encode(new Psd2QcStatement(psd2Type)).ToArray();
            _Psd2Type = psd2Type;
            _decoded = true;
        }

        /// <summary>
        /// Used to deserialize from an existing extension instance.
        /// </summary>
        /// <param name="encodedExtension"></param>
        /// <param name="critical"></param>
        public QualifiedCertificateStatementsExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {

        }

        private bool _decoded = false;
        private Psd2CertificateAttributes _Psd2Type;

        /// <summary>
        /// The deserialized contents
        /// </summary>
        public Psd2CertificateAttributes Psd2Type {
            get {
                if (!_decoded) { 
                    DecodeExtension();
                }
                return _Psd2Type;
            }
        }

        /// <summary>
        /// Copies the extension properties of the specified System.Security.Cryptography.AsnEncodedData object.
        /// </summary>
        /// <param name="asnEncodedData">The System.Security.Cryptography.AsnEncodedData to be copied.</param>
        public override void CopyFrom(AsnEncodedData asnEncodedData) {
            base.CopyFrom(asnEncodedData);
            _decoded = false;
        }

        private void DecodeExtension() {
            var decoder = new DefaultDerAsnDecoder();
            var sequence = decoder.Decode(RawData) as DerAsnSequence;
            _Psd2Type = new Psd2QcStatement(sequence.Value).ExtractAttributes();
            _decoded = true;
        }
    }

    /// <summary>
    /// Qualified Certificate Statements for PSD2
    /// etsi-psd2-qcStatement QC-STATEMENT ::= {SYNTAX PSD2QcType IDENTIFIED BY id-etsi-psd2-qcStatement } 
    /// </summary>
    public class Psd2QcStatement : DerAsnSequence
    {
        /// <summary>
         /// id-etsi-psd2-qcStatement OBJECT IDENTIFIER ::=  { itu-t(0) identified-organization(4) etsi(0) psd2(19495) qcstatement(2) } 
         /// </summary>
        public const string Oid_PSD2_QcStatement = "0.4.0.19495.2";
        private const string Oid_PSD2_Roles = "0.4.0.19495.1";
        private const string Oid_PSD2_Roles_PSP_AS = Oid_PSD2_Roles + ".1";
        private const string Oid_PSD2_Roles_PSP_PI = Oid_PSD2_Roles + ".2";
        private const string Oid_PSD2_Roles_PSP_AI = Oid_PSD2_Roles + ".3";
        private const string Oid_PSD2_Roles_PSP_IC = Oid_PSD2_Roles + ".4";

        private static readonly Dictionary<string, string> roleId2NameMap = new Dictionary<string, string> {
            ["PSP_AS"] = Oid_PSD2_Roles_PSP_AS,
            ["PSP_PI"] = Oid_PSD2_Roles_PSP_PI,
            ["PSP_AI"] = Oid_PSD2_Roles_PSP_AI,
            ["PSP_IC"] = Oid_PSD2_Roles_PSP_IC
        };

        private static string GetPsd2Oid(string roleName) {
            return roleId2NameMap[roleName];
        }
        private static int[] Oid2Array(string oid) {
            return oid.Split('.').Select(x => int.Parse(x)).ToArray();
        }

        /// <summary>
        /// Constructs the QcStatement from <see cref="Psd2CertificateAttributes "/>.
        /// </summary>
        /// <param name="type"></param>
        public Psd2QcStatement(Psd2CertificateAttributes type) : base(new DerAsnType[0]) { 
            var rolesList = new List<DerAsnSequence>();
            foreach (var roleName in type.Roles) {
                var id = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid2Array(GetPsd2Oid(roleName)));
                var name = new DerAsnUtf8String(roleName);
                var role = new DerAsnSequence(new DerAsnType[] { id, name });
                rolesList.Add(role);
            }
            var rolesOfPSP = new DerAsnSequence(rolesList.ToArray()); //RolesOfPSP ::= SEQUENCE OF RoleOfPSP 
            var ncaName = new DerAsnUtf8String(type.AuthorityName);
            var ncaId = new DerAsnUtf8String(type.AuthorizationNumber.ToString());

            var typeSequence = new DerAsnSequence(new DerAsnType[] { rolesOfPSP, ncaName, ncaId });

            var psd2QstatementOid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid2Array(Oid_PSD2_QcStatement));
            Value = new DerAsnType[] { psd2QstatementOid, typeSequence };
        }

        /// <summary>
        /// constructs the QcStatement from an array of ANS.1 Der encoded data.
        /// </summary>
        /// <param name="value"></param>
        public Psd2QcStatement(DerAsnType[] value) : base(value) {

        }

        /// <summary>
        /// Deserializes the raw data into the concrete class <see cref="Psd2CertificateAttributes"/>.
        /// </summary>
        /// <returns>Deserilized contents</returns>
        public Psd2CertificateAttributes ExtractAttributes() {
            var attributes = new Psd2CertificateAttributes();
            var typeSequence = Value.Where(x => x is DerAsnSequence).FirstOrDefault() as DerAsnSequence;
            var roleSequence = typeSequence?.Value.Where(x => x is DerAsnSequence).FirstOrDefault() as DerAsnSequence;
            var ncaName = typeSequence?.Value[1] as DerAsnUtf8String;
            var ncaId = typeSequence?.Value[2] as DerAsnUtf8String;
            attributes.AuthorityName = ncaName.Value;
            attributes.AuthorizationNumber = NCAId.Parse(ncaId.Value, false);
            foreach (var item in roleSequence.Value) {
                if (!(item is DerAsnSequence)) {
                    continue;
                }
                var role = item as DerAsnSequence;
                var roleOid = role.Value[0] as DerAsnObjectIdentifier;
                var roleOidString = string.Join(".", roleOid.Value);
                switch (roleOidString) {
                    case Oid_PSD2_Roles_PSP_AS: attributes.HasAccountServicing = true; break;
                    case Oid_PSD2_Roles_PSP_PI: attributes.HasPaymentInitiation = true; break;
                    case Oid_PSD2_Roles_PSP_AI: attributes.HasAccountInformation = true; break;
                    case Oid_PSD2_Roles_PSP_IC: attributes.HasIssuingOfCardBasedPaymentInstruments = true; break;
                }
            }
            return attributes;
            }
        }
}

