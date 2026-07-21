using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Regex-based WHOIS parser (inspired by weppos/whois-parser)
/// Uses regex patterns to extract fields from WHOIS responses
/// </summary>
[Obsolete("Use RegexWhoisParserWrapper instead. This class is kept for backward compatibility but is no longer actively maintained.")]
public partial class RegexParser
{
    private static readonly Dictionary<string, List<FieldPattern>> FieldPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        // Domain
        ["domain"] =
        [
            new(@"Domain Name:\s*(.+)", 1, "verisign"),
            new(@"Domain name:\s*(.+)", 1, "generic"),
            new(@"domain:\s*(.+)", 1, "generic"),
            new(@"domain name:\s*(.+)", 1, "generic"),
            new(@"\[Domain Name\]\s*(.+)", 1, "jprs"),
            new(@"Complete Domain Name:\s*(.+)", 1, "generic"),
            new(@"Nome de domínio / Domain Name:\s*(.+)", 1, "br"),
            new(@"domain_name:\s*(.+)", 1, "srs_nz"),
            new(@"Domain:\s*(.+)", 1, "denic"),
        ],
        ["registry_domain_id"] =
        [
            new(@"Registry Domain ID:\s*(.+)", 1, "verisign"),
            new(@"Domain ID:\s*(.+)", 1, "generic"),
            new(@"ROID:\s*(.+)", 1, "cnnic"),
            new(@"Registry ID:\s*(.+)", 1, "generic"),
        ],
        ["registrar_name"] =
        [
            new(@"Registrar:\s*(.+)", 1, "verisign"),
            new(@"Sponsoring Registrar:\s*(.+)", 1, "cocca"),
            new(@"Registrar Name:\s*(.+)", 1, "generic"),
            new(@"Authorized Agency:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar Organization:\s*(.+)", 1, "generic"),
            new(@"Last Updated by Registrar:\s*(.+)", 1, "generic"),
            new(@"Registrar ID:\s*(.+)", 1, "generic"),
            new(@"registrar:\s*(.+)", 1, "generic"),
            new(@"등록대행자:\s*(.+)", 1, "kr"),
            new(@"registrar_name:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrar_iana_id"] =
        [
            new(@"Registrar IANA ID:\s*(.+)", 1, "verisign"),
            new(@"Registrar ID:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar IANA ID:\s*(.+)", 1, "cocca"),
        ],
        ["registrar_url"] =
        [
            new(@"Registrar URL:\s*(.+)", 1, "verisign"),
            new(@"Registrar Website:\s*(.+)", 1, "generic"),
            new(@"URL:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar URL:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar Website:\s*(.+)", 1, "generic"),
            new(@"Referral URL:\s*(.+)", 1, "generic"),
            new(@"Registrar URL \(registration services\):\s*(.+)", 1, "generic"),
            new(@"Registration URL:\s*(.+)", 1, "generic"),
        ],
        ["registrar_whois"] =
        [
            new(@"Registrar WHOIS Server:\s*(.+)", 1, "verisign"),
            new(@"Whois Server:\s*(.+)", 1, "generic"),
            new(@"WHOIS Server:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar WHOIS Server:\s*(.+)", 1, "generic"),
        ],
        ["registrar_abuse_email"] =
        [
            new(@"Registrar Abuse Contact Email:\s*(.+)", 1, "verisign"),
            new(@"Sponsoring Registrar Customer Service Email:\s*(.+)", 1, "generic"),
        ],
        ["registrar_abuse_phone"] =
        [
            new(@"Registrar Abuse Contact Phone:\s*(.+)", 1, "verisign"),
            new(@"Sponsoring Registrar Phone:\s*(.+)", 1, "generic"),
            new(@"Sponsoring Registrar Customer Service Contact:\s*(.+)", 1, "generic"),
            new(@"Registrar Contact Information:\s*(.+)", 1, "generic"),
        ],

        // Dates
        ["created"] =
        [
            new(@"Creation Date:\s*(.+)", 1, "verisign"),
            new(@"Created:\s*(.+)", 1, "generic"),
            new(@"Created Date:\s*(.+)", 1, "generic"),
            new(@"Created On:\s*(.+)", 1, "generic"),
            new(@"Domain Create Date:\s*(.+)", 1, "generic"),
            new(@"Registration Date:\s*(.+)", 1, "generic"),
            new(@"Registered on:\s*(.+)", 1, "generic"),
            new(@"Registered Date:\s*(.+)", 1, "generic"),
            new(@"Registration Time:\s*(.+)", 1, "cnnic"),
            new(@"Record created:\s*(.+)", 1, "generic"),
            new(@"Record Created:\s*(.+)", 1, "generic"),
            new(@"created:\s*(.+)", 1, "generic"),
            new(@"registered:\s*(.+)", 1, "generic"),
            new(@"Domain Registration Date:\s*(.+)", 1, "generic"),
            new(@"Domain record activated:\s*(.+)", 1, "generic"),
            new(@"Domain Name Commencement Date:\s*(.+)", 1, "generic"),
            new(@"\[Registered Date\]:\s*(.+)", 1, "jprs"),
            new(@"\[Created on\]:\s*(.+)", 1, "generic"),
            new(@"Data de registo / Creation Date:\s*(.+)", 1, "pt"),
            new(@"Record created on:\s*(.+)", 1, "generic"),
            new(@"\[登録年月日\]\s*(.+)", 1, "jprs"),
            new(@"등록일:\s*(.+)", 1, "kr"),
            new(@"domain_dateregistered:\s*(.+)", 1, "srs_nz"),
            new(@"Date registered:\s*(.+)", 1, "generic"),
            new(@"Registered:\s*(.+)", 1, "generic"),
        ],
        ["updated"] =
        [
            new(@"Updated Date:\s*(.+)", 1, "verisign"),
            new(@"Modified:\s*(.+)", 1, "generic"),
            new(@"Last Modified:\s*(.+)", 1, "generic"),
            new(@"Last Updated:\s*(.+)", 1, "generic"),
            new(@"Last Updated On:\s*(.+)", 1, "generic"),
            new(@"Domain Last Updated Date:\s*(.+)", 1, "generic"),
            new(@"Last Updated Date:\s*(.+)", 1, "generic"),
            new(@"Record last updated on:\s*(.+)", 1, "generic"),
            new(@"Record last updated:\s*(.+)", 1, "generic"),
            new(@"Last Update:\s*(.+)", 1, "generic"),
            new(@"last-update:\s*(.+)", 1, "generic"),
            new(@"changed:\s*(.+)", 1, "generic"),
            new(@"\[Last Update\]:\s*(.+)", 1, "generic"),
            new(@"\[Last Updated\]:\s*(.+)", 1, "generic"),
            new(@"modified:\s*(.+)", 1, "generic"),
            new(@"Domain record last updated:\s*(.+)", 1, "generic"),
            new(@"Record changed on:\s*(.+)", 1, "generic"),
            new(@"\[最終更新\]\s*(.+)", 1, "jprs"),
            new(@"최근 정보 변경일:\s*(.+)", 1, "kr"),
            new(@"domain_datelastmodified:\s*(.+)", 1, "srs_nz"),
            new(@"Record last updated:\s*(.+)", 1, "generic"),
            new(@"Modification date:\s*(.+)", 1, "rnids"),
            new(@"Update Date:\s*(.+)", 1, "generic"),
        ],
        ["expires"] =
        [
            new(@"Registry Expiry Date:\s*(.+)", 1, "verisign"),
            new(@"Expiration Date:\s*(.+)", 1, "generic"),
            new(@"Expires:\s*(.+)", 1, "generic"),
            new(@"Expiry Date:\s*(.+)", 1, "generic"),
            new(@"Expiry date:\s*(.+)", 1, "generic"),
            new(@"Expiry:\s*(.+)", 1, "generic"),
            new(@"expire:\s*(.+)", 1, "generic"),
            new(@"Registrar Registration Expiration Date:\s*(.+)", 1, "generic"),
            new(@"Domain Expiration Date:\s*(.+)", 1, "generic"),
            new(@"Expiration Time:\s*(.+)", 1, "cnnic"),
            new(@"Record expires on:\s*(.+)", 1, "generic"),
            new(@"Record expires:\s*(.+)", 1, "generic"),
            new(@"Expiration:\s*(.+)", 1, "generic"),
            new(@"expires:\s*(.+)", 1, "generic"),
            new(@"Domain expires:\s*(.+)", 1, "generic"),
            new(@"\[Expires on\]:\s*(.+)", 1, "generic"),
            new(@"\[有効期限\]\s*(.+)", 1, "jprs"),
            new(@"Data de expiração / Expiration Date:\s*(.+)", 1, "pt"),
            new(@"Expired:\s*(.+)", 1, "generic"),
            new(@"사용 종료일:\s*(.+)", 1, "kr"),
            new(@"domain_datebilleduntil:\s*(.+)", 1, "srs_nz"),
            new(@"Expire Date:\s*(.+)", 1, "generic"),
            new(@"renewal date:\s*(.+)", 1, "generic"),
        ],

        // Status
        ["status"] =
        [
            new(@"Domain Status:\s*(.+)", 1, "verisign"),
            new(@"Status:\s*(.+)", 1, "generic"),
            new(@"Registration status:\s*(.+)", 1, "generic"),
            new(@"Domain status:\s*(.+)", 1, "generic"),
            new(@"status:\s*(.+)", 1, "generic"),
            new(@"\[State\]:\s*(.+)", 1, "generic"),
            new(@"\[Status\]:\s*(.+)", 1, "generic"),
            new(@"state:\s*(.+)", 1, "generic"),
            new(@"Estado / Status:\s*(.+)", 1, "pt"),
            new(@"Re-registration Status:\s*(.+)", 1, "generic"),
            new(@"\[状態\]\s*(.+)", 1, "jprs"),
            new(@"\[ロック状態\]\s*(.+)", 1, "jprs"),
            new(@"등록정보 보호:\s*(.+)", 1, "kr"),
            new(@"query_status:\s*(.+)", 1, "srs_nz"),
            new(@"ren-status:\s*(.+)", 1, "domainregistry_ie"),
            new(@"Domain status:\s*(.+)", 1, "generic"),
            new(@"domaintype:\s*(.+)", 1, "dns_lu"),
        ],

        // Nameservers
        ["nameserver"] =
        [
            new(@"Name Server:\s*(.+)", 1, "verisign"),
            new(@"Nameserver:\s*(.+)", 1, "generic"),
            new(@"nserver:\s*(.+)", 1, "denic"),
            new(@"Name servers:\s*(.+)", 1, "generic"),
            new(@"Name Servers:\s*(.+)", 1, "generic"),
            new(@"Name servers in the listed order:\s*(.+)", 1, "generic"),
            new(@"Nameservers:\s*(.+)", 1, "generic"),
            new(@"Nserver:\s*(.+)", 1, "generic"),
            new(@"DNS:\s*(.+)", 1, "generic"),
            new(@"Host Name:\s*(.+)", 1, "generic"),
            new(@"\[Name Server\]\s*(.+)", 1, "jprs"),
            new(@"Domain nameservers:\s*(.+)", 1, "generic"),
            new(@"Domain servers:\s*(.+)", 1, "generic"),
            new(@"Domain servers in listed order:\s*(.+)", 1, "generic"),
            new(@"Nameserver Information:\s*(.+)", 1, "generic"),
            new(@"Primary Server Hostname:\s*(.+)", 1, "generic"),
            new(@"Secondary Server Hostname:\s*(.+)", 1, "generic"),
            new(@"ns_name_01:\s*(.+)", 1, "srs_nz"),
            new(@"ns_name_02:\s*(.+)", 1, "srs_nz"),
            new(@"ns_name_03:\s*(.+)", 1, "srs_nz"),
            new(@"ns_name_04:\s*(.+)", 1, "srs_nz"),
            new(@"Hostname:\s*(.+)", 1, "generic"),
            new(@"Name servers:\n\s+(.+)", 1, "generic"),
        ],

        // Registrant (weppos patterns: owner-contact, Registrant Contact)
        ["registrant_id"] =
        [
            new(@"Registrant ID:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact ID:\s*(.+)", 1, "shared1"),
            new(@"Registry Registrant ID:\s*(.+)", 1, "generic"),
            new(@"owner-contact:\s*(.+)", 1, "shared3"),
            new(@"holder-c:\s*(.+)", 1, "nic_fr"),
        ],
        ["registrant_name"] =
        [
            new(@"Registrant Name:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Name:\s*(.+)", 1, "shared1"),
            new(@"Registrant:\s*(.+)", 1, "cnnic"),
            new(@"Name:\s*(.+)", 1, "generic"),
            new(@"person:\s*(.+)", 1, "generic"),
            new(@"contact:\s*(.+)", 1, "generic"),
            new(@"owner-name:\s*(.+)", 1, "shared3"),
            new(@"\[Registrant\]:\s*(.+)", 1, "generic"),
            new(@"\[Registrant\]\s*(.+)", 1, "generic"),
            new(@"Titular / Registrant:\s*(.+)", 1, "pt"),
            new(@"holder:\s*(.+)", 1, "generic"),
            new(@"holder-c:\s*(.+)", 1, "generic"),
            new(@"Organization Using Domain Name:\s*(.+)", 1, "generic"),
            new(@"Nombre:\s*(.+)", 1, "generic"),
            new(@"\[登録者名\]\s*(.+)", 1, "jprs"),
            new(@"\[名前\]\s*(.+)", 1, "jprs"),
            new(@"\[Name\]\s*(.+)", 1, "jprs"),
            new(@"등록인:\s*(.+)", 1, "kr"),
            new(@"registrant_contact_name:\s*(.+)", 1, "srs_nz"),
            new(@"Registrant name:\s*(.+)", 1, "nc"),
        ],
        ["registrant_org"] =
        [
            new(@"Registrant Organization:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Organization:\s*(.+)", 1, "shared1"),
            new(@"owner-organization:\s*(.+)", 1, "shared3"),
            new(@"Organization:\s*(.+)", 1, "generic"),
            new(@"Org Name:\s*(.+)", 1, "generic"),
            new(@"Organisation:\s*(.+)", 1, "generic"),
            new(@"descr:\s*(.+)", 1, "generic"),
            new(@"role:\s*(.+)", 1, "generic"),
            new(@"Organization Name:\s*(.+)", 1, "generic"),
            new(@"Company English Name:\s*(.+)", 1, "generic"),
            new(@"org:\s*(.+)", 1, "generic"),
        ],
        ["registrant_email"] =
        [
            new(@"Registrant Email:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Email:\s*(.+)", 1, "shared1"),
            new(@"Registrant Email Address:\s*(.+)", 1, "generic"),
            new(@"Registrant E-mail:\s*(.+)", 1, "generic"),
            new(@"owner-email:\s*(.+)", 1, "shared3"),
            new(@"AC E-Mail:\s*(.+)", 1, "generic"),
            new(@"Email:\s*(.+)", 1, "generic"),
            new(@"E-mail:\s*(.+)", 1, "generic"),
            new(@"e-mail:\s*(.+)", 1, "generic"),
            new(@"E-Mailbox:\s*(.+)", 1, "generic"),
            new(@"Email Address:\s*(.+)", 1, "generic"),
            new(@"\[Email\]\s*(.+)", 1, "jprs"),
            new(@"registrant_contact_email:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_street"] =
        [
            new(@"Registrant Street:\s*(.+)", 1, "verisign"),
            new(@"Registrant Street1:\s*(.+)", 1, "generic"),
            new(@"Registrant Street2:\s*(.+)", 1, "generic"),
            new(@"Registrant Address:\s*(.+)", 1, "generic"),
            new(@"Registrant Address1:\s*(.+)", 1, "generic"),
            new(@"Registrant Address2:\s*(.+)", 1, "generic"),
            new(@"Registrant Address3:\s*(.+)", 1, "generic"),
            new(@"Registrant Contact Street:\s*(.+)", 1, "shared1"),
            new(@"owner-street:\s*(.+)", 1, "shared3"),
            new(@"Address:\s*(.+)", 1, "generic"),
            new(@"Street:\s*(.+)", 1, "generic"),
            new(@"address:\s*(.+)", 1, "generic"),
            new(@"Registrant's address:\s*(.+)", 1, "generic"),
            new(@"street address:\s*(.+)", 1, "generic"),
            new(@"\[住所\]\s*(.+)", 1, "jprs"),
            new(@"\[Postal Address\]\s*(.+)", 1, "jprs"),
            new(@"등록인 주소:\s*(.+)", 1, "kr"),
            new(@"registrant_contact_address1:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_city"] =
        [
            new(@"Registrant City:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact City:\s*(.+)", 1, "shared1"),
            new(@"owner-city:\s*(.+)", 1, "shared3"),
            new(@"City:\s*(.+)", 1, "generic"),
            new(@"city:\s*(.+)", 1, "generic"),
            new(@"registrant_contact_city:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_state"] =
        [
            new(@"Registrant State/Province:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact State/Province:\s*(.+)", 1, "shared1"),
            new(@"StateProv:\s*(.+)", 1, "generic"),
            new(@"State:\s*(.+)", 1, "generic"),
            new(@"Province:\s*(.+)", 1, "generic"),
            new(@"registrant_contact_province:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_postal"] =
        [
            new(@"Registrant Postal Code:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Postal Code:\s*(.+)", 1, "shared1"),
            new(@"Registrant Zip:\s*(.+)", 1, "generic"),
            new(@"owner-zip:\s*(.+)", 1, "shared3"),
            new(@"PostalCode:\s*(.+)", 1, "generic"),
            new(@"Zip:\s*(.+)", 1, "generic"),
            new(@"Postal Code:\s*(.+)", 1, "generic"),
            new(@"Registrant Zip Code:\s*(.+)", 1, "generic"),
            new(@"postal code:\s*(.+)", 1, "generic"),
            new(@"\[郵便番号\]\s*(.+)", 1, "jprs"),
            new(@"등록인 우편번호:\s*(.+)", 1, "kr"),
            new(@"registrant_contact_postalcode:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_country"] =
        [
            new(@"Registrant Country:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Country:\s*(.+)", 1, "shared1"),
            new(@"owner-country:\s*(.+)", 1, "shared3"),
            new(@"Country:\s*(.+)", 1, "generic"),
            new(@"Country Code:\s*(.+)", 1, "generic"),
            new(@"country:\s*(.+)", 1, "generic"),
            new(@"Registrant Country/Economy:\s*(.+)", 1, "generic"),
            new(@"registrant_contact_country:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_phone"] =
        [
            new(@"Registrant Phone:\s*(.+)", 1, "verisign"),
            new(@"Registrant Contact Phone:\s*(.+)", 1, "shared1"),
            new(@"owner-phone:\s*(.+)", 1, "shared3"),
            new(@"Phone:\s*(.+)", 1, "generic"),
            new(@"phone:\s*(.+)", 1, "generic"),
            new(@"Telephone:\s*(.+)", 1, "generic"),
            new(@"Registrant Phone Number:\s*(.+)", 1, "generic"),
            new(@"TEL:\s*(.+)", 1, "generic"),
            new(@"Phone Number:\s*(.+)", 1, "generic"),
            new(@"\[電話番号\]\s*(.+)", 1, "jprs"),
            new(@"registrant_contact_phone:\s*(.+)", 1, "srs_nz"),
        ],
        ["registrant_phone_ext"] =
        [
            new(@"Registrant Phone Ext:\s*(.+)", 1, "verisign"),
            new(@"Registrant Phone Ext\.:\s*(.+)", 1, "generic"),
        ],
        ["registrant_fax"] =
        [
            new(@"Registrant Fax:\s*(.+)", 1, "verisign"),
            new(@"Registrant FAX:\s*(.+)", 1, "generic"),
            new(@"Registrant Fax Ext:\s*(.+)", 1, "generic"),
            new(@"Registrant FAX Ext\.:\s*(.+)", 1, "generic"),
            new(@"Registrant Facsimile Number:\s*(.+)", 1, "generic"),
            new(@"owner-fax:\s*(.+)", 1, "shared3"),
            new(@"Fax:\s*(.+)", 1, "generic"),
            new(@"fax-no:\s*(.+)", 1, "generic"),
            new(@"FAX:\s*(.+)", 1, "generic"),
            new(@"Fax Number:\s*(.+)", 1, "generic"),
            new(@"\[FAX番号\]\s*(.+)", 1, "jprs"),
            new(@"registrant_contact_fax:\s*(.+)", 1, "srs_nz"),
        ],

        // Admin Contact
        ["admin_id"] =
        [
            new(@"Admin ID:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact ID:\s*(.+)", 1, "generic"),
            new(@"admin-c:\s*(.+)", 1, "nic_fr"),
        ],
        ["admin_name"] =
        [
            new(@"Admin Name:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Name:\s*(.+)", 1, "generic"),
            new(@"Admin Contact Name:\s*(.+)", 1, "generic"),
            new(@"Admin:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact:\s*(.+)", 1, "generic"),
            new(@"\[Administrative Contact\]\s*(.+)", 1, "jprs"),
            new(@"admin-c:\s*(.+)", 1, "generic"),
            new(@"Administrative Name:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact\(AC\):\s*(.+)", 1, "generic"),
            new(@"책임자:\s*(.+)", 1, "kr"),
            new(@"admin_contact_name:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_org"] =
        [
            new(@"Admin Organization:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Organization:\s*(.+)", 1, "generic"),
            new(@"Admin Organisation:\s*(.+)", 1, "generic"),
            new(@"Administrative Organization:\s*(.+)", 1, "generic"),
        ],
        ["admin_email"] =
        [
            new(@"Admin Email:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Email:\s*(.+)", 1, "generic"),
            new(@"Admin E-mail:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact Email:\s*(.+)", 1, "generic"),
            new(@"AC E-Mail:\s*(.+)", 1, "generic"),
            new(@"Administrative Email:\s*(.+)", 1, "generic"),
            new(@"Administrative E-mail:\s*(.+)", 1, "generic"),
            new(@"책임자 전자우편:\s*(.+)", 1, "kr"),
            new(@"admin_contact_email:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_phone"] =
        [
            new(@"Admin Phone:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Phone:\s*(.+)", 1, "generic"),
            new(@"Admin Telephone:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact Phone Number:\s*(.+)", 1, "generic"),
            new(@"AC Phone Number:\s*(.+)", 1, "generic"),
            new(@"Administrative Phone:\s*(.+)", 1, "generic"),
            new(@"책임자 전화번호:\s*(.+)", 1, "kr"),
            new(@"admin_contact_phone:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_street"] =
        [
            new(@"Admin Street:\s*(.+)", 1, "verisign"),
            new(@"Admin Street1:\s*(.+)", 1, "generic"),
            new(@"Admin Street2:\s*(.+)", 1, "generic"),
            new(@"Admin Address:\s*(.+)", 1, "generic"),
            new(@"Admin Address1:\s*(.+)", 1, "generic"),
            new(@"Admin Address2:\s*(.+)", 1, "generic"),
            new(@"Admin Address3:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact Address1:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact Address2:\s*(.+)", 1, "generic"),
            new(@"Administrative Address:\s*(.+)", 1, "generic"),
            new(@"admin_contact_address1:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_city"] =
        [
            new(@"Admin City:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact City:\s*(.+)", 1, "generic"),
            new(@"Administrative City:\s*(.+)", 1, "generic"),
            new(@"admin_contact_city:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_state"] =
        [
            new(@"Admin State/Province:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact State/Province:\s*(.+)", 1, "generic"),
            new(@"Administrative State/Province:\s*(.+)", 1, "generic"),
            new(@"admin_contact_province:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_postal"] =
        [
            new(@"Admin Postal Code:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Postal Code:\s*(.+)", 1, "generic"),
            new(@"Administrative Postal Code:\s*(.+)", 1, "generic"),
            new(@"admin_contact_postalcode:\s*(.+)", 1, "srs_nz"),
        ],
        ["admin_country"] =
        [
            new(@"Admin Country:\s*(.+)", 1, "verisign"),
            new(@"Administrative Contact Country:\s*(.+)", 1, "generic"),
            new(@"Administrative Contact Country Code:\s*(.+)", 1, "generic"),
            new(@"Administrative Country/Economy:\s*(.+)", 1, "generic"),
            new(@"admin_contact_country:\s*(.+)", 1, "srs_nz"),
        ],

        // Tech Contact
        ["tech_id"] =
        [
            new(@"Tech ID:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact ID:\s*(.+)", 1, "generic"),
            new(@"Tech Contact ID:\s*(.+)", 1, "generic"),
            new(@"Technical ID:\s*(.+)", 1, "generic"),
            new(@"tech-c:\s*(.+)", 1, "nic_fr"),
        ],
        ["tech_name"] =
        [
            new(@"Tech Name:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Name:\s*(.+)", 1, "generic"),
            new(@"Tech Contact Name:\s*(.+)", 1, "generic"),
            new(@"Technical:\s*(.+)", 1, "generic"),
            new(@"Technical Contact:\s*(.+)", 1, "generic"),
            new(@"\[Technical Contact\]\s*(.+)", 1, "jprs"),
            new(@"tech-c:\s*(.+)", 1, "generic"),
            new(@"Technical Name:\s*(.+)", 1, "generic"),
            new(@"technical_contact_name:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_org"] =
        [
            new(@"Tech Organization:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Organization:\s*(.+)", 1, "generic"),
            new(@"Tech Organisation:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Organization:\s*(.+)", 1, "generic"),
            new(@"Responsável Técnico:\s*(.+)", 1, "br"),
            new(@"Technical Organization:\s*(.+)", 1, "generic"),
        ],
        ["tech_email"] =
        [
            new(@"Tech Email:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Email:\s*(.+)", 1, "generic"),
            new(@"Tech E-mail:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Email:\s*(.+)", 1, "generic"),
            new(@"Tech Contact Email:\s*(.+)", 1, "generic"),
            new(@"Technical E-mail:\s*(.+)", 1, "generic"),
            new(@"technical_contact_email:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_phone"] =
        [
            new(@"Tech Phone:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Phone:\s*(.+)", 1, "generic"),
            new(@"Tech Telephone:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Phone Number:\s*(.+)", 1, "generic"),
            new(@"Technical Phone:\s*(.+)", 1, "generic"),
            new(@"technical_contact_phone:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_street"] =
        [
            new(@"Tech Street:\s*(.+)", 1, "verisign"),
            new(@"Tech Street1:\s*(.+)", 1, "generic"),
            new(@"Tech Street2:\s*(.+)", 1, "generic"),
            new(@"Tech Address:\s*(.+)", 1, "generic"),
            new(@"Tech Address1:\s*(.+)", 1, "generic"),
            new(@"Tech Address2:\s*(.+)", 1, "generic"),
            new(@"Tech Address3:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Address1:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Address2:\s*(.+)", 1, "generic"),
            new(@"Technical Address:\s*(.+)", 1, "generic"),
            new(@"technical_contact_address1:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_city"] =
        [
            new(@"Tech City:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact City:\s*(.+)", 1, "generic"),
            new(@"Technical City:\s*(.+)", 1, "generic"),
            new(@"technical_contact_city:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_state"] =
        [
            new(@"Tech State/Province:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact State/Province:\s*(.+)", 1, "generic"),
            new(@"Technical State/Province:\s*(.+)", 1, "generic"),
            new(@"technical_contact_province:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_postal"] =
        [
            new(@"Tech Postal Code:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Postal Code:\s*(.+)", 1, "generic"),
            new(@"Technical Postal Code:\s*(.+)", 1, "generic"),
            new(@"technical_contact_postalcode:\s*(.+)", 1, "srs_nz"),
        ],
        ["tech_country"] =
        [
            new(@"Tech Country:\s*(.+)", 1, "verisign"),
            new(@"Technical Contact Country:\s*(.+)", 1, "generic"),
            new(@"Technical Contact Country Code:\s*(.+)", 1, "generic"),
            new(@"Technical Country/Economy:\s*(.+)", 1, "generic"),
            new(@"technical_contact_country:\s*(.+)", 1, "srs_nz"),
        ],

        // Billing Contact
        ["billing_id"] =
        [
            new(@"Billing ID:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact ID:\s*(.+)", 1, "generic"),
        ],
        ["billing_name"] =
        [
            new(@"Billing Name:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact:\s*(.+)", 1, "generic"),
        ],
        ["billing_org"] =
        [
            new(@"Billing Organization:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact Organization:\s*(.+)", 1, "generic"),
            new(@"Entidade Gestora:\s*(.+)", 1, "pt"),
            new(@"Billing Organization:\s*(.+)", 1, "generic"),
        ],
        ["billing_email"] =
        [
            new(@"Billing Email:\s*(.+)", 1, "verisign"),
            new(@"Billing E-mail:\s*(.+)", 1, "generic"),
            new(@"Billing Contact Email:\s*(.+)", 1, "generic"),
        ],
        ["billing_phone"] =
        [
            new(@"Billing Phone:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact Phone Number:\s*(.+)", 1, "generic"),
            new(@"Billing Phone:\s*(.+)", 1, "generic"),
        ],
        ["billing_street"] =
        [
            new(@"Billing Street:\s*(.+)", 1, "verisign"),
            new(@"Billing Street1:\s*(.+)", 1, "generic"),
            new(@"Billing Street2:\s*(.+)", 1, "generic"),
            new(@"Billing Address:\s*(.+)", 1, "generic"),
            new(@"Billing Address1:\s*(.+)", 1, "generic"),
            new(@"Billing Address2:\s*(.+)", 1, "generic"),
            new(@"Billing Address3:\s*(.+)", 1, "generic"),
            new(@"Billing Contact Address1:\s*(.+)", 1, "generic"),
            new(@"Billing Contact Address2:\s*(.+)", 1, "generic"),
            new(@"Billing Address:\s*(.+)", 1, "generic"),
        ],
        ["billing_city"] =
        [
            new(@"Billing City:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact City:\s*(.+)", 1, "generic"),
            new(@"Billing City:\s*(.+)", 1, "generic"),
        ],
        ["billing_state"] =
        [
            new(@"Billing State/Province:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact State/Province:\s*(.+)", 1, "generic"),
            new(@"Billing State/Province:\s*(.+)", 1, "generic"),
        ],
        ["billing_postal"] =
        [
            new(@"Billing Postal Code:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact Postal Code:\s*(.+)", 1, "generic"),
            new(@"Billing Postal Code:\s*(.+)", 1, "generic"),
        ],
        ["billing_country"] =
        [
            new(@"Billing Country:\s*(.+)", 1, "verisign"),
            new(@"Billing Contact Country:\s*(.+)", 1, "generic"),
            new(@"Billing Contact Country Code:\s*(.+)", 1, "generic"),
            new(@"Billing Country/Economy:\s*(.+)", 1, "generic"),
        ],

        // DNSSEC
        ["dnssec"] =
        [
            new(@"DNSSEC:\s*(.+)", 1, "verisign"),
            new(@"dnssec:\s*(.+)", 1, "generic"),
            new(@"\[Signing Key\]\s*(.+)", 1, "jprs"),
        ],

        // Trademark
        ["trademark_name"] =
        [
            new(@"Trademark Name:\s*(.+)", 1, "generic"),
        ],
        ["trademark_date"] =
        [
            new(@"Trademark Date:\s*(.+)", 1, "generic"),
        ],
        ["trademark_country"] =
        [
            new(@"Trademark Country:\s*(.+)", 1, "generic"),
        ],
        ["trademark_number"] =
        [
            new(@"Trademark Number:\s*(.+)", 1, "generic"),
        ],

        // Remarks
        ["remarks"] =
        [
            new(@"Remarks:\s*(.+)", 1, "generic"),
            new(@"remarks:\s*(.+)", 1, "generic"),
        ],

        // French NIC format (nic-hdl)
        ["nic_hdl"] =
        [
            new(@"nic-hdl:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_contact"] =
        [
            new(@"contact:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_address"] =
        [
            new(@"address:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_country"] =
        [
            new(@"country:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_phone"] =
        [
            new(@"phone:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_fax"] =
        [
            new(@"fax-no:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_email"] =
        [
            new(@"e-mail:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_changed"] =
        [
            new(@"changed:\s*(.+)", 1, "nic_fr"),
        ],
        ["nic_type"] =
        [
            new(@"type:\s*(.+)", 1, "nic_fr"),
        ],
    };

    private static readonly string[] DateFormats =
    [
        "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:sszzz", "yyyy-MM-ddTHH:mm:ss+0000",
        "yyyy-MM-ddTHH:mm:ss.fZ", "yyyy-MM-ddTHH:mm:ss.ffZ", "yyyy-MM-ddTHH:mm:ss.fffZ",
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ssZ", "yyyy-MM-dd HH:mm:sszzz",
        "yyyy-MM-dd", "dd-MMM-yyyy", "dd-MMM-yyyy HH:mm:ss", "dd.MM.yyyy", "MM/dd/yyyy",
        "yyyyMMdd", "ddd MMM d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy",
        "yyyy. MM. dd.", "yyyy/MM/dd", "yyyy.MM.dd", "dd/MM/yyyy",
        "MMMM d yyyy", "MMMM  d yyyy",
        // French date formats
        "dd/MM/yyyy HH:mm:ss", "dd/MM/yyyy"
    ];

    public WhoisResponse Parse(string rawResponse, string? server = null)
    {
        var response = new WhoisResponse
        {
            RawResponse = rawResponse,
            WhoisServer = server ?? string.Empty,
            IsSuccessful = false
        };

        if (string.IsNullOrWhiteSpace(rawResponse))
        {
            return response;
        }

        try
        {
            var fields = ExtractFields(rawResponse);

            if (fields.Count == 0)
            {
                return response;
            }

            response.IsSuccessful = true;
            response.Domain = GetFieldValue(fields, "domain").ToLowerInvariant();
            response.Dates = ParseDates(fields);
            response.NameServers = GetFieldValues(fields, "nameserver")
                .Select(n => n.ToLowerInvariant().Trim())
                .Where(n => !string.IsNullOrEmpty(n))
                .ToList();
            response.Statuses = ParseStatuses(GetFieldValues(fields, "status"));
            response.Contacts = ParseContacts(fields);
            response.Dnssec = ParseDnssec(fields);
            response.Registrar = ParseRegistrar(fields);
            response.Registry = new RegistryInfo
            {
                Tld = ExtractTld(response.Domain)
            };

            if (string.IsNullOrEmpty(response.Domain))
            {
                response.Domain = response.Query;
            }
        }
        catch (Exception ex)
        {
            response.IsSuccessful = false;
            response.ErrorMessage = $"Parse error: {ex.Message}";
        }

        return response;
    }

    public ParseResult ParseWithDetails(string rawResponse, string? server = null)
    {
        var response = Parse(rawResponse, server);
        var matchedFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var fields = ExtractFields(rawResponse);
            foreach (var field in fields)
            {
                if (field.Value.Count > 0)
                    matchedFields[field.Key] = field.Value[0];
            }
        }
        catch { }

        return new ParseResult
        {
            Response = response,
            MatchedFields = matchedFields,
            ParserName = "RegexParser"
        };
    }

    private static Dictionary<string, List<string>> ExtractFields(string rawResponse)
    {
        var processed = PreprocessWhois(rawResponse);
        var fields = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var lines = processed.Split('\n');

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('%') || trimmed.StartsWith('#'))
                continue;

            foreach (var (key, patterns) in FieldPatterns)
            {
                foreach (var pattern in patterns)
                {
                    var match = Regex.Match(trimmed, pattern.Pattern, RegexOptions.IgnoreCase);
                    if (match.Success && match.Groups.Count > 1)
                    {
                        var value = match.Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(value))
                        {
                            if (!fields.ContainsKey(key))
                                fields[key] = [];
                            fields[key].Add(value);
                        }
                        break;
                    }
                }
            }
        }

        return fields;
    }

    /// <summary>
    /// Preprocess WHOIS response to handle section-based formats (.uk, etc.)
    /// Merges multi-line fields and removes empty lines.
    /// </summary>
    private static string PreprocessWhois(string raw)
    {
        var lines = raw.Split('\n');
        var result = new List<string>();
        int i = 0;

        while (i < lines.Length)
        {
            var line = lines[i];
            var trimmed = line.Trim();

            if (string.IsNullOrEmpty(trimmed)) { i++; continue; }

            // Check if line is a field label ending with ':' (no value after it)
            if (trimmed.EndsWith(':') && trimmed.Length > 1)
            {
                var nextLine = i + 1 < lines.Length ? lines[i + 1] : null;
                if (nextLine != null)
                {
                    var nextTrimmed = nextLine.Trim();
                    var nextIndent = nextLine.Length - nextLine.TrimStart().Length;
                    var curIndent = line.Length - line.TrimStart().Length;

                    if (!string.IsNullOrEmpty(nextTrimmed) && nextIndent > curIndent)
                    {
                        // If next line is also a label, this is a section header - skip it
                        if (nextTrimmed.EndsWith(':') && nextTrimmed.Length > 1)
                        {
                            i++;
                            continue;
                        }

                        // Merge: "Key: Value"
                        var key = trimmed[..^1].Trim();
                        result.Add($"{key}: {nextTrimmed}");
                        i += 2;

                        // Handle continuation lines
                        while (i < lines.Length)
                        {
                            var contLine = lines[i];
                            var contTrimmed = contLine.Trim();
                            var contIndent = contLine.Length - contLine.TrimStart().Length;
                            if (string.IsNullOrEmpty(contTrimmed) || contIndent <= curIndent) break;
                            if (contTrimmed.Contains(':') && contTrimmed.Split(':')[0].Trim().Length > 1) break;
                            if (!string.IsNullOrEmpty(contTrimmed)) result.Add($"{key}: {contTrimmed}");
                            i++;
                        }
                        continue;
                    }
                }
            }

            result.Add(trimmed);
            i++;
        }

        return string.Join('\n', result);
    }

    private static string GetFieldValue(Dictionary<string, List<string>> fields, string key)
    {
        return fields.TryGetValue(key, out var values) && values.Count > 0 ? values[0] : string.Empty;
    }

    private static List<string> GetFieldValues(Dictionary<string, List<string>> fields, string key)
    {
        return fields.TryGetValue(key, out var values) ? values : [];
    }

    private DomainDates ParseDates(Dictionary<string, List<string>> fields)
    {
        return new DomainDates
        {
            Created = ParseDate(GetFieldValue(fields, "created")),
            Updated = ParseDate(GetFieldValue(fields, "updated")),
            Expires = ParseDate(GetFieldValue(fields, "expires"))
        };
    }

    private static DateTime? ParseDate(string? dateStr)
    {
        if (string.IsNullOrWhiteSpace(dateStr)) return null;

        dateStr = dateStr.Split('(')[0].Trim();
        dateStr = Regex.Replace(dateStr, @"\s*(JST|UTC|GMT|KST)\s*$", "", RegexOptions.IgnoreCase).Trim();

        foreach (var format in DateFormats)
        {
            if (DateTime.TryParseExact(dateStr, format, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var date))
                return date;
        }

        return DateTime.TryParse(dateStr, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var parsed) ? parsed : null;
    }

    private static List<string> ParseStatuses(List<string> statusValues)
    {
        return statusValues
            .SelectMany(s => s.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
            .Select(s => s.Trim().ToLowerInvariant())
            .Where(s => !string.IsNullOrEmpty(s) && !s.StartsWith("http") && !s.StartsWith("("))
            .Distinct()
            .ToList();
    }

    private ContactCollection ParseContacts(Dictionary<string, List<string>> fields)
    {
        // Try French NIC format first
        var frenchContact = ParseFrenchNicContact(fields);
        if (frenchContact != null)
        {
            return frenchContact;
        }

        return new ContactCollection
        {
            Registrant = ParseContact(fields, "registrant"),
            Admin = ParseContact(fields, "admin"),
            Tech = ParseContact(fields, "tech"),
            Billing = ParseContact(fields, "billing")
        };
    }

    /// <summary>
    /// Parse French NIC format contacts (holder-c, admin-c, tech-c with nic-hdl)
    /// </summary>
    private ContactCollection? ParseFrenchNicContact(Dictionary<string, List<string>> fields)
    {
        var holderC = GetFieldValue(fields, "registrant_id"); // holder-c
        var adminC = GetFieldValue(fields, "admin_id"); // admin-c
        var techC = GetFieldValue(fields, "tech_id"); // tech-c

        // If no French format IDs found, return null
        if (string.IsNullOrEmpty(holderC) && string.IsNullOrEmpty(adminC) && string.IsNullOrEmpty(techC))
            return null;

        var contacts = new ContactCollection();

        // For French format, we need to parse nic-hdl blocks
        // But since ExtractFields doesn't handle multi-line blocks well,
        // we'll use the nic_* fields directly
        var contactType = GetFieldValue(fields, "nic_type");
        var contactName = GetFieldValue(fields, "nic_contact");
        var contactAddress = GetFieldValue(fields, "nic_address");
        var contactCountry = GetFieldValue(fields, "nic_country");
        var contactPhone = GetFieldValue(fields, "nic_phone");
        var contactFax = GetFieldValue(fields, "nic_fax");
        var contactEmail = GetFieldValue(fields, "nic_email");

        // Build contact info from nic_* fields
        var contactInfo = new ContactInfo
        {
            Name = contactName ?? string.Empty,
            Street = contactAddress ?? string.Empty,
            Country = contactCountry ?? string.Empty,
            Phone = contactPhone ?? string.Empty,
            Email = contactEmail ?? string.Empty
        };

        // Determine contact type
        if (!string.IsNullOrEmpty(contactType))
        {
            if (contactType.Equals("ORGANIZATION", StringComparison.OrdinalIgnoreCase))
            {
                contactInfo.Organization = contactName ?? string.Empty;
                contactInfo.Name = string.Empty;
            }
        }

        // Assign to appropriate contact type based on holder-c/admin-c/tech-c
        if (!string.IsNullOrEmpty(holderC))
            contacts.Registrant = contactInfo;
        if (!string.IsNullOrEmpty(adminC))
            contacts.Admin = contactInfo;
        if (!string.IsNullOrEmpty(techC))
            contacts.Tech = contactInfo;

        return contacts;
    }

    private static ContactInfo ParseContact(Dictionary<string, List<string>> fields, string prefix)
    {
        return new ContactInfo
        {
            Name = GetFieldValue(fields, $"{prefix}_name"),
            Organization = GetFieldValue(fields, $"{prefix}_org"),
            Email = GetFieldValue(fields, $"{prefix}_email"),
            Street = GetFieldValue(fields, $"{prefix}_street"),
            City = GetFieldValue(fields, $"{prefix}_city"),
            State = GetFieldValue(fields, $"{prefix}_state"),
            PostalCode = GetFieldValue(fields, $"{prefix}_postal"),
            Country = GetFieldValue(fields, $"{prefix}_country"),
            Phone = GetFieldValue(fields, $"{prefix}_phone")
        };
    }

    private static DnssecInfo? ParseDnssec(Dictionary<string, List<string>> fields)
    {
        var dnssecValue = GetFieldValue(fields, "dnssec");
        if (string.IsNullOrEmpty(dnssecValue))
            return null;

        var signed = !dnssecValue.Contains("unsigned", StringComparison.OrdinalIgnoreCase) &&
                     !dnssecValue.Equals("no", StringComparison.OrdinalIgnoreCase);

        return new DnssecInfo
        {
            Signed = signed,
            DelegationSigned = signed
        };
    }

    private static RegistrarInfo ParseRegistrar(Dictionary<string, List<string>> fields)
    {
        var name = GetFieldValue(fields, "registrar_name");

        // Clean registrar name - remove URL in parentheses
        if (!string.IsNullOrEmpty(name))
        {
            var parenIndex = name.IndexOf('(');
            if (parenIndex > 0)
                name = name[..parenIndex].Trim();
        }

        return new RegistrarInfo
        {
            Name = name,
            IanaId = GetFieldValue(fields, "registrar_iana_id"),
            Website = GetFieldValue(fields, "registrar_url"),
            WhoisServer = GetFieldValue(fields, "registrar_whois"),
            AbuseContactEmail = GetFieldValue(fields, "registrar_abuse_email"),
            AbuseContactPhone = GetFieldValue(fields, "registrar_abuse_phone")
        };
    }

    private static string ExtractTld(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return string.Empty;
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }

    private record FieldPattern(string Pattern, int GroupIndex, string Server);
}

public class ParseResult
{
    public WhoisResponse Response { get; set; } = new();
    public Dictionary<string, string> MatchedFields { get; set; } = new();
    public string ParserName { get; set; } = string.Empty;
}
