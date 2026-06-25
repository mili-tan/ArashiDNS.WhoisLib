using System.Globalization;
using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Detection;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.Formatting;

public class TraditionalFormatter : IWhoisFormatter
{
    private readonly PrivacyDetector _privacyDetector;
    private readonly RegistryIdentifier _registryIdentifier;

    private static readonly string[] DateFormats =
    [
        "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:sszzz", "yyyy-MM-ddTHH:mm:ss+0000",
        "yyyy-MM-ddTHH:mm:ss.fZ", "yyyy-MM-ddTHH:mm:ss.ffZ", "yyyy-MM-ddTHH:mm:ss.fffZ",
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ssZ", "yyyy-MM-dd HH:mm:sszzz",
        "yyyy-MM-dd", "dd-MMM-yyyy", "dd-MMM-yyyy HH:mm:ss", "dd.MM.yyyy", "MM/dd/yyyy",
        "yyyyMMdd", "ddd MMM d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy",
        "yyyy. MM. dd.", "yyyy/MM/dd", "yyyy.MM.dd", "dd/MM/yyyy",
        "MMMM d yyyy", "MMMM  d yyyy",
        "ddd MMM dd HH:mm:ss yyyy", "ddd MMM d HH:mm:ss yyyy"
    ];

    private static readonly Dictionary<string, string[]> DomainFieldMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        // Domain
        ["domain"] = ["Domain Name:", "Domain name:", "domain name:", "domain:", "[Domain Name]", "Domain ", "Complete Domain Name:", "Nome de domínio / Domain Name:"],
        ["registry_domain_id"] = ["Registry Domain ID:", "Domain ID:", "ROID:", "Registry ID:"],
        ["registrar_name"] = ["Registrar:", "Sponsoring Registrar:", "Registrar Name:", "Authorized Agency:", "Sponsoring Registrar Organization:", "Last Updated by Registrar:", "Registrar ID:", "등록대행자:"],
        ["registrar_iana_id"] = ["Registrar IANA ID:", "Registrar ID:", "Sponsoring Registrar IANA ID:"],
        ["registrar_url"] = ["Registrar URL:", "Registrar Website:", "URL:", "Sponsoring Registrar URL:", "Sponsoring Registrar Website:", "Referral URL:", "Registrar URL (registration services):", "Registration URL:"],
        ["registrar_whois"] = ["Registrar WHOIS Server:", "Whois Server:", "WHOIS Server:", "Sponsoring Registrar WHOIS Server:"],
        ["registrar_abuse_email"] = ["Registrar Abuse Contact Email:", "Sponsoring Registrar Customer Service Email:"],
        ["registrar_abuse_phone"] = ["Registrar Abuse Contact Phone:", "Sponsoring Registrar Phone:", "Sponsoring Registrar Customer Service Contact:", "Registrar Contact Information:"],
        ["created"] = ["Creation Date:", "Created:", "Created Date:", "Created On:", "Domain Create Date:", "Registration Date:", "Registered on:", "Registered Date:", "Registration Time:", "Record created:", "Record Created:", "created:", "registered:", "Domain Registration Date:", "Domain record activated:", "Domain Name Commencement Date:", "[Registered Date]:", "[Created on]:", "Data de registo / Creation Date:", "Record created on:", "[登録年月日]", "등록일:"],
        ["updated"] = ["Updated Date:", "Modified:", "Last Modified:", "Last Updated:", "Last Updated On:", "Domain Last Updated Date:", "Last Updated Date:", "Record last updated on:", "Record last updated:", "Last Update:", "last-update:", "changed:", "[Last Update]:", "[Last Updated]:", "modified:", "Domain record last updated:", "Record changed on:", "[最終更新]", "최근 정보 변경일:"],
        ["expires"] = ["Registry Expiry Date:", "Expiration Date:", "Expires:", "Expiry Date:", "Expiry date:", "Expiry:", "expire:", "Registrar Registration Expiration Date:", "Domain Expiration Date:", "Expiration Time:", "Record expires on:", "Record expires:", "Expiration:", "expires:", "Domain expires:", "[Expires on]:", "[有効期限]", "Data de expiração / Expiration Date:", "Expired:", "사용 종료일:"],
        ["status"] = ["Domain Status:", "Status:", "Registration status:", "Domain status:", "status:", "[State]:", "[Status]:", "state:", "Estado / Status:", "Re-registration Status:", "[状態]", "[ロック状態]", "등록정보 보호:"],
        ["nameserver"] = ["Name Server:", "Nameserver:", "nserver:", "Name servers:", "Name Servers:", "Name servers in the listed order:", "Nameservers:", "Nserver:", "DNS:", "Host Name:", "[Name Server]", "Domain nameservers:", "Domain servers:", "Domain servers in listed order:", "Nameserver Information:", "Primary Server Hostname:", "Secondary Server Hostname:"],

        // Registrant
        ["registrant_id"] = ["Registrant ID:", "Registrant Contact ID:"],
        ["registrant_name"] = ["Registrant Name:", "Registrant Contact Name:", "Registrant:", "Name:", "person:", "contact:", "[Registrant]:", "[Registrant]", "Titular / Registrant:", "holder:", "holder-c:", "Organization Using Domain Name:", "Nombre:", "[登録者名]", "[名前]", "[Name]", "등록인:"],
        ["registrant_org"] = ["Registrant Organization:", "Registrant Contact Organization:", "Organization:", "Org Name:", "Organisation:", "descr:", "role:", "Organization Name:", "Company English Name:", "org:"],
        ["registrant_email"] = ["Registrant Email:", "Registrant Contact Email:", "Registrant Email Address:", "Registrant E-mail:", "AC E-Mail:", "Email:", "E-mail:", "e-mail:", "Registrant Contact Email:", "E-Mailbox:", "Email Address:", "[Email]"],
        ["registrant_street"] = ["Registrant Street:", "Registrant Street1:", "Registrant Street2:", "Registrant Address:", "Registrant Address1:", "Registrant Address2:", "Registrant Address3:", "Registrant Contact Street:", "Address:", "Street:", "address:", "Registrant's address:", "Registrant Address:", "street address:", "[住所]", "[Postal Address]", "등록인 주소:"],
        ["registrant_city"] = ["Registrant City:", "Registrant Contact City:", "City:", "city:"],
        ["registrant_state"] = ["Registrant State/Province:", "Registrant Contact State/Province:", "StateProv:", "State:", "Province:"],
        ["registrant_postal"] = ["Registrant Postal Code:", "Registrant Contact Postal Code:", "Registrant Zip:", "PostalCode:", "Zip:", "Postal Code:", "Registrant Zip Code:", "postal code:", "[郵便番号]", "Registrant Zip Code:", "등록인 우편번호:"],
        ["registrant_country"] = ["Registrant Country:", "Registrant Contact Country:", "Country:", "Country Code:", "country:", "Registrant Country/Economy:"],
        ["registrant_phone"] = ["Registrant Phone:", "Registrant Contact Phone:", "Phone:", "phone:", "Telephone:", "Registrant Phone Number:", "TEL:", "Phone Number:", "[電話番号]"],
        ["registrant_phone_ext"] = ["Registrant Phone Ext:", "Registrant Phone Ext.:"],
        ["registrant_fax"] = ["Registrant Fax:", "Registrant FAX:", "Registrant Fax Ext:", "Registrant FAX Ext.:", "Registrant Facsimile Number:", "Fax:", "fax-no:", "FAX:", "Fax Number:", "[FAX番号]"],
        ["admin_id"] = ["Admin ID:", "Administrative Contact ID:"],
        ["admin_name"] = ["Admin Name:", "Administrative Contact Name:", "Admin Contact Name:", "Admin:", "Administrative Contact:", "[Administrative Contact]", "admin-c:", "Administrative Name", "Administrative Contact(AC):", "책임자:"],
        ["admin_org"] = ["Admin Organization:", "Administrative Contact Organization:", "Admin Organisation:", "Administrative Organization:"],
        ["admin_email"] = ["Admin Email:", "Administrative Contact Email:", "Admin E-mail:", "Administrative Contact Email:", "AC E-Mail:", "Administrative Email:", "Administrative E-mail:", "책임자 전자우편:"],
        ["admin_phone"] = ["Admin Phone:", "Administrative Contact Phone:", "Admin Telephone:", "Administrative Contact Phone Number:", "AC Phone Number:", "Administrative Phone:", "책임자 전화번호:"],
        ["admin_phone_ext"] = ["Admin Phone Ext:", "Administrative Phone Ext.:"],
        ["admin_fax"] = ["Admin Fax:", "Admin FAX:", "Admin Fax Ext:", "Admin FAX Ext.:", "Administrative Contact Facsimile Number:", "Administrative FAX:", "Administrative FAX Ext.:"],
        ["admin_street"] = ["Admin Street:", "Admin Street1:", "Admin Street2:", "Admin Address:", "Admin Address1:", "Admin Address2:", "Admin Address3:", "Administrative Contact Address1:", "Administrative Contact Address2:", "Administrative Address:", "Administrative Address2:", "Administrative Address3:"],
        ["admin_city"] = ["Admin City:", "Administrative Contact City:", "Administrative City:"],
        ["admin_state"] = ["Admin State/Province:", "Administrative Contact State/Province:", "Administrative State/Province:"],
        ["admin_postal"] = ["Admin Postal Code:", "Administrative Contact Postal Code:", "Administrative Postal Code:"],
        ["admin_country"] = ["Admin Country:", "Administrative Contact Country:", "Administrative Contact Country Code:", "Administrative Country/Economy:"],
        ["tech_id"] = ["Tech ID:", "Technical Contact ID:", "Tech Contact ID:", "Technical ID:"],
        ["tech_name"] = ["Tech Name:", "Technical Contact Name:", "Tech Contact Name:", "Technical:", "Technical Contact:", "[Technical Contact]", "tech-c:", "Technical Name:"],
        ["tech_org"] = ["Tech Organization:", "Technical Contact Organization:", "Tech Organisation:", "Technical Contact Organization:", "Responsável Técnico:", "Technical Organization:"],
        ["tech_email"] = ["Tech Email:", "Technical Contact Email:", "Tech E-mail:", "Technical Contact Email:", "Tech Contact Email:", "Technical E-mail:"],
        ["tech_phone"] = ["Tech Phone:", "Technical Contact Phone:", "Tech Telephone:", "Technical Contact Phone Number:", "Technical Phone:"],
        ["tech_phone_ext"] = ["Tech Phone Ext:", "Technical Phone Ext.:"],
        ["tech_fax"] = ["Tech Fax:", "Tech FAX:", "Tech Fax Ext:", "Tech FAX Ext.:", "Technical Contact Facsimile Number:", "Technical FAX:", "Technical FAX Ext.:"],
        ["tech_street"] = ["Tech Street:", "Tech Street1:", "Tech Street2:", "Tech Address:", "Tech Address1:", "Tech Address2:", "Tech Address3:", "Technical Contact Address1:", "Technical Contact Address2:", "Technical Address:", "Technical Address2:", "Technical Address3:"],
        ["tech_city"] = ["Tech City:", "Technical Contact City:", "Technical City:"],
        ["tech_state"] = ["Tech State/Province:", "Technical Contact State/Province:", "Technical State/Province:"],
        ["tech_postal"] = ["Tech Postal Code:", "Technical Contact Postal Code:", "Technical Postal Code:"],
        ["tech_country"] = ["Tech Country:", "Technical Contact Country:", "Technical Contact Country Code:", "Technical Country/Economy:"],
        ["billing_id"] = ["Billing ID:", "Billing Contact ID:"],
        ["billing_name"] = ["Billing Name:", "Billing Contact:"],
        ["billing_org"] = ["Billing Organization:", "Billing Contact Organization:", "Entidade Gestora:", "Billing Organization:"],
        ["billing_email"] = ["Billing Email:", "Billing E-mail:", "Billing Contact Email:", "Billing E-mail:"],
        ["billing_phone"] = ["Billing Phone:", "Billing Contact Phone Number:", "Billing Phone:"],
        ["billing_phone_ext"] = ["Billing Phone Ext:", "Billing Phone Ext.:"],
        ["billing_fax"] = ["Billing Fax:", "Billing FAX:", "Billing Fax Ext:", "Billing FAX Ext.:", "Billing Contact Facsimile Number:", "Billing FAX:", "Billing FAX Ext.:"],
        ["billing_street"] = ["Billing Street:", "Billing Street1:", "Billing Street2:", "Billing Address:", "Billing Address1:", "Billing Address2:", "Billing Address3:", "Billing Contact Address1:", "Billing Address2:", "Billing Address3:"],
        ["billing_city"] = ["Billing City:", "Billing Contact City:", "Billing City:"],
        ["billing_state"] = ["Billing State/Province:", "Billing Contact State/Province:", "Billing State/Province:"],
        ["billing_postal"] = ["Billing Postal Code:", "Billing Contact Postal Code:", "Billing Postal Code:"],
        ["billing_country"] = ["Billing Country:", "Billing Contact Country:", "Billing Contact Country Code:", "Billing Country/Economy:"],
        ["dnssec"] = ["DNSSEC:", "DNSSEC", "dnssec:", "[Signing Key]"],
        ["trademark_name"] = ["Trademark Name:"],
        ["trademark_date"] = ["Trademark Date:"],
        ["trademark_country"] = ["Trademark Country:"],
        ["trademark_number"] = ["Trademark Number:"],
        ["remarks"] = ["Remarks:", "remarks:"],
    };

    private static readonly Dictionary<string, string[]> IpFieldMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["network_range"] = ["NetRange:", "inetnum:", "IP Address:"],
        ["network_name"] = ["NetName:", "netname:"],
        ["organization"] = ["OrgName:", "org-name:", "org:", "descr:"],
        ["address"] = ["Address:", "address:"],
        ["city"] = ["City:"],
        ["state"] = ["StateProv:"],
        ["postal_code"] = ["PostalCode:"],
        ["country"] = ["Country:", "country:"],
        ["abuse_email"] = ["OrgAbuseEmail:", "abuse-mailbox:", "e-mail:"],
        ["abuse_phone"] = ["OrgAbusePhone:", "phone:"],
    };

    public TraditionalFormatter(RegistrarListProvider registrarProvider)
    {
        _privacyDetector = new PrivacyDetector();
        _registryIdentifier = new RegistryIdentifier(registrarProvider);
    }

    public async Task<FormattedResult> FormatAsync(WhoisResponse response)
    {
        if (response.QueryType is WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6)
            return await FormatIpResponseAsync(response);
        
        if (response.QueryType == WhoisQueryType.Asn)
            return await FormatIpResponseAsync(response);
        
        return await FormatDomainResponseAsync(response);
    }

    private async Task<FormattedResult> FormatDomainResponseAsync(WhoisResponse response)
    {
        try
        {
            if (string.IsNullOrEmpty(response.Domain) && !string.IsNullOrEmpty(response.RawResponse))
            {
                var fields = ExtractFields(response.RawResponse, DomainFieldMappings);
                var parsed = ParseDomainResponse(fields, response.RawResponse);
                
                // Handle section-based WHOIS formats (like .kg)
                if (string.IsNullOrEmpty(parsed.Domain) || 
                    (string.IsNullOrEmpty(parsed.Registrar?.Name) && parsed.Dates?.Expires == null))
                {
                    var sectionParsed = ParseSectionBasedWhois(response.RawResponse);
                    if (!string.IsNullOrEmpty(sectionParsed.Domain))
                        parsed.Domain = sectionParsed.Domain;
                    if (parsed.Dates?.Expires == null && sectionParsed.Dates?.Expires != null)
                        parsed.Dates = sectionParsed.Dates;
                    if (string.IsNullOrEmpty(parsed.Registrar?.Name) && sectionParsed.Registrar != null)
                        parsed.Registrar = sectionParsed.Registrar;
                    if (parsed.NameServers.Count == 0 && sectionParsed.NameServers.Count > 0)
                        parsed.NameServers = sectionParsed.NameServers;
                    if (parsed.Contacts?.Registrant == null && sectionParsed.Contacts?.Registrant != null)
                        parsed.Contacts = sectionParsed.Contacts;
                }
                
                response.Domain = parsed.Domain ?? response.Query;
                response.Dates = parsed.Dates;
                response.NameServers = parsed.NameServers ?? new List<string>();
                response.Statuses = parsed.Statuses ?? new List<string>();
                response.Contacts = parsed.Contacts ?? new ContactCollection();
                response.Registrar = parsed.Registrar;
                response.Registry = parsed.Registry;
            }
            else if (string.IsNullOrEmpty(response.Domain))
            {
                response.Domain = response.Query;
            }
        }
        catch
        {
            // If parsing fails, use query as domain
            if (string.IsNullOrEmpty(response.Domain))
                response.Domain = response.Query;
        }

        response.Privacy = _privacyDetector.Detect(response);
        response.Registry = await _registryIdentifier.IdentifyRegistryAsync(response);
        response.Registrar = await _registryIdentifier.IdentifyRegistrarAsync(response);

        return new FormattedResult
        {
            Domain = response.Domain ?? response.Query,
            Registry = response.Registry,
            Registrar = response.Registrar,
            Privacy = response.Privacy,
            Contacts = response.Contacts?.GetMergedContacts() ?? new List<ContactInfo>(),
            Dates = response.Dates,
            NameServers = response.NameServers ?? new List<string>(),
            Statuses = response.Statuses ?? new List<string>(),
            Dnssec = response.Dnssec
        };
    }

    private async Task<FormattedResult> FormatIpResponseAsync(WhoisResponse response)
    {
        if (string.IsNullOrEmpty(response.Domain))
        {
            var fields = ExtractFields(response.RawResponse, IpFieldMappings);
            response.Domain = GetFieldValue(fields, "network_range");
        }

        if (response.Registry == null || string.IsNullOrEmpty(response.Registry.Name))
        {
            var fields = ExtractFields(response.RawResponse, IpFieldMappings);
            response.Registry = new RegistryInfo
            {
                Name = GetFieldValue(fields, "organization"),
                WhoisServer = response.WhoisServer
            };
        }

        response.Privacy = _privacyDetector.Detect(response);

        return new FormattedResult
        {
            Domain = response.Domain,
            Registry = response.Registry,
            Privacy = response.Privacy,
            Contacts = response.Contacts?.GetMergedContacts() ?? [],
            NameServers = response.NameServers ?? [],
            Statuses = response.Statuses ?? []
        };
    }

    private WhoisResponse ParseDomainResponse(Dictionary<string, List<string>> fields, string rawResponse)
    {
        var response = new WhoisResponse { RawResponse = rawResponse };
        response.Domain = CleanFieldValue(GetFieldValue(fields, "domain"));
        response.Dates = ParseDates(fields);
        response.NameServers = CleanFieldValues(GetFieldValues(fields, "nameserver"));
        response.Statuses = ParseStatuses(GetFieldValues(fields, "status"));
        response.Contacts = ParseContacts(fields);
        response.Dnssec = ParseDnssec(fields);
        response.Registrar = new RegistrarInfo
        {
            Name = CleanFieldValue(GetFieldValue(fields, "registrar_name")),
            IanaId = CleanFieldValue(GetFieldValue(fields, "registrar_iana_id")),
            Website = CleanFieldValue(GetFieldValue(fields, "registrar_url")),
            WhoisServer = CleanFieldValue(GetFieldValue(fields, "registrar_whois"))
        };
        response.Registry = new RegistryInfo
        {
            Tld = ExtractTld(response.Domain),
            IanaId = CleanFieldValue(GetFieldValue(fields, "registry_domain_id"))
        };
        return response;
    }

    private static string CleanFieldValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        value = value.Trim();
        if (value.StartsWith('[') && value.EndsWith(']'))
            value = value[1..^1].Trim();
        return value;
    }

    private static List<string> CleanFieldValues(List<string> values)
    {
        return values.Select(CleanFieldValue).Where(v => !string.IsNullOrEmpty(v)).ToList();
    }

    private static Dictionary<string, List<string>> ExtractFields(string rawResponse, Dictionary<string, string[]> fieldMappings)
    {
        var fields = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var lines = rawResponse.Split('\n');

        var sortedMappings = fieldMappings
            .SelectMany(kvp => kvp.Value.Select(prefix => new { Key = kvp.Key, Prefix = prefix }))
            .Where(x => !string.IsNullOrEmpty(x.Prefix))
            .OrderByDescending(x => x.Prefix.Length)
            .ToList();

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('%') || trimmed.StartsWith('#'))
                continue;

            var wordCount = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
            if (wordCount > 10) continue;

            foreach (var mapping in sortedMappings)
            {
                var prefix = mapping.Prefix;
                
                // Handle [FieldName] bracket format (e.g., [Domain Name]   GOOGLE.JP)
                if (prefix.StartsWith('['))
                {
                    if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        var value = trimmed[prefix.Length..].Trim();
                        if (!string.IsNullOrEmpty(value))
                        {
                            if (!fields.ContainsKey(mapping.Key))
                                fields[mapping.Key] = [];
                            fields[mapping.Key].Add(value);
                        }
                        break;
                    }
                    continue;
                }

                // Handle normal prefix with optional spaces before colon
                // e.g., "Domain Name                 : google.kr" matches "Domain Name:"
                var prefixWithoutColon = prefix.EndsWith(':') ? prefix[..^1] : prefix;
                if (trimmed.StartsWith(prefixWithoutColon, StringComparison.OrdinalIgnoreCase))
                {
                    var afterPrefix = trimmed[prefixWithoutColon.Length..];
                    if (afterPrefix.Length > 0 && (afterPrefix[0] == ':' || (afterPrefix[0] == ' ' && afterPrefix.Contains(':'))))
                    {
                        var colonIdx = afterPrefix.IndexOf(':');
                        if (colonIdx >= 0)
                        {
                            var value = afterPrefix[(colonIdx + 1)..].Trim();
                            if (!string.IsNullOrEmpty(value))
                            {
                                if (!fields.ContainsKey(mapping.Key))
                                    fields[mapping.Key] = [];
                                fields[mapping.Key].Add(value);
                            }
                            break;
                        }
                    }
                }
            }
        }
        return fields;
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
            if (DateTime.TryParseExact(dateStr, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                return date;
        }

        var koreanFormat = Regex.Replace(dateStr, @"(\d{4})\.\s*(\d{2})\.\s*(\d{2})\.", "$1-$2-$3");
        if (DateTime.TryParse(koreanFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var koreanDate))
            return koreanDate;

        return DateTime.TryParse(dateStr, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) ? parsed : null;
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
        return new ContactCollection
        {
            Registrant = ParseContact(fields, "registrant"),
            Admin = ParseContact(fields, "admin"),
            Tech = ParseContact(fields, "tech"),
            Billing = ParseContact(fields, "billing")
        };
    }

    private static DnssecInfo? ParseDnssec(Dictionary<string, List<string>> fields)
    {
        var dnssecValue = CleanFieldValue(GetFieldValue(fields, "dnssec"));
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

    private static ContactInfo ParseContact(Dictionary<string, List<string>> fields, string prefix)
    {
        return new ContactInfo
        {
            Name = CleanFieldValue(GetFieldValue(fields, $"{prefix}_name")),
            Organization = CleanFieldValue(GetFieldValue(fields, $"{prefix}_org")),
            Email = CleanFieldValue(GetFieldValue(fields, $"{prefix}_email")),
            Street = CleanFieldValue(GetFieldValue(fields, $"{prefix}_street")),
            City = CleanFieldValue(GetFieldValue(fields, $"{prefix}_city")),
            State = CleanFieldValue(GetFieldValue(fields, $"{prefix}_state")),
            PostalCode = CleanFieldValue(GetFieldValue(fields, $"{prefix}_postal")),
            Country = CleanFieldValue(GetFieldValue(fields, $"{prefix}_country")),
            Phone = CleanFieldValue(GetFieldValue(fields, $"{prefix}_phone"))
        };
    }

    private static string ExtractTld(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return string.Empty;
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }

    /// <summary>
    /// Parse section-based WHOIS formats (like .kg, .cn, etc.)
    /// </summary>
    private static WhoisResponse ParseSectionBasedWhois(string rawResponse)
    {
        var response = new WhoisResponse { RawResponse = rawResponse };
        var lines = rawResponse.Split('\n');
        var contacts = new ContactCollection();
        ContactInfo? currentContact = null;
        var nameServers = new List<string>();
        var inNameserverSection = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('%') || trimmed.StartsWith('#'))
                continue;

            // Domain: "Domain AC.KG (ACTIVE)"
            if (trimmed.StartsWith("Domain ", StringComparison.OrdinalIgnoreCase) && !trimmed.Contains("Status"))
            {
                var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    response.Domain = parts[1].TrimEnd('.').ToLowerInvariant();
                    if (response.Domain.Contains('('))
                        response.Domain = response.Domain.Split('(')[0].Trim();
                }
            }

            // Contact sections
            if (trimmed.EndsWith("Contact:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.EndsWith("Contact", StringComparison.OrdinalIgnoreCase))
            {
                currentContact = new ContactInfo();
                if (trimmed.Contains("Admin", StringComparison.OrdinalIgnoreCase))
                    contacts.Admin = currentContact;
                else if (trimmed.Contains("Tech", StringComparison.OrdinalIgnoreCase))
                    contacts.Tech = currentContact;
                else if (trimmed.Contains("Bill", StringComparison.OrdinalIgnoreCase))
                    contacts.Billing = currentContact;
                else
                    contacts.Registrant = currentContact;
                continue;
            }

            // Contact fields
            if (currentContact != null)
            {
                if (trimmed.StartsWith("Name:", StringComparison.OrdinalIgnoreCase))
                    currentContact.Name = trimmed[5..].Trim();
                else if (trimmed.StartsWith("Address:", StringComparison.OrdinalIgnoreCase))
                    currentContact.Street = trimmed[8..].Trim();
                else if (trimmed.StartsWith("Email:", StringComparison.OrdinalIgnoreCase))
                    currentContact.Email = trimmed[6..].Trim();
                else if (trimmed.StartsWith("phone:", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("Phone:", StringComparison.OrdinalIgnoreCase))
                    currentContact.Phone = trimmed[6..].Trim();
            }

            // Dates
            if (trimmed.StartsWith("Record created:", StringComparison.OrdinalIgnoreCase))
            {
                var dateStr = trimmed[15..].Trim();
                if (DateTime.TryParse(dateStr, out var date))
                    response.Dates ??= new DomainDates();
                response.Dates!.Created = ParseKgDate(dateStr);
            }
            else if (trimmed.StartsWith("Record last updated", StringComparison.OrdinalIgnoreCase))
            {
                var dateStr = trimmed.Contains(":") ? trimmed[(trimmed.IndexOf(':') + 1)..].Trim() : trimmed;
                response.Dates ??= new DomainDates();
                response.Dates.Updated = ParseKgDate(dateStr);
            }
            else if (trimmed.StartsWith("Record expires", StringComparison.OrdinalIgnoreCase))
            {
                var dateStr = trimmed.Contains(":") ? trimmed[(trimmed.IndexOf(':') + 1)..].Trim() : trimmed;
                response.Dates ??= new DomainDates();
                response.Dates.Expires = ParseKgDate(dateStr);
            }

            // Nameservers
            if (trimmed.Contains("Name servers", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("Nameservers", StringComparison.OrdinalIgnoreCase))
            {
                inNameserverSection = true;
                continue;
            }

            if (inNameserverSection && !string.IsNullOrEmpty(trimmed))
            {
                if (trimmed.Contains(':') || trimmed.Contains(' '))
                {
                    // Skip non-NS lines
                    if (trimmed.StartsWith("NS", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.EndsWith(".COM", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.EndsWith(".NET", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.EndsWith(".ORG", StringComparison.OrdinalIgnoreCase))
                    {
                        nameServers.Add(trimmed.ToLowerInvariant());
                    }
                    else
                    {
                        inNameserverSection = false;
                    }
                }
            }
        }

        response.Contacts = contacts;
        response.NameServers = nameServers;
        return response;
    }

    private static DateTime? ParseKgDate(string dateStr)
    {
        if (string.IsNullOrWhiteSpace(dateStr))
            return null;

        // Format: "Wed Feb 10 17:56:46 2021" or "Tue Feb  9 17:56:46 2027"
        var formats = new[]
        {
            "ddd MMM d HH:mm:ss yyyy",
            "ddd MMM dd HH:mm:ss yyyy",
            "ddd MMM  d HH:mm:ss yyyy"
        };

        foreach (var format in formats)
        {
            if (DateTime.TryParseExact(dateStr.Trim(), format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                return date;
        }

        return DateTime.TryParse(dateStr, out var parsed) ? parsed : null;
    }
}
