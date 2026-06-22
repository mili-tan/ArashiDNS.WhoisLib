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
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd", "dd-MMM-yyyy", "dd.MM.yyyy", "MM/dd/yyyy",
        "yyyyMMdd", "ddd MMM d HH:mm:ss yyyy", "ddd MMM dd HH:mm:ss yyyy",
        "yyyy. MM. dd.", "yyyy/MM/dd", "yyyy.MM.dd"
    ];

    private static readonly Dictionary<string, string[]> DomainFieldMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["domain"] = ["Domain Name:", "Domain name:", "domain name:", "domain:", "[Domain Name]"],
        ["registrar_name"] = ["Registrar:", "Sponsoring Registrar:", "Registrar Name:", "Authorized Agency:"],
        ["registrar_iana_id"] = ["Registrar IANA ID:", "Registrar ID:"],
        ["registrar_url"] = ["Registrar URL:", "Registrar Website:", "URL:"],
        ["registrar_whois"] = ["Registrar WHOIS Server:", "Whois Server:"],
        ["created"] = ["Creation Date:", "Created:", "Created Date:", "Registration Date:", "Registered on:", "Registered Date:", "Registration Time:"],
        ["updated"] = ["Updated Date:", "Modified:", "Last Modified:", "Last Updated:", "Last Updated Date:"],
        ["expires"] = ["Registry Expiry Date:", "Expiration Date:", "Expires:", "Expiry Date:", "Registrar Registration Expiration Date:", "Expiration Time:"],
        ["status"] = ["Domain Status:", "Status:", "Registration status:"],
        ["nameserver"] = ["Name Server:", "Nameserver:", "nserver:", "Name servers:", "Name Servers:"],
        ["registrant_name"] = ["Registrant Name:", "Registrant Contact Name:", "Registrant:"],
        ["registrant_org"] = ["Registrant Organization:", "Registrant Contact Organization:", "Organization:", "Org Name:"],
        ["registrant_email"] = ["Registrant Email:", "Registrant Contact Email:", "Registrant Email Address:", "AC E-Mail:"],
        ["registrant_street"] = ["Registrant Street:", "Registrant Contact Street:", "Address:"],
        ["registrant_city"] = ["Registrant City:", "Registrant Contact City:", "City:"],
        ["registrant_state"] = ["Registrant State/Province:", "Registrant Contact State/Province:", "StateProv:"],
        ["registrant_postal"] = ["Registrant Postal Code:", "Registrant Contact Postal Code:", "Registrant Zip:", "PostalCode:"],
        ["registrant_country"] = ["Registrant Country:", "Registrant Contact Country:", "Country:"],
        ["registrant_phone"] = ["Registrant Phone:", "Registrant Contact Phone:", "Phone:"],
        ["admin_name"] = ["Admin Name:", "Administrative Contact Name:", "Admin Contact Name:"],
        ["admin_org"] = ["Admin Organization:", "Administrative Contact Organization:"],
        ["admin_email"] = ["Admin Email:", "Administrative Contact Email:"],
        ["admin_phone"] = ["Admin Phone:", "Administrative Contact Phone:"],
        ["tech_name"] = ["Tech Name:", "Technical Contact Name:", "Tech Contact Name:"],
        ["tech_org"] = ["Tech Organization:", "Technical Contact Organization:"],
        ["tech_email"] = ["Tech Email:", "Technical Contact Email:"],
        ["tech_phone"] = ["Tech Phone:", "Technical Contact Phone:"],
        ["registry_domain_id"] = ["Registry Domain ID:", "Domain ID:", "ROID:"],
        ["dnssec"] = ["DNSSEC:"],
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
        if (string.IsNullOrEmpty(response.Domain) && !string.IsNullOrEmpty(response.RawResponse))
        {
            var fields = ExtractFields(response.RawResponse, DomainFieldMappings);
            var parsed = ParseDomainResponse(fields, response.RawResponse);
            
            response.Domain = parsed.Domain;
            response.Dates = parsed.Dates;
            response.NameServers = parsed.NameServers;
            response.Statuses = parsed.Statuses;
            response.Contacts = parsed.Contacts;
            response.Registrar = parsed.Registrar;
            response.Registry = parsed.Registry;
        }
        else if (string.IsNullOrEmpty(response.Domain))
        {
            response.Domain = response.Query;
        }

        response.Privacy = _privacyDetector.Detect(response);
        response.Registry = await _registryIdentifier.IdentifyRegistryAsync(response);
        response.Registrar = await _registryIdentifier.IdentifyRegistrarAsync(response);

        return new FormattedResult
        {
            Domain = response.Domain,
            Registry = response.Registry,
            Registrar = response.Registrar,
            Privacy = response.Privacy,
            Contacts = response.Contacts.GetMergedContacts(),
            Dates = response.Dates,
            NameServers = response.NameServers,
            Statuses = response.Statuses,
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
                if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var afterPrefix = trimmed.Length > prefix.Length ? trimmed[prefix.Length] : '\0';
                    if (afterPrefix == ':' || afterPrefix == ' ' || afterPrefix == '\t' || trimmed.Length == prefix.Length)
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
            Tech = ParseContact(fields, "tech")
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
}
