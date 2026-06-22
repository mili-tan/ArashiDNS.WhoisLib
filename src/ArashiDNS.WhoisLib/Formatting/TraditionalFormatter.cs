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

    private static readonly string[] DateFormats = new[]
    {
        "yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-ddTHH:mm:sszzz",
        "yyyy-MM-ddTHH:mm:ss+0000",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd",
        "dd-MMM-yyyy",
        "dd.MM.yyyy",
        "MM/dd/yyyy",
        "yyyyMMdd",
        "ddd MMM d HH:mm:ss yyyy",
        "ddd MMM dd HH:mm:ss yyyy",
        "yyyy. MM. dd.",
        "yyyy/MM/dd",
        "yyyy.MM.dd"
    };

    // 域名WHOIS字段映射 - 支持多种格式
    private static readonly Dictionary<string, string[]> DomainFieldMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        // 域名 - 支持缩进和大小写变体
        ["domain"] = new[] { "Domain Name:", "Domain name:", "domain name:", "domain:", "[Domain Name]" },
        
        // 注册�?        ["registrar_name"] = new[] { "Registrar:", "Sponsoring Registrar:", "Registrar Name:", "Authorized Agency:" },
        ["registrar_iana_id"] = new[] { "Registrar IANA ID:", "Registrar ID:" },
        ["registrar_url"] = new[] { "Registrar URL:", "Registrar Website:", "URL:" },
        ["registrar_whois"] = new[] { "Registrar WHOIS Server:", "Whois Server:" },
        
        // 日期 - 支持多种格式
        ["created"] = new[] { "Creation Date:", "Created:", "Created Date:", "Registration Date:", 
                              "Domain Registration Date:", "Registered on:", "Registered Date:", 
                              "Registration Time:", "[Created Date]" },
        ["updated"] = new[] { "Updated Date:", "Modified:", "Last Modified:", "Last Updated:", 
                              "Domain Last Updated Date:", "Last updated:", "Last Updated Date:",
                              "?? ?? ????:" },
        ["expires"] = new[] { "Registry Expiry Date:", "Expiration Date:", "Expires:", "Expiry Date:", 
                              "Domain Expiration Date:", "Expiry date:", "Expiration Date:",
                              "Registrar Registration Expiration Date:", "Expiration Time:",
                              "[Expiration Date]" },
        
        // 状�?        ["status"] = new[] { "Domain Status:", "Status:", "Domain Status", "Registration status:" },
        
        // 名称服务�?        ["nameserver"] = new[] { "Name Server:", "Nameserver:", "nserver:", "Name servers:", 
                                 "Name Servers:", "Name Server" },
        
        // 注册人信�?        ["registrant_name"] = new[] { "Registrant Name:", "Registrant Contact Name:", "Registrant:", 
                                      "Registrant" },
        ["registrant_org"] = new[] { "Registrant Organization:", "Registrant Contact Organization:", 
                                     "Registrant Organisation:", "Organization:", "Org Name:" },
        ["registrant_email"] = new[] { "Registrant Email:", "Registrant Contact Email:", 
                                       "Registrant Email Address:", "Registrant Contact Email:",
                                       "AC E-Mail:", "Registrant Contact Email" },
        ["registrant_street"] = new[] { "Registrant Street:", "Registrant Contact Street:", "Address:" },
        ["registrant_city"] = new[] { "Registrant City:", "Registrant Contact City:", "City:" },
        ["registrant_state"] = new[] { "Registrant State/Province:", "Registrant Contact State/Province:", 
                                       "Registrant State:", "StateProv:", "State/Province:" },
        ["registrant_postal"] = new[] { "Registrant Postal Code:", "Registrant Contact Postal Code:", 
                                        "Registrant Zip:", "PostalCode:", "Registrant Zip Code:" },
        ["registrant_country"] = new[] { "Registrant Country:", "Registrant Contact Country:", 
                                         "Registrant Country/Region:", "Country:" },
        ["registrant_phone"] = new[] { "Registrant Phone:", "Registrant Contact Phone:", 
                                       "Registrant Phone Ext:", "AC Phone Number:", "Phone:" },
        
        // 管理联系�?        ["admin_name"] = new[] { "Admin Name:", "Administrative Contact Name:", "Admin Contact Name:", 
                                 "Administrative Contact(AC):" },
        ["admin_org"] = new[] { "Admin Organization:", "Administrative Contact Organization:", 
                                "Admin Contact Organization:" },
        ["admin_email"] = new[] { "Admin Email:", "Administrative Contact Email:", "Admin Contact Email:" },
        ["admin_street"] = new[] { "Admin Street:", "Administrative Contact Street:", "Admin Contact Street:" },
        ["admin_city"] = new[] { "Admin City:", "Administrative Contact City:", "Admin Contact City:" },
        ["admin_state"] = new[] { "Admin State/Province:", "Administrative Contact State/Province:", "Admin State:" },
        ["admin_postal"] = new[] { "Admin Postal Code:", "Administrative Contact Postal Code:", "Admin Zip:" },
        ["admin_country"] = new[] { "Admin Country:", "Administrative Contact Country:", "Admin Country/Region:" },
        ["admin_phone"] = new[] { "Admin Phone:", "Administrative Contact Phone:", "Admin Phone Ext:" },
        
        // 技术联系人
        ["tech_name"] = new[] { "Tech Name:", "Technical Contact Name:", "Tech Contact Name:" },
        ["tech_org"] = new[] { "Tech Organization:", "Technical Contact Organization:", "Tech Contact Organization:" },
        ["tech_email"] = new[] { "Tech Email:", "Technical Contact Email:", "Tech Contact Email:" },
        ["tech_street"] = new[] { "Tech Street:", "Technical Contact Street:", "Tech Contact Street:" },
        ["tech_city"] = new[] { "Tech City:", "Technical Contact City:", "Tech Contact City:" },
        ["tech_state"] = new[] { "Tech State/Province:", "Technical Contact State/Province:", "Tech State:" },
        ["tech_postal"] = new[] { "Tech Postal Code:", "Technical Contact Postal Code:", "Tech Zip:" },
        ["tech_country"] = new[] { "Tech Country:", "Technical Contact Country:", "Tech Country/Region:" },
        ["tech_phone"] = new[] { "Tech Phone:", "Technical Contact Phone:", "Tech Phone Ext:" },
        
        // 其他
        ["registry_domain_id"] = new[] { "Registry Domain ID:", "Domain ID:", "ROID:" },
        ["dnssec"] = new[] { "DNSSEC:" },
    };

    // IP WHOIS字段映射 - 支持ARIN, RIPE, APNIC, AFRINIC格式
    private static readonly Dictionary<string, string[]> IpFieldMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        ["network_range"] = new[] { "NetRange:", "inetnum:", "IP Address:" },
        ["network_name"] = new[] { "NetName:", "netname:" },
        ["organization"] = new[] { "OrgName:", "org-name:", "org:", "Organisation:", "descr:" },
        ["address"] = new[] { "Address:", "address:" },
        ["city"] = new[] { "City:" },
        ["state"] = new[] { "StateProv:", "state:" },
        ["postal_code"] = new[] { "PostalCode:", "postal-code:" },
        ["country"] = new[] { "Country:", "country:" },
        ["abuse_email"] = new[] { "OrgAbuseEmail:", "abuse-mailbox:", "e-mail:" },
        ["abuse_phone"] = new[] { "OrgAbusePhone:", "phone:" },
    };

    public TraditionalFormatter(RegistrarListProvider registrarProvider)
    {
        _privacyDetector = new PrivacyDetector();
        _registryIdentifier = new RegistryIdentifier(registrarProvider);
    }

    public async Task<FormattedResult> FormatAsync(WhoisResponse response)
    {
        // 根据查询类型选择不同的解析策�?        if (response.QueryType == WhoisQueryType.Ipv4 || response.QueryType == WhoisQueryType.Ipv6)
        {
            return await FormatIpResponseAsync(response);
        }
        else if (response.QueryType == WhoisQueryType.Asn)
        {
            return await FormatAsnResponseAsync(response);
        }
        else
        {
            return await FormatDomainResponseAsync(response);
        }
    }

    private async Task<FormattedResult> FormatDomainResponseAsync(WhoisResponse response)
    {
        // 检查响应是否已经解析过（例如RDAP响应�?        if (string.IsNullOrEmpty(response.Domain) && !string.IsNullOrEmpty(response.RawResponse))
        {
            // 只有当Domain为空且有RawResponse时才解析（WHOIS响应�?            var fields = ExtractFields(response.RawResponse, DomainFieldMappings);
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
            // 如果Domain为空，使用查询�?            response.Domain = response.Query;
        }

        // Detect privacy protection
        response.Privacy = _privacyDetector.Detect(response);

        // Identify registry/registrar
        response.Registry = await _registryIdentifier.IdentifyRegistryAsync(response);
        response.Registrar = await _registryIdentifier.IdentifyRegistrarAsync(response);

        // Return formatted result
        return new FormattedResult
        {
            Domain = response.Domain,
            Registry = response.Registry,
            Registrar = response.Registrar,
            Privacy = response.Privacy,
            Contacts = response.Contacts.GetMergedContacts(),
            Dates = response.Dates,
            NameServers = response.NameServers,
            Statuses = response.Statuses
        };
    }

    private async Task<FormattedResult> FormatIpResponseAsync(WhoisResponse response)
    {
        // 如果Domain已经设置（例如RDAP响应），则保留；否则从WHOIS响应中解�?        if (string.IsNullOrEmpty(response.Domain))
        {
            var fields = ExtractFields(response.RawResponse, IpFieldMappings);
            response.Domain = GetFieldValue(fields, "network_range");
        }

        // 如果Registry未设置，则从WHOIS响应中解�?        if (response.Registry == null || string.IsNullOrEmpty(response.Registry.Name))
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
            Contacts = response.Contacts?.GetMergedContacts() ?? new List<ContactInfo>(),
            NameServers = response.NameServers ?? new List<string>(),
            Statuses = response.Statuses ?? new List<string>()
        };
    }

    private async Task<FormattedResult> FormatAsnResponseAsync(WhoisResponse response)
    {
        // ASN格式与IP类似
        return await FormatIpResponseAsync(response);
    }

    private WhoisResponse ParseDomainResponse(Dictionary<string, List<string>> fields, string rawResponse)
    {
        var response = new WhoisResponse
        {
            RawResponse = rawResponse
        };

        // 清理域名字段（移除缩进和多余空格�?        response.Domain = CleanFieldValue(GetFieldValue(fields, "domain"));
        response.Dates = ParseDates(fields);
        response.NameServers = CleanFieldValues(GetFieldValues(fields, "nameserver"));
        response.Statuses = ParseStatuses(GetFieldValues(fields, "status"));
        response.Contacts = ParseContacts(fields);

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
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        // 移除前导/尾随空格和缩�?        value = value.Trim();
        
        // 移除方括号（如JPRS格式 [Domain Name] -> Domain Name�?        if (value.StartsWith('[') && value.EndsWith(']'))
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

        // 按前缀长度降序排序，确保优先匹配更具体的前缀
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

            // 跳过看起来像句子的行（包含太多单词）
            var wordCount = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
            if (wordCount > 10)
                continue;

            foreach (var mapping in sortedMappings)
            {
                var prefix = mapping.Prefix;
                
                // 处理带缩进的格式（如VeriSign�?"   Domain Name:"�?                // 确保前缀后面是冒号、空格或行尾
                if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var afterPrefix = trimmed.Length > prefix.Length ? trimmed[prefix.Length] : '\0';
                    if (afterPrefix == ':' || afterPrefix == ' ' || afterPrefix == '\t' || trimmed.Length == prefix.Length)
                    {
                        var value = trimmed[prefix.Length..].Trim();
                        if (!string.IsNullOrEmpty(value))
                        {
                            if (!fields.ContainsKey(mapping.Key))
                                fields[mapping.Key] = new List<string>();
                            fields[mapping.Key].Add(value);
                        }
                        break;
                    }
                }
                
                // 处理JPRS格式 "a. [Domain Name]    VALUE"
                if (prefix.StartsWith("[") && trimmed.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var idx = trimmed.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        var value = trimmed[(idx + prefix.Length)..].Trim();
                        if (!string.IsNullOrEmpty(value) && !value.StartsWith("["))
                        {
                            if (!fields.ContainsKey(mapping.Key))
                                fields[mapping.Key] = new List<string>();
                            fields[mapping.Key].Add(value);
                        }
                    }
                    break;
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
        return fields.TryGetValue(key, out var values) ? values : new List<string>();
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
        if (string.IsNullOrWhiteSpace(dateStr))
            return null;

        // 移除括号内的内容（如时区说明�?        dateStr = dateStr.Split('(')[0].Trim();
        
        // 移除尾随的时区缩写（如JST, UTC等）
        dateStr = Regex.Replace(dateStr, @"\s*(JST|UTC|GMT|KST)\s*$", "", RegexOptions.IgnoreCase).Trim();

        foreach (var format in DateFormats)
        {
            if (DateTime.TryParseExact(dateStr, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                return date;
        }

        // 尝试处理 "1999. 07. 28." 这种格式（韩文WHOIS�?        var koreanFormat = Regex.Replace(dateStr, @"(\d{4})\.\s*(\d{2})\.\s*(\d{2})\.", "$1-$2-$3");
        if (DateTime.TryParse(koreanFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var koreanDate))
            return koreanDate;

        if (DateTime.TryParse(dateStr, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return parsed;

        return null;
    }

    private static List<string> ParseStatuses(List<string> statusValues)
    {
        return statusValues
            .SelectMany(s => s.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
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
        if (string.IsNullOrEmpty(domain))
            return string.Empty;

        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }
}
