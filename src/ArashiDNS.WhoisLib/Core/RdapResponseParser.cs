using System.Text.Json;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Core;

public class RdapResponseParser
{
    public WhoisResponse Parse(string query, WhoisQueryType queryType, string rawJson, string endpoint)
    {
        try
        {
            using var doc = JsonDocument.Parse(rawJson, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
            var root = doc.RootElement;
            
            // 根据查询类型获取域名/名称
            string domain;
            if (queryType == WhoisQueryType.Ipv4 || queryType == WhoisQueryType.Ipv6)
            {
                domain = GetIpDomain(root, query);
            }
            else if (queryType == WhoisQueryType.Asn)
            {
                domain = GetAsnDomain(root, query);
            }
            else
            {
                domain = GetStringProperty(root, "ldhName") ?? query;
            }

            var response = new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                RawResponse = rawJson,
                Domain = domain,
                IsSuccessful = true,
                WhoisServer = endpoint
            };

            // 解析各个字段（尽力而为�?            response.Statuses = TryParse(() => ParseStatuses(root)) ?? new List<string>();
            response.NameServers = TryParse(() => ParseNameservers(root)) ?? new List<string>();
            response.Dates = TryParse(() => ParseDates(root)) ?? new DomainDates();
            TryExecute(() => ParseEntities(response, root));

            return response;
        }
        catch (Exception ex)
        {
            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                RawResponse = rawJson,
                IsSuccessful = false,
                ErrorMessage = $"Failed to parse RDAP response: {ex.Message}"
            };
        }
    }

    #region Helper Methods

    private T? TryParse<T>(Func<T> parser) where T : class
    {
        try { return parser(); }
        catch { return null; }
    }

    private void TryExecute(Action action)
    {
        try { action(); }
        catch { }
    }

    private string? GetStringProperty(JsonElement element, string name)
    {
        try
        {
            if (element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
            {
                var value = prop.GetString();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }
        }
        catch { }
        return null;
    }

    #endregion

    #region Domain/IP/ASN Resolution

    private string GetIpDomain(JsonElement root, string query)
    {
        try
        {
            var name = GetStringProperty(root, "name");
            if (!string.IsNullOrEmpty(name))
                return name;

            var start = GetStringProperty(root, "startAddress");
            var end = GetStringProperty(root, "endAddress");
            if (!string.IsNullOrEmpty(start) && !string.IsNullOrEmpty(end))
                return $"{start} - {end}";
        }
        catch
        {
            // 解析失败，返回查询�?        }

        return query;
    }

    private string GetAsnDomain(JsonElement root, string query)
    {
        var name = GetStringProperty(root, "name");
        if (!string.IsNullOrEmpty(name))
            return name;

        var handle = GetStringProperty(root, "handle");
        if (!string.IsNullOrEmpty(handle))
            return handle;

        return query;
    }

    #endregion

    #region Basic Field Parsing

    private List<string> ParseStatuses(JsonElement root)
    {
        var result = new List<string>();
        if (root.TryGetProperty("status", out var statuses) && statuses.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in statuses.EnumerateArray())
            {
                if (s.ValueKind == JsonValueKind.String)
                {
                    var value = s.GetString()?.ToLowerInvariant();
                    if (!string.IsNullOrEmpty(value))
                        result.Add(value);
                }
            }
        }
        return result;
    }

    private List<string> ParseNameservers(JsonElement root)
    {
        var result = new List<string>();
        if (root.TryGetProperty("nameservers", out var nameservers) && nameservers.ValueKind == JsonValueKind.Array)
        {
            foreach (var ns in nameservers.EnumerateArray())
            {
                if (ns.TryGetProperty("ldhName", out var name) && name.ValueKind == JsonValueKind.String)
                {
                    var value = name.GetString()?.ToLowerInvariant();
                    if (!string.IsNullOrEmpty(value))
                        result.Add(value);
                }
            }
        }
        return result;
    }

    private DomainDates ParseDates(JsonElement root)
    {
        var dates = new DomainDates();
        if (root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
        {
            foreach (var evt in events.EnumerateArray())
            {
                var action = GetStringProperty(evt, "eventAction");
                var dateStr = GetStringProperty(evt, "eventDate");
                
                if (string.IsNullOrEmpty(action) || string.IsNullOrEmpty(dateStr))
                    continue;

                if (DateTime.TryParse(dateStr, out var date))
                {
                    switch (action.ToLowerInvariant())
                    {
                        case "registration":
                            dates.Created = date;
                            break;
                        case "last changed":
                        case "last update":
                            dates.Updated = date;
                            break;
                        case "expiration":
                        case "registrar expiration":
                            dates.Expires = date;
                            break;
                    }
                }
            }
        }
        return dates;
    }

    #endregion

    #region Entity Parsing

    private void ParseEntities(WhoisResponse response, JsonElement root)
    {
        if (!root.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array)
            return;

        var contacts = new ContactCollection();

        foreach (var entity in entities.EnumerateArray())
        {
            try
            {
                var roles = ParseRoles(entity);
                
                if (roles.Contains("registrar"))
                {
                    response.Registrar = ParseRegistrar(entity);
                }

                if (roles.Contains("registrant") && contacts.Registrant == null)
                {
                    contacts.Registrant = ParseContact(entity);
                }

                if (roles.Contains("administrative") && contacts.Admin == null)
                {
                    contacts.Admin = ParseContact(entity);
                }

                if (roles.Contains("technical") && contacts.Tech == null)
                {
                    contacts.Tech = ParseContact(entity);
                }

                if (entity.TryGetProperty("entities", out var nestedEntities) && nestedEntities.ValueKind == JsonValueKind.Array)
                {
                    ParseNestedEntities(response, contacts, nestedEntities, roles);
                }
            }
            catch
            {
                // 跳过无法解析的实�?            }
        }

        response.Contacts = contacts;
    }

    private void ParseNestedEntities(WhoisResponse response, ContactCollection contacts, JsonElement entities, List<string> parentRoles)
    {
        foreach (var entity in entities.EnumerateArray())
        {
            try
            {
                var roles = ParseRoles(entity);
                var allRoles = roles.Union(parentRoles).ToList();

                if (allRoles.Contains("registrant") && contacts.Registrant == null)
                {
                    contacts.Registrant = ParseContact(entity);
                }
                if (allRoles.Contains("administrative") && contacts.Admin == null)
                {
                    contacts.Admin = ParseContact(entity);
                }
                if (allRoles.Contains("technical") && contacts.Tech == null)
                {
                    contacts.Tech = ParseContact(entity);
                }

                if (entity.TryGetProperty("entities", out var nestedEntities) && nestedEntities.ValueKind == JsonValueKind.Array)
                {
                    ParseNestedEntities(response, contacts, nestedEntities, allRoles);
                }
            }
            catch
            {
                // 跳过无法解析的实�?            }
        }
    }

    private List<string> ParseRoles(JsonElement entity)
    {
        var roles = new List<string>();
        if (entity.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in rolesElement.EnumerateArray())
            {
                if (r.ValueKind == JsonValueKind.String)
                {
                    var value = r.GetString();
                    if (!string.IsNullOrEmpty(value))
                        roles.Add(value);
                }
            }
        }
        return roles;
    }

    private RegistrarInfo ParseRegistrar(JsonElement entity)
    {
        var registrar = new RegistrarInfo();
        
        if (entity.TryGetProperty("vcardArray", out var vcard))
        {
            registrar.Name = GetVcardValue(vcard, "fn") ?? "";
        }
        
        registrar.IanaId = GetPublicId(entity, "IANA Registrar ID") ?? "";
        registrar.Website = GetLink(entity, "about") ?? "";

        if (string.IsNullOrEmpty(registrar.Name))
        {
            registrar.Name = GetStringProperty(entity, "handle") ?? "";
        }

        return registrar;
    }

    private ContactInfo ParseContact(JsonElement entity)
    {
        var contact = new ContactInfo();
        
        if (entity.TryGetProperty("vcardArray", out var vcard))
        {
            contact.Name = GetVcardValue(vcard, "fn") ?? "";
            contact.Organization = GetVcardValue(vcard, "org") ?? "";
            contact.Email = GetVcardEmail(vcard) ?? "";
            contact.Phone = GetVcardPhone(vcard) ?? "";
            contact.Street = GetVcardAddress(vcard, "street") ?? "";
            contact.City = GetVcardAddress(vcard, "city") ?? "";
            contact.State = GetVcardAddress(vcard, "region") ?? "";
            contact.PostalCode = GetVcardAddress(vcard, "code") ?? "";
            contact.Country = GetVcardAddress(vcard, "country") ?? "";
        }

        return contact;
    }

    #endregion

    #region vCard Parsing

    private string? GetVcardValue(JsonElement vcard, string propertyName)
    {
        try
        {
            var props = GetVcardProperties(vcard);
            if (props == null) return null;

            foreach (var prop in props.Value.EnumerateArray())
            {
                if (prop.ValueKind != JsonValueKind.Array) continue;
                var arr = prop.EnumerateArray().ToList();
                if (arr.Count < 4 || arr[0].ValueKind != JsonValueKind.String) continue;

                var name = arr[0].GetString();
                if (string.Equals(name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    return ExtractStringValue(arr[3]);
                }
            }
        }
        catch { }
        return null;
    }

    private string? GetVcardEmail(JsonElement vcard)
    {
        return GetVcardValue(vcard, "email");
    }

    private string? GetVcardPhone(JsonElement vcard)
    {
        var value = GetVcardValue(vcard, "tel");
        if (value?.StartsWith("tel:") == true)
            value = value[4..];
        return value;
    }

    private string? GetVcardAddress(JsonElement vcard, string part)
    {
        try
        {
            var props = GetVcardProperties(vcard);
            if (props == null) return null;

            foreach (var prop in props.Value.EnumerateArray())
            {
                if (prop.ValueKind != JsonValueKind.Array) continue;
                var arr = prop.EnumerateArray().ToList();
                if (arr.Count < 4 || arr[0].ValueKind != JsonValueKind.String) continue;

                var name = arr[0].GetString();
                if (!string.Equals(name, "adr", StringComparison.OrdinalIgnoreCase)) continue;

                if (arr[3].ValueKind != JsonValueKind.Array) continue;
                var addrParts = arr[3].EnumerateArray().ToList();

                return part.ToLowerInvariant() switch
                {
                    "street" => addrParts.Count > 2 ? ExtractStringValue(addrParts[2]) : null,
                    "city" => addrParts.Count > 3 ? ExtractStringValue(addrParts[3]) : null,
                    "region" => addrParts.Count > 4 ? ExtractStringValue(addrParts[4]) : null,
                    "code" => addrParts.Count > 5 ? ExtractStringValue(addrParts[5]) : null,
                    "country" => addrParts.Count > 6 ? ExtractStringValue(addrParts[6]) : null,
                    _ => null
                };
            }
        }
        catch { }
        return null;
    }

    private JsonElement? GetVcardProperties(JsonElement vcard)
    {
        try
        {
            if (vcard.ValueKind == JsonValueKind.Array && vcard.GetArrayLength() > 1)
            {
                return vcard[1];
            }
            
            if (vcard.TryGetProperty("value", out var val))
            {
                return val;
            }
        }
        catch { }
        return null;
    }

    private string? ExtractStringValue(JsonElement element)
    {
        try
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.Array => string.Join(", ", element.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString())
                    .Where(s => !string.IsNullOrEmpty(s))),
                _ => null
            };
        }
        catch { return null; }
    }

    #endregion

    #region Public IDs and Links

    private string? GetPublicId(JsonElement entity, string type)
    {
        try
        {
            if (entity.TryGetProperty("publicIds", out var publicIds) && publicIds.ValueKind == JsonValueKind.Array)
            {
                foreach (var pid in publicIds.EnumerateArray())
                {
                    var pidType = GetStringProperty(pid, "type");
                    if (string.Equals(pidType, type, StringComparison.OrdinalIgnoreCase))
                    {
                        return GetStringProperty(pid, "identifier");
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private string? GetLink(JsonElement entity, string rel)
    {
        try
        {
            if (entity.TryGetProperty("links", out var links) && links.ValueKind == JsonValueKind.Array)
            {
                foreach (var link in links.EnumerateArray())
                {
                    var linkRel = GetStringProperty(link, "rel");
                    if (string.Equals(linkRel, rel, StringComparison.OrdinalIgnoreCase))
                    {
                        return GetStringProperty(link, "href");
                    }
                }
            }
        }
        catch { }
        return null;
    }

    #endregion
}
