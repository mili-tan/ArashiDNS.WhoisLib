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

            string domain = queryType switch
            {
                WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6 => GetIpDomain(root, query),
                WhoisQueryType.Asn => GetAsnDomain(root, query),
                _ => GetStringProperty(root, "ldhName") ?? query
            };

            var contacts = new ContactCollection();
            RegistrarInfo? registrar = null;
            TryExecute(() => ParseEntities(root, contacts, r => registrar = r));

            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                RawResponse = rawJson,
                Domain = domain,
                IsSuccessful = true,
                WhoisServer = endpoint,
                Statuses = TryParse(() => ParseStatuses(root)) ?? [],
                NameServers = TryParse(() => ParseNameservers(root)) ?? [],
                Dates = TryParse(() => ParseDates(root)) ?? new DomainDates(),
                Contacts = contacts,
                Registrar = registrar
            };
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

    private string GetIpDomain(JsonElement root, string query)
    {
        try
        {
            var name = GetStringProperty(root, "name");
            if (!string.IsNullOrEmpty(name)) return name;

            var start = GetStringProperty(root, "startAddress");
            var end = GetStringProperty(root, "endAddress");
            if (!string.IsNullOrEmpty(start) && !string.IsNullOrEmpty(end))
                return $"{start} - {end}";
        }
        catch { }
        return query;
    }

    private string GetAsnDomain(JsonElement root, string query)
    {
        try
        {
            var name = GetStringProperty(root, "name");
            if (!string.IsNullOrEmpty(name)) return name;

            var handle = GetStringProperty(root, "handle");
            if (!string.IsNullOrEmpty(handle)) return handle;
        }
        catch { }
        return query;
    }

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
                    if (!string.IsNullOrEmpty(value)) result.Add(value);
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
                    if (!string.IsNullOrEmpty(value)) result.Add(value);
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
                if (string.IsNullOrEmpty(action) || string.IsNullOrEmpty(dateStr)) continue;

                if (DateTime.TryParse(dateStr, out var date))
                {
                    switch (action.ToLowerInvariant())
                    {
                        case "registration": dates.Created = date; break;
                        case "last changed" or "last update": dates.Updated = date; break;
                        case "expiration" or "registrar expiration": dates.Expires = date; break;
                    }
                }
            }
        }
        return dates;
    }

    private void ParseEntities(JsonElement root, ContactCollection contacts, Action<RegistrarInfo> onRegistrar)
    {
        if (!root.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array)
            return;

        foreach (var entity in entities.EnumerateArray())
        {
            try
            {
                var roles = ParseRoles(entity);

                if (roles.Contains("registrar"))
                {
                    var registrar = ParseRegistrarEntity(entity);
                    if (registrar != null) onRegistrar(registrar);
                }

                if (roles.Contains("registrant") && contacts.Registrant == null)
                    contacts.Registrant = ParseContact(entity);
                if (roles.Contains("administrative") && contacts.Admin == null)
                    contacts.Admin = ParseContact(entity);
                if (roles.Contains("technical") && contacts.Tech == null)
                    contacts.Tech = ParseContact(entity);

                if (entity.TryGetProperty("entities", out var nested) && nested.ValueKind == JsonValueKind.Array)
                {
                    foreach (var nestedEntity in nested.EnumerateArray())
                    {
                        var nestedRoles = ParseRoles(nestedEntity);
                        var allRoles = nestedRoles.Union(roles).ToList();
                        if (allRoles.Contains("registrant") && contacts.Registrant == null)
                            contacts.Registrant = ParseContact(nestedEntity);
                        if (allRoles.Contains("administrative") && contacts.Admin == null)
                            contacts.Admin = ParseContact(nestedEntity);
                        if (allRoles.Contains("technical") && contacts.Tech == null)
                            contacts.Tech = ParseContact(nestedEntity);
                    }
                }
            }
            catch { }
        }
    }

    private RegistrarInfo? ParseRegistrarEntity(JsonElement entity)
    {
        var registrar = new RegistrarInfo();

        if (entity.TryGetProperty("vcardArray", out var vcard))
        {
            registrar.Name = GetVcardValue(vcard, "fn") ?? "";
            // If fn is empty, try org
            if (string.IsNullOrEmpty(registrar.Name))
                registrar.Name = GetVcardValue(vcard, "org") ?? "";
        }

        if (entity.TryGetProperty("handle", out var handle) && handle.ValueKind == JsonValueKind.String)
        {
            registrar.IanaId = handle.GetString() ?? "";
        }

        if (entity.TryGetProperty("publicIds", out var publicIds) && publicIds.ValueKind == JsonValueKind.Array)
        {
            foreach (var pid in publicIds.EnumerateArray())
            {
                var pidType = GetStringProperty(pid, "type");
                if (pidType == "IANA Registrar ID")
                {
                    registrar.IanaId = GetStringProperty(pid, "identifier") ?? registrar.IanaId;
                    break;
                }
            }
        }

        if (entity.TryGetProperty("links", out var links) && links.ValueKind == JsonValueKind.Array)
        {
            foreach (var link in links.EnumerateArray())
            {
                var rel = GetStringProperty(link, "rel");
                if (rel == "about")
                {
                    registrar.Website = GetStringProperty(link, "href") ?? "";
                    break;
                }
            }
        }

        return string.IsNullOrEmpty(registrar.Name) && string.IsNullOrEmpty(registrar.IanaId)
            ? null
            : registrar;
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
                    if (!string.IsNullOrEmpty(value)) roles.Add(value);
                }
            }
        }
        return roles;
    }

    private ContactInfo ParseContact(JsonElement entity)
    {
        var contact = new ContactInfo();
        if (!entity.TryGetProperty("vcardArray", out var vcard)) return contact;

        contact.Name = GetVcardValue(vcard, "fn") ?? "";
        contact.Organization = GetVcardValue(vcard, "org") ?? "";
        contact.Email = GetVcardPropertyValue(vcard, "email") ?? "";
        contact.Phone = GetVcardPhone(vcard) ?? "";
        contact.Street = GetVcardAddress(vcard, "street") ?? "";
        contact.City = GetVcardAddress(vcard, "city") ?? "";
        contact.State = GetVcardAddress(vcard, "region") ?? "";
        contact.PostalCode = GetVcardAddress(vcard, "code") ?? "";
        contact.Country = GetVcardAddress(vcard, "country") ?? "";
        return contact;
    }

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
                    return ExtractStringValue(arr[3]);
            }
        }
        catch { }
        return null;
    }

    private string? GetVcardPropertyValue(JsonElement vcard, string propertyName)
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
                    return ExtractStringValue(arr[3]);
            }
        }
        catch { }
        return null;
    }

    private string? GetVcardPhone(JsonElement vcard)
    {
        var value = GetVcardPropertyValue(vcard, "tel");
        return value?.StartsWith("tel:") == true ? value[4..] : value;
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
                return vcard[1];
            if (vcard.TryGetProperty("value", out var val))
                return val;
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
}
