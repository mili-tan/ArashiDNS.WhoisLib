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

            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                RawResponse = rawJson,
                Domain = ParseDomain(root, queryType, query),
                IsSuccessful = true,
                WhoisServer = GetString(root, "port43") ?? endpoint,
                Statuses = ParseStatuses(root),
                NameServers = ParseNameservers(root),
                Dates = ParseDates(root),
                Contacts = ParseContacts(root, out var registrar),
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

    #region Domain/IP/ASN Resolution

    private string ParseDomain(JsonElement root, WhoisQueryType queryType, string fallback)
    {
        return queryType switch
        {
            WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6 => ParseIpDomain(root, fallback),
            WhoisQueryType.Asn => ParseAsnDomain(root, fallback),
            _ => GetString(root, "ldhName") ?? GetString(root, "unicodeName") ?? fallback
        };
    }

    private string ParseIpDomain(JsonElement root, string fallback)
    {
        var name = GetString(root, "name");
        if (!string.IsNullOrEmpty(name)) return name;

        var start = GetString(root, "startAddress");
        var end = GetString(root, "endAddress");
        if (!string.IsNullOrEmpty(start) && !string.IsNullOrEmpty(end))
            return $"{start} - {end}";

        return fallback;
    }

    private string ParseAsnDomain(JsonElement root, string fallback)
    {
        return GetString(root, "name") ?? GetString(root, "handle") ?? fallback;
    }

    #endregion

    #region Basic Field Parsing

    private List<string> ParseStatuses(JsonElement root)
    {
        var result = new List<string>();
        if (!root.TryGetProperty("status", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return result;

        foreach (var s in arr.EnumerateArray())
        {
            if (s.ValueKind == JsonValueKind.String)
            {
                var value = s.GetString()?.ToLowerInvariant();
                if (!string.IsNullOrEmpty(value))
                    result.Add(value);
            }
        }
        return result;
    }

    private List<string> ParseNameservers(JsonElement root)
    {
        var result = new List<string>();
        if (!root.TryGetProperty("nameservers", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return result;

        foreach (var ns in arr.EnumerateArray())
        {
            var name = GetString(ns, "ldhName") ?? GetString(ns, "unicodeName");
            if (!string.IsNullOrEmpty(name))
                result.Add(name.ToLowerInvariant());
        }
        return result;
    }

    private DomainDates ParseDates(JsonElement root)
    {
        var dates = new DomainDates();
        if (!root.TryGetProperty("events", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return dates;

        foreach (var evt in arr.EnumerateArray())
        {
            var action = GetString(evt, "eventAction");
            var dateStr = GetString(evt, "eventDate");
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
        return dates;
    }

    #endregion

    #region Entity/Contact Parsing

    private ContactCollection ParseContacts(JsonElement root, out RegistrarInfo? registrar)
    {
        registrar = null;
        var contacts = new ContactCollection();

        if (!root.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array)
            return contacts;

        foreach (var entity in entities.EnumerateArray())
        {
            try
            {
                ProcessEntity(entity, contacts, ref registrar, new HashSet<string>());
            }
            catch { }
        }

        return contacts;
    }

    private void ProcessEntity(JsonElement entity, ContactCollection contacts, ref RegistrarInfo? registrar, HashSet<string> processedHandles)
    {
        var roles = GetRoles(entity);
        var handle = GetString(entity, "handle") ?? "";

        // Avoid processing same entity twice
        if (!string.IsNullOrEmpty(handle))
        {
            if (processedHandles.Contains(handle)) return;
            processedHandles.Add(handle);
        }

        // Registrar
        if (roles.Contains("registrar") && registrar == null)
        {
            registrar = ParseRegistrar(entity);
        }

        // Contacts (first match wins)
        if (roles.Contains("registrant") && contacts.Registrant == null)
            contacts.Registrant = ParseContact(entity);
        if (roles.Contains("administrative") && contacts.Admin == null)
            contacts.Admin = ParseContact(entity);
        if (roles.Contains("technical") && contacts.Tech == null)
            contacts.Tech = ParseContact(entity);
        if (roles.Contains("billing") && contacts.Billing == null)
            contacts.Billing = ParseContact(entity);

        // Process nested entities
        if (entity.TryGetProperty("entities", out var nested) && nested.ValueKind == JsonValueKind.Array)
        {
            foreach (var nestedEntity in nested.EnumerateArray())
            {
                ProcessEntity(nestedEntity, contacts, ref registrar, processedHandles);
            }
        }
    }

    private RegistrarInfo ParseRegistrar(JsonElement entity)
    {
        var registrar = new RegistrarInfo();

        // Get name from vCard
        if (entity.TryGetProperty("vcardArray", out var vcard))
        {
            registrar.Name = GetVcardValue(vcard, "fn") ?? GetVcardValue(vcard, "org") ?? "";
        }

        // Get IANA ID from handle
        registrar.IanaId = GetString(entity, "handle") ?? "";

        // Override with publicIds if available
        if (entity.TryGetProperty("publicIds", out var publicIds) && publicIds.ValueKind == JsonValueKind.Array)
        {
            foreach (var pid in publicIds.EnumerateArray())
            {
                if (GetString(pid, "type") == "IANA Registrar ID")
                {
                    registrar.IanaId = GetString(pid, "identifier") ?? registrar.IanaId;
                    break;
                }
            }
        }

        // Get website from links
        if (entity.TryGetProperty("links", out var links) && links.ValueKind == JsonValueKind.Array)
        {
            foreach (var link in links.EnumerateArray())
            {
                if (GetString(link, "rel") == "about")
                {
                    registrar.Website = GetString(link, "href") ?? "";
                    break;
                }
            }
        }

        return registrar;
    }

    private ContactInfo ParseContact(JsonElement entity)
    {
        var contact = new ContactInfo();

        if (!entity.TryGetProperty("vcardArray", out var vcard))
            return contact;

        var properties = GetVcardProperties(vcard);
        if (properties == null)
            return contact;

        foreach (var prop in properties.Value.EnumerateArray())
        {
            try
            {
                if (prop.ValueKind != JsonValueKind.Array) continue;

                var items = prop.EnumerateArray().ToList();
                if (items.Count < 4 || items[0].ValueKind != JsonValueKind.String)
                    continue;

                var fieldType = items[0].GetString()?.ToLowerInvariant();
                if (string.IsNullOrEmpty(fieldType) || fieldType is "version" or "n")
                    continue;

                var value = items[3];
                var attributes = items.Count > 1 && items[1].ValueKind == JsonValueKind.Object
                    ? items[1]
                    : default;

                ApplyVcardField(contact, fieldType, value, attributes);
            }
            catch { }
        }

        // Fallback: use org as name if name is empty
        if (string.IsNullOrEmpty(contact.Name) && !string.IsNullOrEmpty(contact.Organization))
            contact.Name = contact.Organization;

        return contact;
    }

    private void ApplyVcardField(ContactInfo contact, string fieldType, JsonElement value, JsonElement attributes)
    {
        switch (fieldType)
        {
            case "fn":
                contact.Name = ExtractString(value) ?? "";
                break;

            case "org":
                contact.Organization = ExtractString(value) ?? "";
                break;

            case "email":
                contact.Email = ExtractString(value) ?? "";
                break;

            case "contact-uri":
                if (string.IsNullOrEmpty(contact.Email))
                    contact.Email = ExtractString(value) ?? "";
                break;

            case "tel":
                var phone = ExtractString(value);
                if (phone?.StartsWith("tel:") == true)
                    phone = phone[4..];

                if (!string.IsNullOrEmpty(phone) && string.IsNullOrEmpty(contact.Phone))
                    contact.Phone = phone;
                break;

            case "adr":
                ApplyAddressField(contact, value, attributes);
                break;
        }
    }

    private void ApplyAddressField(ContactInfo contact, JsonElement value, JsonElement attributes)
    {
        // Check for label first (easier to parse)
        if (attributes.ValueKind == JsonValueKind.Object &&
            attributes.TryGetProperty("label", out var label) &&
            label.ValueKind == JsonValueKind.String)
        {
            contact.Street = label.GetString() ?? "";
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            // adr format: [pobox, ext, street, city, region, code, country]
            var parts = value.EnumerateArray().ToList();
            var streetParts = new List<string>();

            if (parts.Count > 0) streetParts.Add(ExtractString(parts[0]) ?? "");
            if (parts.Count > 1) streetParts.Add(ExtractString(parts[1]) ?? "");
            if (parts.Count > 2) streetParts.Add(ExtractString(parts[2]) ?? "");

            contact.Street = string.Join(", ", streetParts.Where(s => !string.IsNullOrEmpty(s)));
            if (parts.Count > 3) contact.City = ExtractString(parts[3]) ?? "";
            if (parts.Count > 4) contact.State = ExtractString(parts[4]) ?? "";
            if (parts.Count > 5) contact.PostalCode = ExtractString(parts[5]) ?? "";
            if (parts.Count > 6) contact.Country = ExtractString(parts[6]) ?? "";
        }

        // Country code from attributes overrides
        if (attributes.ValueKind == JsonValueKind.Object &&
            attributes.TryGetProperty("cc", out var cc) &&
            cc.ValueKind == JsonValueKind.String)
        {
            contact.Country = cc.GetString() ?? contact.Country;
        }
    }

    #endregion

    #region vCard Helpers

    private JsonElement? GetVcardProperties(JsonElement vcard)
    {
        if (vcard.ValueKind == JsonValueKind.Array && vcard.GetArrayLength() > 1)
            return vcard[1];

        if (vcard.TryGetProperty("value", out var val))
            return val;

        return null;
    }

    private string? GetVcardValue(JsonElement vcard, string propertyName)
    {
        var properties = GetVcardProperties(vcard);
        if (properties == null) return null;

        foreach (var prop in properties.Value.EnumerateArray())
        {
            if (prop.ValueKind != JsonValueKind.Array) continue;

            var items = prop.EnumerateArray().ToList();
            if (items.Count < 4 || items[0].ValueKind != JsonValueKind.String) continue;

            if (string.Equals(items[0].GetString(), propertyName, StringComparison.OrdinalIgnoreCase))
                return ExtractString(items[3]);
        }

        return null;
    }

    #endregion

    #region Utility Methods

    private List<string> GetRoles(JsonElement entity)
    {
        var roles = new List<string>();
        if (!entity.TryGetProperty("roles", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return roles;

        foreach (var r in arr.EnumerateArray())
        {
            if (r.ValueKind == JsonValueKind.String)
            {
                var value = r.GetString();
                if (!string.IsNullOrEmpty(value))
                    roles.Add(value);
            }
        }
        return roles;
    }

    private string? GetString(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
        {
            var value = prop.GetString();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
        return null;
    }

    private string? ExtractString(JsonElement element)
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

    #endregion
}
