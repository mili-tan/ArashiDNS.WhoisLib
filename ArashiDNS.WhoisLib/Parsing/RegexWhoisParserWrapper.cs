using ArashiDNS.RegexWhoisParser;
using ArashiDNS.RegexWhoisParser.Parser;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Wrapper for ArashiDNS.RegexWhoisParser library
/// Maps ParserBase output to WhoisResponse format
/// </summary>
public class RegexWhoisParserWrapper
{
    public WhoisResponse Parse(string rawResponse, string? server = null)
    {
        if (string.IsNullOrWhiteSpace(rawResponse))
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                IsSuccessful = false,
                ErrorMessage = "Empty response"
            };
        }

        try
        {
            var parser = !string.IsNullOrEmpty(server)
                ? RegexWhoisParser.RegexWhoisParser.Parse(rawResponse, server)
                : RegexWhoisParser.RegexWhoisParser.Parse(rawResponse);

            return MapToWhoisResponse(parser, rawResponse, server);
        }
        catch
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                IsSuccessful = false,
                ErrorMessage = "RegexWhoisParser failed"
            };
        }
    }

    private WhoisResponse MapToWhoisResponse(ParserBase parser, string rawResponse, string? server)
    {
        var response = new WhoisResponse
        {
            RawResponse = rawResponse,
            WhoisServer = server ?? string.Empty,
            IsSuccessful = true
        };

        try { response.Domain = parser.Domain?.ToLowerInvariant(); } catch { }
        try { response.Statuses = MapStatus(parser.Status); } catch { }
        try { response.NameServers = MapNameservers(parser.Nameservers); } catch { }
        try { response.Dates = MapDates(parser); } catch { }
        try { response.Registrar = MapRegistrar(parser.Registrar); } catch { }
        try { response.Contacts = MapContacts(parser); } catch { }

        return response;
    }

    private DomainDates? MapDates(ParserBase parser)
    {
        DateTime? created = null, updated = null, expires = null;
        try { created = parser.CreatedOn; } catch { }
        try { updated = parser.UpdatedOn; } catch { }
        try { expires = parser.ExpiresOn; } catch { }

        if (created == null && updated == null && expires == null)
            return null;

        return new DomainDates
        {
            Created = created,
            Updated = updated,
            Expires = expires
        };
    }

    private RegistrarInfo? MapRegistrar(Registrar? registrar)
    {
        if (registrar == null) return null;

        return new RegistrarInfo
        {
            Name = registrar.Name ?? string.Empty,
            IanaId = registrar.Id ?? string.Empty,
            Website = registrar.Url ?? string.Empty,
            WhoisServer = string.Empty
        };
    }

    private ContactCollection MapContacts(ParserBase parser)
    {
        var contacts = new ContactCollection();

        try
        {
            var registrant = parser.RegistrantContacts?.FirstOrDefault();
            if (registrant != null)
                contacts.Registrant = MapContact(registrant);
        }
        catch { }

        try
        {
            var admin = parser.AdminContacts?.FirstOrDefault();
            if (admin != null)
                contacts.Admin = MapContact(admin);
        }
        catch { }

        try
        {
            var tech = parser.TechnicalContacts?.FirstOrDefault();
            if (tech != null)
                contacts.Tech = MapContact(tech);
        }
        catch { }

        return contacts;
    }

    private ContactInfo MapContact(Contact contact)
    {
        return new ContactInfo
        {
            Name = contact.Name ?? string.Empty,
            Organization = contact.Organization ?? string.Empty,
            Email = contact.Email ?? string.Empty,
            Phone = contact.Phone ?? string.Empty,
            Street = contact.Address ?? string.Empty,
            City = contact.City ?? string.Empty,
            State = contact.State ?? string.Empty,
            PostalCode = contact.Zip ?? string.Empty,
            Country = contact.CountryCode ?? contact.Country ?? string.Empty
        };
    }

    private List<string> MapNameservers(List<Nameserver>? nameservers)
    {
        if (nameservers == null) return [];

        return nameservers
            .Where(ns => !string.IsNullOrEmpty(ns.Name))
            .Select(ns => ns.Name!.Trim().ToLowerInvariant())
            .ToList();
    }

    private List<string> MapStatus(object? status)
    {
        if (status == null) return [];

        var result = new List<string>();
        string statusStr;

        if (status is List<string> statusList)
        {
            foreach (var s in statusList)
                AddStatusValues(result, s);
        }
        else
        {
            statusStr = status.ToString() ?? string.Empty;
            AddStatusValues(result, statusStr);
        }

        return result;
    }

    private static void AddStatusValues(List<string> result, string statusStr)
    {
        foreach (var part in statusStr.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            var s = part.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(s) && !s.StartsWith("http") && !s.StartsWith("(") && !result.Contains(s))
                result.Add(s);
        }
    }
}
