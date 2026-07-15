using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Multi-layer WHOIS parser that combines Tokenizer and Regex parsing modes
/// Layer 1: TokenizerParser (template-based, inspired by flipbit/whois)
/// Layer 2: RegexParser (regex-based, inspired by weppos/whois-parser)
/// Layer 3: SectionParser (section-based, for formats like .kg, .cn)
/// </summary>
public class MultiLayerParser
{
    private readonly TokenizerParser _tokenizerParser;
    private readonly RegexParser _regexParser;
    private readonly AvailabilityDetector _availabilityDetector;
    private readonly GeoNormalizer _geoNormalizer;

    public MultiLayerParser()
    {
        _tokenizerParser = new TokenizerParser();
        _regexParser = new RegexParser();
        _availabilityDetector = new AvailabilityDetector();
        _geoNormalizer = new GeoNormalizer();
    }

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

        var availability = _availabilityDetector.Detect(rawResponse);

        if (availability.IsThrottled)
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                WhoisServer = server ?? string.Empty,
                IsSuccessful = false,
                ErrorMessage = "Query throttled"
            };
        }

        if (availability.IsAvailable)
        {
            return new WhoisResponse
            {
                RawResponse = rawResponse,
                WhoisServer = server ?? string.Empty,
                IsSuccessful = true,
                Domain = string.Empty,
                Statuses = ["available"]
            };
        }

        var result = TryTokenizerParse(rawResponse, server);
        if (result.IsSuccessful && HasUsefulData(result))
        {
            return PostProcess(result);
        }

        result = TryRegexParse(rawResponse, server);
        if (result.IsSuccessful)
        {
            return PostProcess(result);
        }

        result = TrySectionParse(rawResponse, server);
        if (result.IsSuccessful)
        {
            return PostProcess(result);
        }

        return new WhoisResponse
        {
            RawResponse = rawResponse,
            WhoisServer = server ?? string.Empty,
            IsSuccessful = false,
            ErrorMessage = "All parsing methods failed"
        };
    }

    private WhoisResponse TryTokenizerParse(string rawResponse, string? server)
    {
        try
        {
            return _tokenizerParser.Parse(rawResponse, server);
        }
        catch
        {
            return new WhoisResponse { IsSuccessful = false };
        }
    }

    private WhoisResponse TryRegexParse(string rawResponse, string? server)
    {
        try
        {
            return _regexParser.Parse(rawResponse, server);
        }
        catch
        {
            return new WhoisResponse { IsSuccessful = false };
        }
    }

    private WhoisResponse TrySectionParse(string rawResponse, string? server)
    {
        try
        {
            return ParseSectionBased(rawResponse, server);
        }
        catch
        {
            return new WhoisResponse { IsSuccessful = false };
        }
    }

    private WhoisResponse ParseSectionBased(string rawResponse, string? server)
    {
        var response = new WhoisResponse
        {
            RawResponse = rawResponse,
            WhoisServer = server ?? string.Empty,
            IsSuccessful = true
        };

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

            if (trimmed.StartsWith("Record created:", StringComparison.OrdinalIgnoreCase))
            {
                response.Dates ??= new DomainDates();
                response.Dates.Created = ParseFlexibleDate(trimmed[15..].Trim());
            }
            else if (trimmed.StartsWith("Record last updated", StringComparison.OrdinalIgnoreCase))
            {
                var dateStr = trimmed.Contains(":") ? trimmed[(trimmed.IndexOf(':') + 1)..].Trim() : trimmed;
                response.Dates ??= new DomainDates();
                response.Dates.Updated = ParseFlexibleDate(dateStr);
            }
            else if (trimmed.StartsWith("Record expires", StringComparison.OrdinalIgnoreCase))
            {
                var dateStr = trimmed.Contains(":") ? trimmed[(trimmed.IndexOf(':') + 1)..].Trim() : trimmed;
                response.Dates ??= new DomainDates();
                response.Dates.Expires = ParseFlexibleDate(dateStr);
            }

            if (trimmed.Contains("Name servers", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("Nameservers", StringComparison.OrdinalIgnoreCase))
            {
                inNameserverSection = true;
                continue;
            }

            if (inNameserverSection && !string.IsNullOrEmpty(trimmed))
            {
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

        response.Contacts = contacts;
        response.NameServers = nameServers;
        return response;
    }

    private static DateTime? ParseFlexibleDate(string? dateStr)
    {
        if (string.IsNullOrWhiteSpace(dateStr))
            return null;

        var formats = new[]
        {
            "ddd MMM d HH:mm:ss yyyy",
            "ddd MMM dd HH:mm:ss yyyy",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd",
            "dd-MMM-yyyy",
            "yyyy-MM-ddTHH:mm:ssZ",
            "yyyy-MM-ddTHH:mm:sszzz"
        };

        foreach (var format in formats)
        {
            if (DateTime.TryParseExact(dateStr.Trim(), format,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var date))
                return date;
        }

        return DateTime.TryParse(dateStr, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var parsed) ? parsed : null;
    }

    private static bool HasUsefulData(WhoisResponse response)
    {
        if (!string.IsNullOrEmpty(response.Domain))
            return true;

        if (response.NameServers.Count > 0)
            return true;

        if (response.Statuses.Count > 0)
            return true;

        if (response.Dates?.Created != null || response.Dates?.Expires != null)
            return true;

        if (response.Registrar != null && !string.IsNullOrEmpty(response.Registrar.Name))
            return true;

        if (response.Contacts?.Registrant != null)
        {
            var r = response.Contacts.Registrant;
            if (!string.IsNullOrEmpty(r.Name) || !string.IsNullOrEmpty(r.Organization) || !string.IsNullOrEmpty(r.Email))
                return true;
        }

        return false;
    }

    private WhoisResponse PostProcess(WhoisResponse response)
    {
        if (response.Contacts?.Registrant != null)
        {
            var geo = _geoNormalizer.Normalize(
                response.Contacts.Registrant.Country,
                response.Contacts.Registrant.State,
                response.Contacts.Registrant.City,
                response.Contacts.Registrant.Street
            );

            if (!string.IsNullOrEmpty(geo.CountryCode))
            {
                response.Contacts.Registrant.Country = geo.CountryCode;
            }
        }

        return response;
    }

    public void AddTokenizerTemplate(string content, string name)
    {
        _tokenizerParser.AddTemplate(content, name);
    }

    public void ClearTokenizerTemplates()
    {
        _tokenizerParser.ClearTemplates();
    }
}
