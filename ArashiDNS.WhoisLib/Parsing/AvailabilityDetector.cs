using System.Text.Json;
using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Parsing;

/// <summary>
/// Detects domain availability status from WHOIS/RDAP responses
/// </summary>
public partial class AvailabilityDetector
{
    private static readonly string[] NotRegisteredPatterns =
    [
        @"No match for\s+""",
        @"No match for\s+domain",
        @"^NOT FOUND",
        @"^No Data Found",
        @"Domain not found",
        @"Status:\s*free\b",
        @"Domain Status:\s*available\b",
        @"^Status:\s*available$",
        @"No such domain",
        @"The queried object does not exist",
        @"Domain not registered",
        @"is free",
        @"NOT EXIST",
        @"No match for",
        @"No records matching",
        @"DOMAIN NOT FOUND",
        @"^Not found$",
        @"AVAILABLE FOR REGISTRATION",
        @"No entries found",
        @"^AVAILABLE$",
        @"is available for registration",
        @"queried domain name is not registered",
        @"has not been registered",
        @"no matching record",
        @"is free for registration"
    ];

    private static readonly string[] RegisteredPatterns =
    [
        @"Domain Name:",
        @"Domain name:",
        @"domain:",
        @"Registry Domain ID:",
        @"Registrar:",
        @"Creation Date:",
        @"Created:",
        @"Registration Date:",
        @"Registry Expiry Date:",
        @"Expiration Date:",
        @"Updated Date:",
        @"Last Updated:",
        @"Name Server:",
        @"Nameserver:",
        @"nserver:",
        @"Domain Status:",
        @"Status:"
    ];

    private static readonly string[] ThrottledPatterns =
    [
        @"exceeded",
        @"rate limit",
        @"try again later",
        @"too many requests",
        @"query limit",
        @"throttl",
        @"abuse",
        @"Please try again"
    ];

    private static readonly string[] ReservedPatterns =
    [
        @"reserved",
        @"reserved by",
        @"reserved domain",
        @"premium domain",
        @"restricted"
    ];

    private static readonly string[] ServerSpecificNotFounds = new[]
    {
        @"No match for ""{query}""\.",  // Verisign
        @"No match for domain",         // Generic
        @"{query} no match",            // Some ccTLDs
    };

    public AvailabilityResult Detect(string? rawResponse, WhoisQueryType queryType = WhoisQueryType.Domain)
    {
        if (string.IsNullOrWhiteSpace(rawResponse))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.Unknown,
                IsAvailable = false,
                ErrorMessage = "Empty response"
            };
        }

        var lower = rawResponse.ToLowerInvariant();

        if (IsThrottled(rawResponse, lower))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.Throttled,
                IsAvailable = false,
                IsThrottled = true
            };
        }

        if (IsReserved(rawResponse, lower))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.Reserved,
                IsAvailable = false,
                IsReserved = true
            };
        }

        if (IsNotRegistered(rawResponse, lower))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.NotRegistered,
                IsAvailable = true
            };
        }

        if (IsRegistered(rawResponse, lower))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.Registered,
                IsAvailable = false
            };
        }

        return new AvailabilityResult
        {
            Status = AvailabilityStatus.Unknown,
            IsAvailable = false
        };
    }

    public AvailabilityResult DetectFromRdap(string? rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            return new AvailabilityResult
            {
                Status = AvailabilityStatus.Unknown,
                IsAvailable = false,
                ErrorMessage = "Empty RDAP response"
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;

            if (root.TryGetProperty("errorCode", out var errorCode))
            {
                var code = errorCode.GetInt32();
                if (code is 404 or 410)
                {
                    return new AvailabilityResult
                    {
                        Status = AvailabilityStatus.NotRegistered,
                        IsAvailable = true
                    };
                }
                if (code is 429)
                {
                    return new AvailabilityResult
                    {
                        Status = AvailabilityStatus.Throttled,
                        IsAvailable = false,
                        IsThrottled = true
                    };
                }
            }

            if (root.TryGetProperty("ldhName", out _) || root.TryGetProperty("unicodeName", out _))
            {
                return new AvailabilityResult
                {
                    Status = AvailabilityStatus.Registered,
                    IsAvailable = false
                };
            }

            if (root.TryGetProperty("notices", out var notices))
            {
                foreach (var notice in notices.EnumerateArray())
                {
                    var title = notice.TryGetProperty("title", out var t) ? t.GetString() : null;
                    if (title != null && title.Contains("Registration", StringComparison.OrdinalIgnoreCase)
                                     && title.Contains("Available", StringComparison.OrdinalIgnoreCase))
                    {
                        return new AvailabilityResult
                        {
                            Status = AvailabilityStatus.NotRegistered,
                            IsAvailable = true
                        };
                    }
                }
            }
        }
        catch
        {
            // JSON parse error - not a valid RDAP response
        }

        return new AvailabilityResult
        {
            Status = AvailabilityStatus.Unknown,
            IsAvailable = false
        };
    }

    private static bool IsNotRegistered(string raw, string lower)
    {
        foreach (var pattern in NotRegisteredPatterns)
        {
            if (Regex.IsMatch(raw, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline))
            {
                var hasRegisteredSignals = false;
                foreach (var regPattern in RegisteredPatterns)
                {
                    if (Regex.IsMatch(raw, regPattern, RegexOptions.IgnoreCase))
                    {
                        hasRegisteredSignals = true;
                        break;
                    }
                }

                if (!hasRegisteredSignals)
                    return true;
            }
        }

        return false;
    }

    private static bool IsRegistered(string raw, string lower)
    {
        var matchCount = 0;
        foreach (var pattern in RegisteredPatterns)
        {
            if (Regex.IsMatch(raw, pattern, RegexOptions.IgnoreCase))
            {
                matchCount++;
                if (matchCount >= 2) return true;
            }
        }
        return false;
    }

    private static bool IsThrottled(string raw, string lower)
    {
        foreach (var pattern in ThrottledPatterns)
        {
            if (Regex.IsMatch(raw, pattern, RegexOptions.IgnoreCase))
                return true;
        }
        return false;
    }

    private static bool IsReserved(string raw, string lower)
    {
        foreach (var pattern in ReservedPatterns)
        {
            if (Regex.IsMatch(raw, pattern, RegexOptions.IgnoreCase))
                return true;
        }
        return false;
    }
}

public class AvailabilityResult
{
    public AvailabilityStatus Status { get; set; }
    public bool IsAvailable { get; set; }
    public bool IsThrottled { get; set; }
    public bool IsReserved { get; set; }
    public string? ErrorMessage { get; set; }
}

public enum AvailabilityStatus
{
    Unknown,
    NotRegistered,
    Registered,
    Reserved,
    Throttled,
    Error
}
