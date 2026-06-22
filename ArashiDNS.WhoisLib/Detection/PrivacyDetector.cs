using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Detection;

public class PrivacyDetector
{
    private static readonly string[] PrivacyKeywords = new[]
    {
        "redacted for privacy",
        "redacted for gdpr",
        "data protected",
        "data not available",
        "whoisguard",
        "domains by proxy",
        "contact privacy",
        "withheld for privacy",
        "perfect privacy",
        "registration private",
        "privacyprotect",
        "privacydotlink",
        "privacy service",
        "whoisprivacy",
        "identity protection service",
        "super privacy service",
        "dynadot privacy",
        "not disclosed",
        "personal data is not published",
        "please query the rdds"
    };

    private static readonly string[] PrivacyEmailDomains = new[]
    {
        "@domainsbyproxy.com",
        "@whoisguard.com",
        "@contactprivacy.com",
        "@withheldforprivacy.com",
        "@privacyprotect.com",
        "@privacydotlink.com",
        "@proxy.domain.com",
        "@privacy",
        "@redacted",
        "@protect"
    };

    private static readonly Dictionary<string, string> PrivacyProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["domains by proxy"] = "Domains By Proxy (GoDaddy)",
        ["domainsbyproxy"] = "Domains By Proxy (GoDaddy)",
        ["registration private"] = "Domains By Proxy (GoDaddy)",
        ["whoisguard"] = "WhoisGuard (Namecheap)",
        ["contact privacy"] = "Contact Privacy (Google)",
        ["contactprivacy"] = "Contact Privacy (Google)",
        ["withheld for privacy"] = "Withheld for Privacy (Namecheap)",
        ["withheldforprivacy"] = "Withheld for Privacy (Namecheap)",
        ["perfect privacy"] = "Perfect Privacy (Network Solutions)",
        ["privacyprotect"] = "Privacy Protect",
        ["privacydotlink"] = "PrivacyDotLink",
        ["super privacy service"] = "Dynadot Privacy",
        ["dynadot privacy"] = "Dynadot Privacy",
        ["redacted for privacy"] = "GDPR Redaction",
        ["redacted for gdpr"] = "GDPR Redaction",
        ["identity protection service"] = "Identity Protection Service"
    };

    public PrivacyInfo Detect(WhoisResponse response)
    {
        var rawResponse = response.RawResponse?.ToLowerInvariant() ?? string.Empty;
        var indicators = new List<string>();

        foreach (var keyword in PrivacyKeywords)
        {
            if (rawResponse.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add(keyword);
            }
        }

        var registrantEmail = response.Contacts?.Registrant?.Email ?? string.Empty;
        foreach (var domain in PrivacyEmailDomains)
        {
            if (registrantEmail.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add($"Email domain: {domain}");
            }
        }

        var redactedCount = Regex.Matches(rawResponse, @"redacted").Count;
        if (redactedCount >= 3)
        {
            indicators.Add($"Multiple redacted fields ({redactedCount})");
        }

        var isPrivate = indicators.Count > 0;
        var provider = DetectProvider(rawResponse);

        return new PrivacyInfo
        {
            IsPrivate = isPrivate,
            Provider = provider,
            Indicators = indicators
        };
    }

    private static string? DetectProvider(string rawResponse)
    {
        foreach (var provider in PrivacyProviders)
        {
            if (rawResponse.Contains(provider.Key, StringComparison.OrdinalIgnoreCase))
            {
                return provider.Value;
            }
        }

        return null;
    }
}
