using System.Net.Http;
using System.Text.Json;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;
using ArashiDNS.WhoisLib.ServerDiscovery;

namespace ArashiDNS.WhoisLib.Core;

public class RdapClient : IWhoisClient
{
    private readonly HttpClient _httpClient;
    private readonly RdapResponseParser _parser;
    private readonly RdapBootstrapProvider? _bootstrapProvider;
    private readonly RdapServerLookup _rdapLookup = new();

    public RdapClient(HttpClient? httpClient = null, RdapBootstrapProvider? bootstrapProvider = null)
    {
        if (httpClient != null)
        {
            _httpClient = httpClient;
        }
        else
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        }

        _httpClient.DefaultRequestHeaders.Add("Accept", "application/rdap+json");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "WhoisLib/1.0");
        _parser = new RdapResponseParser();
        _bootstrapProvider = bootstrapProvider;
    }

    public async Task<WhoisResponse> QueryAsync(string query)
    {
        var queryType = DetectQueryType(query);
        return await QueryAsync(query, queryType);
    }

    public async Task<WhoisResponse> QueryAsync(string query, string server)
    {
        return await QueryAsync(query);
    }

    public async Task<WhoisResponse> QueryAsync(string query, WhoisQueryType queryType)
    {
        try
        {
            var endpoint = await GetRdapEndpointAsync(query, queryType);
            if (string.IsNullOrEmpty(endpoint))
            {
                return new WhoisResponse
                {
                    Query = query, QueryType = queryType,
                    IsSuccessful = false,
                    ErrorMessage = $"No RDAP endpoint found for {query}"
                };
            }

            return await QueryWithReferralAsync(query, queryType, endpoint);
        }
        catch (Exception ex)
        {
            return new WhoisResponse
            {
                Query = query, QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = $"RDAP query error: {ex.Message}"
            };
        }
    }

    private async Task<WhoisResponse> QueryWithReferralAsync(string query, WhoisQueryType queryType, string endpoint, int depth = 0)
    {
        const int maxDepth = 3;
        if (depth >= maxDepth)
        {
            return new WhoisResponse
            {
                Query = query, QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = "RDAP referral depth exceeded"
            };
        }

        var response = await _httpClient.GetAsync(endpoint);
        if (!response.IsSuccessStatusCode)
        {
            return new WhoisResponse
            {
                Query = query, QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = $"RDAP query failed: {response.StatusCode}"
            };
        }

        var json = await response.Content.ReadAsStringAsync();
        var result = _parser.Parse(query, queryType, json, endpoint);

        // Follow referral if registrant has no useful data
        if (result.IsSuccessful && depth < maxDepth && NeedsReferral(result))
        {
            var relatedLink = ExtractRelatedLink(json);
            if (!string.IsNullOrEmpty(relatedLink))
            {
                var referralResult = await QueryWithReferralAsync(query, queryType, relatedLink, depth + 1);
                if (referralResult.IsSuccessful)
                {
                    // Merge: keep registry from current, use referral's contacts
                    referralResult.Registry = result.Registry;
                    referralResult.Domain = result.Domain;
                    return referralResult;
                }
            }
        }

        return result;
    }

    private string? ExtractRelatedLink(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("links", out var links))
            {
                foreach (var link in links.EnumerateArray())
                {
                    if (link.TryGetProperty("rel", out var rel) && rel.GetString() == "related" &&
                        link.TryGetProperty("href", out var href))
                    {
                        // Check for application/rdap+json type (preferred)
                        if (link.TryGetProperty("type", out var type))
                        {
                            var typeStr = type.GetString();
                            if (!string.IsNullOrEmpty(typeStr) && typeStr.Contains("rdap+json"))
                                return href.GetString();
                        }
                        // Fallback: accept any related link
                        return href.GetString();
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static bool NeedsReferral(WhoisResponse result)
    {
        // Follow referral if no registrant at all
        if (result.Contacts.Registrant == null)
            return true;

        // Follow referral if registrant has no useful data
        var r = result.Contacts.Registrant;
        if (string.IsNullOrEmpty(r.Name) &&
            string.IsNullOrEmpty(r.Organization) &&
            string.IsNullOrEmpty(r.Email))
            return true;

        return false;
    }

    private async Task<string?> GetRdapEndpointAsync(string query, WhoisQueryType queryType)
    {
        if (queryType == WhoisQueryType.Domain)
        {
            var tld = ExtractTld(query);

            if (_bootstrapProvider != null)
            {
                var endpoint = await _bootstrapProvider.GetDnsRdapEndpointAsync(tld);
                if (!string.IsNullOrEmpty(endpoint))
                    return ConstructDomainUrl(endpoint, query);
            }

            var builtinEndpoint = await _rdapLookup.FindServerAsync(query, queryType);
            if (!string.IsNullOrEmpty(builtinEndpoint))
                return ConstructDomainUrl(builtinEndpoint, query);

            return $"https://rdap.org/domain/{Uri.EscapeDataString(query.ToLowerInvariant())}";
        }

        if (queryType is WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6)
        {
            if (_bootstrapProvider != null && System.Net.IPAddress.TryParse(query, out var ip))
            {
                var endpoint = await _bootstrapProvider.GetIpRdapEndpointAsync(ip);
                if (!string.IsNullOrEmpty(endpoint))
                    return endpoint.TrimEnd('/') + "/ip/" + Uri.EscapeDataString(query);
            }
            return $"https://rdap.org/ip/{Uri.EscapeDataString(query)}";
        }

        if (queryType == WhoisQueryType.Asn)
        {
            var asnStr = query.Replace("AS", "").Replace("as", "");
            if (_bootstrapProvider != null && long.TryParse(asnStr, out var asn))
            {
                var endpoint = await _bootstrapProvider.GetAsnRdapEndpointAsync(asn);
                if (!string.IsNullOrEmpty(endpoint))
                    return endpoint.TrimEnd('/') + "/autnum/" + Uri.EscapeDataString(asnStr);
            }
            return $"https://rdap.org/autnum/{Uri.EscapeDataString(asnStr)}";
        }

        return null;
    }

    private string ConstructDomainUrl(string baseUrl, string domain)
    {
        if (!baseUrl.EndsWith('/')) baseUrl += '/';
        return baseUrl + "domain/" + Uri.EscapeDataString(domain.ToUpperInvariant());
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }

    private static WhoisQueryType DetectQueryType(string query)
    {
        var normalized = query.Trim();
        if (normalized.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(normalized[2..], out _)) return WhoisQueryType.Asn;
        }
        if (long.TryParse(normalized, out _)) return WhoisQueryType.Asn;
        if (System.Net.IPAddress.TryParse(normalized, out var ip))
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? WhoisQueryType.Ipv4 : WhoisQueryType.Ipv6;
        return WhoisQueryType.Domain;
    }
}
