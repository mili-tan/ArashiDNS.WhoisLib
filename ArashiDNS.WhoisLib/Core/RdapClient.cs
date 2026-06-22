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

    public Action<string, bool, string?>? OnRequest { get; set; }

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
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5
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
            Report(endpoint, false, "Referral depth exceeded");
            return new WhoisResponse { Query = query, QueryType = queryType, IsSuccessful = false, ErrorMessage = "RDAP referral depth exceeded" };
        }

        var (json, error) = await FetchRdapAsync(endpoint);
        if (json == null)
        {
            Report(endpoint, false, error);
            return depth == 0
                ? new WhoisResponse { Query = query, QueryType = queryType, IsSuccessful = false, ErrorMessage = error }
                : new WhoisResponse { Query = query, QueryType = queryType, IsSuccessful = true, RawResponse = "", WhoisServer = endpoint };
        }

        if (!IsValidRdap(json))
        {
            Report(endpoint, false, "Invalid RDAP response");
            return depth == 0
                ? new WhoisResponse { Query = query, QueryType = queryType, IsSuccessful = false, ErrorMessage = "Invalid RDAP response" }
                : new WhoisResponse { Query = query, QueryType = queryType, IsSuccessful = true, RawResponse = "", WhoisServer = endpoint };
        }

        Report(endpoint, true);
        var result = _parser.Parse(query, queryType, json, endpoint);

        if (result.IsSuccessful && depth < maxDepth && NeedsReferral(result))
        {
            var relatedLink = ExtractRelatedLink(json);
            if (!string.IsNullOrEmpty(relatedLink))
            {
                var referralResult = await QueryWithReferralAsync(query, queryType, relatedLink, depth + 1);

                if (referralResult.IsSuccessful && HasUsefulData(referralResult))
                {
                    MergeResults(result, referralResult);
                    return referralResult;
                }
            }
        }

        return result;
    }

    private void Report(string endpoint, bool success, string? error = null)
    {
        OnRequest?.Invoke(endpoint, success, error);
    }

    private async Task<(string? json, string? error)> FetchRdapAsync(string endpoint)
    {
        try
        {
            var response = await _httpClient.GetAsync(endpoint);
            if (!response.IsSuccessStatusCode)
                return (null, $"RDAP query failed: {response.StatusCode}");

            var json = await response.Content.ReadAsStringAsync();
            return (json, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    private static bool IsValidRdap(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("rgv587_flag", out _)) return false;
            if (root.TryGetProperty("url", out var urlProp))
            {
                var url = urlProp.GetString();
                if (url != null && url.Contains("punish")) return false;
            }

            if (root.TryGetProperty("ldhName", out _)) return true;
            if (root.TryGetProperty("objectClassName", out _)) return true;
            if (root.TryGetProperty("errorCode", out _)) return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static void MergeResults(WhoisResponse registryResult, WhoisResponse referralResult)
    {
        if (registryResult.Dates != null)
            referralResult.Dates = registryResult.Dates;

        referralResult.Registry = registryResult.Registry;
        referralResult.Domain = registryResult.Domain;
        referralResult.Statuses = registryResult.Statuses.Count > 0 ? registryResult.Statuses : referralResult.Statuses;
        referralResult.NameServers = registryResult.NameServers.Count > 0 ? registryResult.NameServers : referralResult.NameServers;
    }

    private static bool HasUsefulData(WhoisResponse result)
    {
        if (result.Contacts.Registrant != null)
        {
            var r = result.Contacts.Registrant;
            if (!string.IsNullOrEmpty(r.Name) || !string.IsNullOrEmpty(r.Organization) || !string.IsNullOrEmpty(r.Email))
                return true;
        }
        if (result.Contacts.Tech != null)
        {
            var t = result.Contacts.Tech;
            if (!string.IsNullOrEmpty(t.Name) || !string.IsNullOrEmpty(t.Organization) || !string.IsNullOrEmpty(t.Email))
                return true;
        }
        return false;
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
                        if (link.TryGetProperty("type", out var type))
                        {
                            var typeStr = type.GetString();
                            if (!string.IsNullOrEmpty(typeStr) && typeStr.Contains("rdap+json"))
                                return href.GetString();
                        }
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
        if (result.Contacts.Registrant == null && result.Contacts.Tech == null)
            return true;

        var r = result.Contacts.Registrant;
        if (r != null && string.IsNullOrEmpty(r.Name) && string.IsNullOrEmpty(r.Organization) && string.IsNullOrEmpty(r.Email))
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
