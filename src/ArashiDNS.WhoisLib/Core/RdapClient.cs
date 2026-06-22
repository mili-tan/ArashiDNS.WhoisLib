using System.Net.Http;
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
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
            _httpClient = new HttpClient(handler);
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
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
                    Query = query,
                    QueryType = queryType,
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
                Query = query,
                QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = $"RDAP query error: {ex.Message}"
            };
        }
    }

    private async Task<WhoisResponse> QueryWithReferralAsync(string query, WhoisQueryType queryType, string endpoint, int depth = 0)
    {
        const int maxDepth = 3; // 最大referral深度
        
        if (depth >= maxDepth)
        {
            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = "RDAP referral depth exceeded"
            };
        }

        var response = await _httpClient.GetAsync(endpoint);
        if (!response.IsSuccessStatusCode)
        {
            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = $"RDAP query failed: {response.StatusCode}"
            };
        }

        var json = await response.Content.ReadAsStringAsync();
        var result = _parser.Parse(query, queryType, json, endpoint);

        // 检查是否需要follow referral（如果有related链接且缺少联系人信息�?        if (result.IsSuccessful && result.Contacts.Registrant == null && depth < maxDepth)
        {
            var relatedLink = ExtractRelatedLink(json);
            if (!string.IsNullOrEmpty(relatedLink))
            {
                // follow referral获取完整信息
                var referralResult = await QueryWithReferralAsync(query, queryType, relatedLink, depth + 1);
                if (referralResult.IsSuccessful)
                {
                    // 合并结果：保留原始的registry信息，使用referral的联系人信息
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
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("links", out var links))
            {
                foreach (var link in links.EnumerateArray())
                {
                    if (link.TryGetProperty("rel", out var rel) &&
                        rel.GetString() == "related" &&
                        link.TryGetProperty("href", out var href))
                    {
                        return href.GetString();
                    }
                }
            }
        }
        catch
        {
        }

        return null;
    }

    private async Task<string?> GetRdapEndpointAsync(string query, WhoisQueryType queryType)
    {
        if (queryType == WhoisQueryType.Domain)
        {
            var tld = ExtractTld(query);
            
            // 1. 先尝试bootstrap provider（动态IANA数据�?            if (_bootstrapProvider != null)
            {
                var endpoint = await _bootstrapProvider.GetDnsRdapEndpointAsync(tld);
                if (!string.IsNullOrEmpty(endpoint))
                {
                    return ConstructDomainUrl(endpoint, query);
                }
            }

            // 2. 回退到内置列�?            var builtinEndpoint = await _rdapLookup.FindServerAsync(query, queryType);
            if (!string.IsNullOrEmpty(builtinEndpoint))
            {
                return ConstructDomainUrl(builtinEndpoint, query);
            }

            // 3. 最后回退到rdap.org代理
            return $"https://rdap.org/domain/{Uri.EscapeDataString(query.ToLowerInvariant())}";
        }
        else if (queryType == WhoisQueryType.Ipv4 || queryType == WhoisQueryType.Ipv6)
        {
            if (_bootstrapProvider != null && System.Net.IPAddress.TryParse(query, out var ip))
            {
                var endpoint = await _bootstrapProvider.GetIpRdapEndpointAsync(ip);
                if (!string.IsNullOrEmpty(endpoint))
                {
                    return endpoint.TrimEnd('/') + "/ip/" + Uri.EscapeDataString(query);
                }
            }

            return $"https://rdap.org/ip/{Uri.EscapeDataString(query)}";
        }
        else if (queryType == WhoisQueryType.Asn)
        {
            var asnStr = query.Replace("AS", "").Replace("as", "");
            if (_bootstrapProvider != null && long.TryParse(asnStr, out var asn))
            {
                var endpoint = await _bootstrapProvider.GetAsnRdapEndpointAsync(asn);
                if (!string.IsNullOrEmpty(endpoint))
                {
                    return endpoint.TrimEnd('/') + "/autnum/" + Uri.EscapeDataString(asnStr);
                }
            }

            return $"https://rdap.org/autnum/{Uri.EscapeDataString(asnStr)}";
        }

        return null;
    }

    private string ConstructDomainUrl(string baseUrl, string domain)
    {
        if (!baseUrl.EndsWith('/'))
            baseUrl += '/';
        
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

        if (normalized.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("as", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(normalized[2..], out _))
                return WhoisQueryType.Asn;
        }

        if (long.TryParse(normalized, out _))
            return WhoisQueryType.Asn;

        if (System.Net.IPAddress.TryParse(normalized, out var ip))
        {
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? WhoisQueryType.Ipv4
                : WhoisQueryType.Ipv6;
        }

        return WhoisQueryType.Domain;
    }
}
