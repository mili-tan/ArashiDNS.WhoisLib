using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

/// <summary>
/// 已知WHOIS服务器查�?/// 从TldRegistryProvider获取数据
/// </summary>
public class KnownServerLookup : IServerFinder
{
    public Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        if (queryType == WhoisQueryType.Domain)
        {
            var tld = ExtractTld(query);
            if (!string.IsNullOrEmpty(tld))
            {
                // 先尝试完整域名匹配（如co.uk�?                var parts = query.ToLowerInvariant().TrimEnd('.').Split('.');
                if (parts.Length > 2)
                {
                    var parentDomain = string.Join('.', parts[1..]);
                    var parentServer = TldRegistryProvider.GetWhoisServer(parentDomain);
                    if (!string.IsNullOrEmpty(parentServer))
                        return Task.FromResult<string?>(parentServer);
                }

                // 再尝试TLD匹配
                return Task.FromResult(TldRegistryProvider.GetWhoisServer(tld));
            }
        }
        else if (queryType == WhoisQueryType.Asn || queryType == WhoisQueryType.Ipv4 || queryType == WhoisQueryType.Ipv6)
        {
            return Task.FromResult<string?>("whois.arin.net");
        }

        return Task.FromResult<string?>(null);
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }
}
