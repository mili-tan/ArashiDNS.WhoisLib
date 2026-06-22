using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

public class KnownServerLookup : IServerFinder
{
    public Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        if (queryType == WhoisQueryType.Domain)
        {
            var tld = ExtractTld(query);
            if (!string.IsNullOrEmpty(tld))
            {
                var parts = query.ToLowerInvariant().TrimEnd('.').Split('.');
                if (parts.Length > 2)
                {
                    var parentDomain = string.Join('.', parts[1..]);
                    var parentServer = TldRegistryProvider.GetWhoisServer(parentDomain);
                    if (!string.IsNullOrEmpty(parentServer))
                        return Task.FromResult<string?>(parentServer);
                }

                return Task.FromResult(TldRegistryProvider.GetWhoisServer(tld));
            }
        }
        else if (queryType is WhoisQueryType.Asn or WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6)
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
