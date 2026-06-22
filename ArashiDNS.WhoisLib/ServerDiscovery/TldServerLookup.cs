using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

/// <summary>
/// Unified TLD server lookup for both WHOIS and RDAP
/// Uses TldRegistryProvider as single data source
/// </summary>
public class TldServerLookup : IServerFinder
{
    private readonly bool _rdapMode;

    public TldServerLookup(bool rdapMode = false)
    {
        _rdapMode = rdapMode;
    }

    public Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        if (queryType == WhoisQueryType.Domain)
        {
            var tld = ExtractTld(query);
            if (!string.IsNullOrEmpty(tld))
            {
                // Try parent domain first (e.g., co.uk)
                var parts = query.ToLowerInvariant().TrimEnd('.').Split('.');
                if (parts.Length > 2)
                {
                    var parentDomain = string.Join('.', parts[1..]);
                    var parentResult = LookupByTld(parentDomain);
                    if (!string.IsNullOrEmpty(parentResult))
                        return Task.FromResult<string?>(parentResult);
                }

                return Task.FromResult(LookupByTld(tld));
            }
        }
        else if (queryType is WhoisQueryType.Asn or WhoisQueryType.Ipv4 or WhoisQueryType.Ipv6)
        {
            // RDAP uses IANA bootstrap, WHOIS uses ARIN
            if (!_rdapMode)
                return Task.FromResult<string?>("whois.arin.net");
        }

        return Task.FromResult<string?>(null);
    }

    private string? LookupByTld(string tld)
    {
        return _rdapMode
            ? TldRegistryProvider.GetRdapEndpoint(tld)
            : TldRegistryProvider.GetWhoisServer(tld);
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }
}
