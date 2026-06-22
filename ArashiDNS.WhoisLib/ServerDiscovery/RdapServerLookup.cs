using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

public class RdapServerLookup : IServerFinder
{
    public Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        if (queryType != WhoisQueryType.Domain)
            return Task.FromResult<string?>(null);

        var tld = ExtractTld(query);
        if (string.IsNullOrEmpty(tld))
            return Task.FromResult<string?>(null);

        var parts = query.ToLowerInvariant().TrimEnd('.').Split('.');
        if (parts.Length > 2)
        {
            var parentDomain = string.Join('.', parts[1..]);
            var parentEndpoint = TldRegistryProvider.GetRdapEndpoint(parentDomain);
            if (!string.IsNullOrEmpty(parentEndpoint))
                return Task.FromResult<string?>(parentEndpoint);
        }

        return Task.FromResult(TldRegistryProvider.GetRdapEndpoint(tld));
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        return parts.Length > 0 ? parts[^1].ToLowerInvariant() : string.Empty;
    }
}
