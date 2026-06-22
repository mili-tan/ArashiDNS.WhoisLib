using System.Net;
using System.Net.Sockets;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

public class DnsServerLookup : IServerFinder
{
    private const string WhoisServerSuffix = "whois-servers.net";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    public async Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        if (queryType != WhoisQueryType.Domain)
            return null;

        var tld = ExtractTld(query);
        if (string.IsNullOrEmpty(tld))
            return null;

        var dnsName = $"{tld}.{WhoisServerSuffix}";

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(dnsName);
            if (addresses.Length > 0)
            {
                var hostEntry = await Dns.GetHostEntryAsync(dnsName);
                return hostEntry.HostName;
            }
        }
        catch
        {
            // DNS lookup failed, return null
        }

        return null;
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        if (parts.Length < 2)
            return string.Empty;

        return parts[^1].ToLowerInvariant();
    }
}
