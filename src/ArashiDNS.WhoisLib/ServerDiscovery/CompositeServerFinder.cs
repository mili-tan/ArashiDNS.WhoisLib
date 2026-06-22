using System.Collections.Concurrent;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

public class CompositeServerFinder : IServerFinder
{
    private readonly KnownServerLookup _knownLookup;
    private readonly DnsServerLookup _dnsLookup;
    private readonly IanaServerLookup _ianaLookup;
    private readonly IpAllocationProvider _ipProvider;
    private readonly ConcurrentDictionary<string, string> _cache = new();

    public CompositeServerFinder(
        KnownServerLookup knownLookup,
        DnsServerLookup dnsLookup,
        IanaServerLookup ianaLookup,
        IpAllocationProvider ipProvider)
    {
        _knownLookup = knownLookup;
        _dnsLookup = dnsLookup;
        _ianaLookup = ianaLookup;
        _ipProvider = ipProvider;
    }

    public async Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        var cacheKey = $"{queryType}:{query.ToLowerInvariant()}";
        if (_cache.TryGetValue(cacheKey, out var cached))
            return cached;

        string? server = null;

        // For IP/ASN, try IANA allocation data first
        if (queryType == WhoisQueryType.Ipv4 || queryType == WhoisQueryType.Ipv6)
        {
            if (System.Net.IPAddress.TryParse(query, out var ip))
            {
                server = await _ipProvider.FindWhoisServerForIpAsync(ip);
                if (!string.IsNullOrEmpty(server))
                {
                    _cache[cacheKey] = server;
                    return server;
                }
            }
        }
        else if (queryType == WhoisQueryType.Asn)
        {
            if (long.TryParse(query.Replace("AS", "").Replace("as", ""), out var asn))
            {
                server = await _ipProvider.FindWhoisServerForAsnAsync(asn);
                if (!string.IsNullOrEmpty(server))
                {
                    _cache[cacheKey] = server;
                    return server;
                }
            }
        }

        // Level 1: Known list lookup
        server = await _knownLookup.FindServerAsync(query, queryType);
        if (!string.IsNullOrEmpty(server))
        {
            _cache[cacheKey] = server;
            return server;
        }

        // Level 2: DNS lookup (tld.whois-servers.net)
        server = await _dnsLookup.FindServerAsync(query, queryType);
        if (!string.IsNullOrEmpty(server))
        {
            _cache[cacheKey] = server;
            return server;
        }

        // Level 3: IANA WHOIS lookup
        server = await _ianaLookup.FindServerAsync(query, queryType);
        if (!string.IsNullOrEmpty(server))
        {
            _cache[cacheKey] = server;
        }

        return server;
    }
}
