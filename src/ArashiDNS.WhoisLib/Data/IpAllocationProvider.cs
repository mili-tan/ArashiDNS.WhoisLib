using System.Net;
using System.Net.Sockets;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data.Cache;

namespace ArashiDNS.WhoisLib.Data;

public class IpAllocationProvider
{
    private const string Ipv4CacheKey = "iana_ipv4_allocations";
    private const string Ipv6CacheKey = "iana_ipv6_allocations";
    private const string AsCacheKey = "iana_as_allocations";
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromDays(7);

    private readonly ICacheProvider _cache;
    private readonly IanaDataDownloader _downloader;

    public IpAllocationProvider(ICacheProvider cache, IanaDataDownloader downloader)
    {
        _cache = cache;
        _downloader = downloader;
    }

    public async Task<string?> FindWhoisServerForIpAsync(IPAddress ipAddress)
    {
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            return await FindWhoisServerForIpv4Async(ipAddress);
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return await FindWhoisServerForIpv6Async(ipAddress);
        }
        return null;
    }

    public async Task<string?> FindWhoisServerForAsnAsync(long asn)
    {
        var allocations = await GetAsAllocationsAsync();
        var allocation = allocations.FirstOrDefault(a => asn >= a.RangeStart && asn <= a.RangeEnd);
        return allocation?.WhoisServer;
    }

    private async Task<string?> FindWhoisServerForIpv4Async(IPAddress ipAddress)
    {
        var allocations = await GetIpv4AllocationsAsync();
        var bytes = ipAddress.GetAddressBytes();
        var firstOctet = bytes[0];

        var allocation = allocations.FirstOrDefault(a =>
            int.Parse(a.Prefix) == firstOctet);

        return allocation?.WhoisServer;
    }

    private async Task<string?> FindWhoisServerForIpv6Async(IPAddress ipAddress)
    {
        var allocations = await GetIpv6AllocationsAsync();
        var bytes = ipAddress.GetAddressBytes();

        var matchingAllocations = allocations
            .Where(a => a.PrefixLength > 0)
            .OrderByDescending(a => a.PrefixLength);

        foreach (var allocation in matchingAllocations)
        {
            if (IsInPrefix(bytes, allocation.Prefix, allocation.PrefixLength))
            {
                return allocation.WhoisServer;
            }
        }

        return null;
    }

    private static bool IsInPrefix(byte[] address, string prefix, int prefixLength)
    {
        try
        {
            var prefixAddr = IPAddress.Parse(prefix.Split('/')[0]);
            var prefixBytes = prefixAddr.GetAddressBytes();
            var bytesToCheck = prefixLength / 8;
            var remainingBits = prefixLength % 8;

            for (int i = 0; i < bytesToCheck; i++)
            {
                if (i >= address.Length || i >= prefixBytes.Length)
                    break;
                if (address[i] != prefixBytes[i])
                    return false;
            }

            if (remainingBits > 0 && bytesToCheck < address.Length && bytesToCheck < prefixBytes.Length)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));
                return (address[bytesToCheck] & mask) == (prefixBytes[bytesToCheck] & mask);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task<List<IpAllocation>> GetIpv4AllocationsAsync()
    {
        var cached = await _cache.GetAsync<List<IpAllocation>>(Ipv4CacheKey);
        if (cached != null)
            return cached;

        var allocations = await _downloader.DownloadIpv4AllocationsAsync();
        await _cache.SetAsync(Ipv4CacheKey, allocations, CacheExpiration);
        return allocations;
    }

    private async Task<List<IpAllocation>> GetIpv6AllocationsAsync()
    {
        var cached = await _cache.GetAsync<List<IpAllocation>>(Ipv6CacheKey);
        if (cached != null)
            return cached;

        var allocations = await _downloader.DownloadIpv6AllocationsAsync();
        await _cache.SetAsync(Ipv6CacheKey, allocations, CacheExpiration);
        return allocations;
    }

    private async Task<List<AsAllocation>> GetAsAllocationsAsync()
    {
        var cached = await _cache.GetAsync<List<AsAllocation>>(AsCacheKey);
        if (cached != null)
            return cached;

        var allocations = await _downloader.DownloadAsAllocationsAsync();
        await _cache.SetAsync(AsCacheKey, allocations, CacheExpiration);
        return allocations;
    }
}
