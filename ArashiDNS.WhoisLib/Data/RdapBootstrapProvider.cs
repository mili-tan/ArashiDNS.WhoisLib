using System.Net.Http;
using System.Text.Json;
using ArashiDNS.WhoisLib.Data.Cache;

namespace ArashiDNS.WhoisLib.Data;

public class RdapBootstrapProvider
{
    private const string DnsBootstrapUrl = "https://data.iana.org/rdap/dns.json";
    private const string Ipv4BootstrapUrl = "https://data.iana.org/rdap/ipv4.json";
    private const string Ipv6BootstrapUrl = "https://data.iana.org/rdap/ipv6.json";
    private const string AsnBootstrapUrl = "https://data.iana.org/rdap/asn.json";
    private const string CacheKey = "rdap_bootstrap";
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromDays(7);

    private readonly ICacheProvider _cache;
    private readonly HttpClient _httpClient;
    private Dictionary<string, string>? _dnsEndpoints;
    private List<IpRdapRange>? _ipv4Endpoints;
    private List<IpRdapRange>? _ipv6Endpoints;
    private List<AsnRdapRange>? _asnEndpoints;

    public RdapBootstrapProvider(ICacheProvider cache, HttpClient? httpClient = null, string? userAgent = null)
    {
        _cache = cache;
        _httpClient = httpClient ?? new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", userAgent ?? "ArashiDNS.WhoisLib/1.0");
    }

    public async Task<string?> GetDnsRdapEndpointAsync(string tld)
    {
        await EnsureDnsEndpointsLoadedAsync();
        return _dnsEndpoints?.GetValueOrDefault(tld.ToLowerInvariant());
    }

    public async Task<string?> GetIpRdapEndpointAsync(System.Net.IPAddress ipAddress)
    {
        await EnsureIpEndpointsLoadedAsync();

        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return FindIpv4Endpoint(ipAddress);
        }
        else
        {
            return FindIpv6Endpoint(ipAddress);
        }
    }

    public async Task<string?> GetAsnRdapEndpointAsync(long asn)
    {
        await EnsureAsnEndpointsLoadedAsync();
        return _asnEndpoints?.FirstOrDefault(r => asn >= r.Start && asn <= r.End)?.Url;
    }

    private async Task EnsureDnsEndpointsLoadedAsync()
    {
        if (_dnsEndpoints != null) return;

        var cached = await _cache.GetAsync<Dictionary<string, string>>($"{CacheKey}_dns");
        if (cached != null)
        {
            _dnsEndpoints = cached;
            return;
        }

        try
        {
            var json = await _httpClient.GetStringAsync(DnsBootstrapUrl);
            var doc = JsonDocument.Parse(json);
            var services = doc.RootElement.GetProperty("services");

            _dnsEndpoints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var service in services.EnumerateArray())
            {
                var tlds = service[0];
                var urls = service[1];

                if (urls.GetArrayLength() > 0)
                {
                    var url = urls[0].GetString();
                    if (!string.IsNullOrEmpty(url))
                    {
                        foreach (var tld in tlds.EnumerateArray())
                        {
                            var tldStr = tld.GetString()?.ToLowerInvariant();
                            if (!string.IsNullOrEmpty(tldStr))
                            {
                                _dnsEndpoints[tldStr] = url;
                            }
                        }
                    }
                }
            }

            await _cache.SetAsync($"{CacheKey}_dns", _dnsEndpoints, CacheExpiration);
        }
        catch
        {
            _dnsEndpoints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private async Task EnsureIpEndpointsLoadedAsync()
    {
        if (_ipv4Endpoints != null && _ipv6Endpoints != null) return;

        var cachedV4 = await _cache.GetAsync<List<IpRdapRange>>($"{CacheKey}_ipv4");
        var cachedV6 = await _cache.GetAsync<List<IpRdapRange>>($"{CacheKey}_ipv6");

        if (cachedV4 != null && cachedV6 != null)
        {
            _ipv4Endpoints = cachedV4;
            _ipv6Endpoints = cachedV6;
            return;
        }

        try
        {
            _ipv4Endpoints = await LoadIpBootstrapAsync(Ipv4BootstrapUrl);
            _ipv6Endpoints = await LoadIpBootstrapAsync(Ipv6BootstrapUrl);

            await _cache.SetAsync($"{CacheKey}_ipv4", _ipv4Endpoints, CacheExpiration);
            await _cache.SetAsync($"{CacheKey}_ipv6", _ipv6Endpoints, CacheExpiration);
        }
        catch
        {
            _ipv4Endpoints = new List<IpRdapRange>();
            _ipv6Endpoints = new List<IpRdapRange>();
        }
    }

    private async Task<List<IpRdapRange>> LoadIpBootstrapAsync(string url)
    {
        var json = await _httpClient.GetStringAsync(url);
        var doc = JsonDocument.Parse(json);
        var services = doc.RootElement.GetProperty("services");
        var ranges = new List<IpRdapRange>();

        foreach (var service in services.EnumerateArray())
        {
            var prefixes = service[0];
            var urls = service[1];

            if (urls.GetArrayLength() > 0)
            {
                var rdapUrl = urls[0].GetString();
                if (!string.IsNullOrEmpty(rdapUrl))
                {
                    foreach (var prefix in prefixes.EnumerateArray())
                    {
                        var prefixStr = prefix.GetString();
                        if (!string.IsNullOrEmpty(prefixStr))
                        {
                            ranges.Add(new IpRdapRange
                            {
                                Prefix = prefixStr,
                                Url = rdapUrl
                            });
                        }
                    }
                }
            }
        }

        return ranges;
    }

    private async Task EnsureAsnEndpointsLoadedAsync()
    {
        if (_asnEndpoints != null) return;

        var cached = await _cache.GetAsync<List<AsnRdapRange>>($"{CacheKey}_asn");
        if (cached != null)
        {
            _asnEndpoints = cached;
            return;
        }

        try
        {
            var json = await _httpClient.GetStringAsync(AsnBootstrapUrl);
            var doc = JsonDocument.Parse(json);
            var services = doc.RootElement.GetProperty("services");
            var ranges = new List<AsnRdapRange>();

            foreach (var service in services.EnumerateArray())
            {
                var asnRanges = service[0];
                var urls = service[1];

                if (urls.GetArrayLength() > 0)
                {
                    var rdapUrl = urls[0].GetString();
                    if (!string.IsNullOrEmpty(rdapUrl))
                    {
                        foreach (var asnRange in asnRanges.EnumerateArray())
                        {
                            var rangeStr = asnRange.GetString();
                            if (!string.IsNullOrEmpty(rangeStr))
                            {
                                var parts = rangeStr.Split('-');
                                if (parts.Length == 2 &&
                                    long.TryParse(parts[0], out var start) &&
                                    long.TryParse(parts[1], out var end))
                                {
                                    ranges.Add(new AsnRdapRange
                                    {
                                        Start = start,
                                        End = end,
                                        Url = rdapUrl
                                    });
                                }
                            }
                        }
                    }
                }
            }

            _asnEndpoints = ranges;
            await _cache.SetAsync($"{CacheKey}_asn", _asnEndpoints, CacheExpiration);
        }
        catch
        {
            _asnEndpoints = new List<AsnRdapRange>();
        }
    }

    private string? FindIpv4Endpoint(System.Net.IPAddress ipAddress)
    {
        if (_ipv4Endpoints == null) return null;

        var bytes = ipAddress.GetAddressBytes();
        var firstOctet = bytes[0];

        var prefix = $"{firstOctet}.0.0.0/8";
        return _ipv4Endpoints.FirstOrDefault(r => r.Prefix == prefix)?.Url;
    }

    private string? FindIpv6Endpoint(System.Net.IPAddress ipAddress)
    {
        if (_ipv6Endpoints == null) return null;

        // Simplified IPv6 lookup, match prefix
        var addrStr = ipAddress.ToString();
        return _ipv6Endpoints.FirstOrDefault(r => addrStr.StartsWith(r.Prefix.Split('/')[0]))?.Url;
    }

    private class IpRdapRange
    {
        public string Prefix { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
    }

    private class AsnRdapRange
    {
        public long Start { get; set; }
        public long End { get; set; }
        public string Url { get; set; } = string.Empty;
    }
}
