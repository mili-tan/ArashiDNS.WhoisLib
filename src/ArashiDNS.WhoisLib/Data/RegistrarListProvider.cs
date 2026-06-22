using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Data.Cache;

namespace ArashiDNS.WhoisLib.Data;

public class RegistrarListProvider
{
    private const string CacheKey = "iana_registrars";
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromDays(7);

    private readonly ICacheProvider _cache;
    private readonly IanaDataDownloader _downloader;

    public RegistrarListProvider(ICacheProvider cache, IanaDataDownloader downloader)
    {
        _cache = cache;
        _downloader = downloader;
    }

    public async Task<List<RegistrarEntry>> GetRegistrarsAsync()
    {
        var cached = await _cache.GetAsync<List<RegistrarEntry>>(CacheKey);
        if (cached != null)
            return cached;

        var registrars = await _downloader.DownloadRegistrarsAsync();
        await _cache.SetAsync(CacheKey, registrars, CacheExpiration);
        return registrars;
    }

    public async Task<RegistrarEntry?> FindRegistrarByIdAsync(string ianaId)
    {
        var registrars = await GetRegistrarsAsync();
        return registrars.FirstOrDefault(r => r.Id == ianaId);
    }

    public async Task<RegistrarEntry?> FindRegistrarByNameAsync(string name)
    {
        var registrars = await GetRegistrarsAsync();
        var normalizedName = name.ToLowerInvariant().Trim();
        return registrars.FirstOrDefault(r =>
            r.Name.ToLowerInvariant().Contains(normalizedName) ||
            normalizedName.Contains(r.Name.ToLowerInvariant()));
    }
}
