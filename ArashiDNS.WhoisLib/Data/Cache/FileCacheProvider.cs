using System.Text.Json;

namespace ArashiDNS.WhoisLib.Data.Cache;

public class FileCacheProvider : ICacheProvider
{
    private readonly string _cacheDirectory;
    private readonly JsonSerializerOptions _jsonOptions;

    public FileCacheProvider(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory ?? Path.Combine(
            Directory.GetCurrentDirectory(),
            ".WhoisLibCache"
        );

        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        Directory.CreateDirectory(_cacheDirectory);
    }

    public async Task<T?> GetAsync<T>(string key) where T : class
    {
        var filePath = GetFilePath(key);
        if (!File.Exists(filePath))
            return null;

        try
        {
            var json = await File.ReadAllTextAsync(filePath);
            var cached = JsonSerializer.Deserialize<CacheEntry<T>>(json, _jsonOptions);

            if (cached == null)
                return null;

            if (cached.ExpiresAt.HasValue && cached.ExpiresAt.Value < DateTime.UtcNow)
            {
                File.Delete(filePath);
                return null;
            }

            return cached.Value;
        }
        catch
        {
            return null;
        }
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null) where T : class
    {
        var filePath = GetFilePath(key);
        var entry = new CacheEntry<T>
        {
            Value = value,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiration.HasValue ? DateTime.UtcNow.Add(expiration.Value) : null
        };

        var json = JsonSerializer.Serialize(entry, _jsonOptions);
        await File.WriteAllTextAsync(filePath, json);
    }

    public Task RemoveAsync(string key)
    {
        var filePath = GetFilePath(key);
        if (File.Exists(filePath))
            File.Delete(filePath);
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string key)
    {
        var filePath = GetFilePath(key);
        return Task.FromResult(File.Exists(filePath));
    }

    private string GetFilePath(string key)
    {
        var safeFileName = string.Join("_", key.Split(Path.GetInvalidFileNameChars()));
        return Path.Combine(_cacheDirectory, $"{safeFileName}.json");
    }

    private class CacheEntry<T>
    {
        public T? Value { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }
}
