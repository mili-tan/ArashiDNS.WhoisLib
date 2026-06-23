using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib;

/// <summary>
/// Quick lookup entry point
/// </summary>
public static class Whois
{
    private static WhoisLookup? _defaultClient;
    private static readonly object Lock = new();

    /// <summary>
    /// Get the default client instance
    /// </summary>
    private static WhoisLookup GetDefaultClient()
    {
        if (_defaultClient == null)
        {
            lock (Lock)
            {
                _defaultClient ??= new WhoisLookup();
            }
        }
        return _defaultClient;
    }

    /// <summary>
    /// Quick lookup
    /// </summary>
    /// <param name="query">Domain/IP/ASN</param>
    /// <returns>Query result</returns>
    public static async Task<QueryResult> LookupAsync(string query)
    {
        return await GetDefaultClient().QueryAsync(query);
    }

    /// <summary>
    /// Query with specified options
    /// </summary>
    public static async Task<QueryResult> LookupAsync(string query, WhoisClientOptions options)
    {
        using var client = new WhoisLookup(options);
        return await client.QueryAsync(query);
    }

    /// <summary>
    /// Dispose the default client
    /// </summary>
    public static void Dispose()
    {
        _defaultClient?.Dispose();
        _defaultClient = null;
    }
}
