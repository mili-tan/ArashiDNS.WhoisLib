using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib;

/// <summary>
/// 快速查询入口
/// </summary>
public static class Whois
{
    private static WhoisLookup? _defaultClient;
    private static readonly object Lock = new();

    /// <summary>
    /// 获取默认客户端实例
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
    /// 快速查询
    /// </summary>
    /// <param name="query">域名/IP/ASN</param>
    /// <returns>查询结果</returns>
    public static async Task<QueryResult> LookupAsync(string query)
    {
        return await GetDefaultClient().QueryAsync(query);
    }

    /// <summary>
    /// 使用指定选项查询
    /// </summary>
    public static async Task<QueryResult> LookupAsync(string query, WhoisClientOptions options)
    {
        using var client = new WhoisLookup(options);
        return await client.QueryAsync(query);
    }

    /// <summary>
    /// 释放默认客户端
    /// </summary>
    public static void Dispose()
    {
        _defaultClient?.Dispose();
        _defaultClient = null;
    }
}
