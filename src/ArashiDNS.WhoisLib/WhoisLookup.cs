using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Core;
using ArashiDNS.WhoisLib.Data;
using ArashiDNS.WhoisLib.Data.Cache;
using ArashiDNS.WhoisLib.Detection;
using ArashiDNS.WhoisLib.Formatting;
using ArashiDNS.WhoisLib.ServerDiscovery;

namespace ArashiDNS.WhoisLib;

/// <summary>
/// ArashiDNS WHOIS/RDAP 查询客户端
/// </summary>
public class WhoisLookup : IDisposable
{
    private readonly WhoisClientOptions _options;
    private readonly WhoisClient _whoisClient;
    private readonly RdapClient _rdapClient;
    private readonly RegistrarListProvider _registrarProvider;
    private readonly TraditionalFormatter _traditionalFormatter;
    private readonly LlmFormatter? _llmFormatter;
    private bool _disposed;

    public WhoisLookup(WhoisClientOptions? options = null)
    {
        _options = options ?? new WhoisClientOptions();

        var cache = new FileCacheProvider(_options.CacheDirectory);
        var downloader = new IanaDataDownloader();
        _registrarProvider = new RegistrarListProvider(cache, downloader);
        var ipProvider = new IpAllocationProvider(cache, downloader);

        var knownLookup = new KnownServerLookup();
        var dnsLookup = new DnsServerLookup();
        var ianaLookup = new IanaServerLookup();
        var serverFinder = new CompositeServerFinder(knownLookup, dnsLookup, ianaLookup, ipProvider);

        _whoisClient = new WhoisClient(serverFinder);
        _rdapClient = new RdapClient();
        _traditionalFormatter = new TraditionalFormatter(_registrarProvider);

        var apiKey = _options.LlmApiKey ?? Environment.GetEnvironmentVariable("DEEPSEEK_API_KEY");
        if (!string.IsNullOrEmpty(apiKey))
        {
            _llmFormatter = new LlmFormatter(new LlmFormatterOptions
            {
                ApiKey = apiKey,
                ApiEndpoint = _options.LlmApiEndpoint ?? "https://api.deepseek.com/chat/completions",
                Model = _options.LlmModel ?? "deepseek-v4-flash",
                EnableThinking = _options.LlmEnableThinking
            });
        }
    }

    /// <summary>
    /// 查询域名/IP/ASN信息
    /// </summary>
    public async Task<QueryResult> QueryAsync(string query)
    {
        return _options.Strategy switch
        {
            QueryStrategy.RdapFirst => await QueryRdapFirstAsync(query),
            QueryStrategy.WhoisFirst => await QueryWhoisFirstAsync(query),
            QueryStrategy.RdapOnly => await QueryRdapOnlyAsync(query),
            QueryStrategy.WhoisOnly => await QueryWhoisOnlyAsync(query),
            QueryStrategy.LlmOnly => await QueryLlmOnlyAsync(query),
            _ => await QueryRdapFirstAsync(query)
        };
    }

    private async Task<QueryResult> QueryRdapFirstAsync(string query)
    {
        // 1. RDAP + 传统
        var result = await TryRdapTraditionalAsync(query);
        if (result.IsSuccessful) return result;

        // 2. WHOIS + 传统
        result = await TryWhoisTraditionalAsync(query);
        if (result.IsSuccessful) return result;

        // 3. WHOIS + LLM
        if (_llmFormatter != null)
        {
            result = await TryWhoisLlmAsync(query);
            if (result.IsSuccessful) return result;
        }

        return new QueryResult
        {
            IsSuccessful = false,
            ErrorMessage = "All query methods failed"
        };
    }

    private async Task<QueryResult> QueryWhoisFirstAsync(string query)
    {
        // 1. WHOIS + 传统
        var result = await TryWhoisTraditionalAsync(query);
        if (result.IsSuccessful) return result;

        // 2. RDAP + 传统
        result = await TryRdapTraditionalAsync(query);
        if (result.IsSuccessful) return result;

        // 3. WHOIS + LLM
        if (_llmFormatter != null)
        {
            result = await TryWhoisLlmAsync(query);
            if (result.IsSuccessful) return result;
        }

        return new QueryResult
        {
            IsSuccessful = false,
            ErrorMessage = "All query methods failed"
        };
    }

    private async Task<QueryResult> QueryRdapOnlyAsync(string query)
    {
        return await TryRdapTraditionalAsync(query);
    }

    private async Task<QueryResult> QueryWhoisOnlyAsync(string query)
    {
        return await TryWhoisTraditionalAsync(query);
    }

    private async Task<QueryResult> QueryLlmOnlyAsync(string query)
    {
        if (_llmFormatter == null)
        {
            return new QueryResult
            {
                IsSuccessful = false,
                ErrorMessage = "LLM API key not configured"
            };
        }

        // 先获取原始数据
        var whoisResponse = await _whoisClient.QueryAsync(query);
        if (!whoisResponse.IsSuccessful)
        {
            whoisResponse = await _rdapClient.QueryAsync(query);
        }

        if (!whoisResponse.IsSuccessful)
        {
            return new QueryResult
            {
                IsSuccessful = false,
                ErrorMessage = whoisResponse.ErrorMessage
            };
        }

        var formatted = await _llmFormatter.FormatAsync(whoisResponse);
        return new QueryResult
        {
            Data = formatted,
            RawResponse = whoisResponse.RawResponse,
            UsedProtocol = "WHOIS",
            UsedFormatter = "LLM",
            IsSuccessful = true
        };
    }

    private async Task<QueryResult> TryRdapTraditionalAsync(string query)
    {
        try
        {
            var response = await _rdapClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            var formatted = await _traditionalFormatter.FormatAsync(response);
            return new QueryResult
            {
                Data = formatted,
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP",
                UsedFormatter = "Traditional",
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryWhoisTraditionalAsync(string query)
    {
        try
        {
            var response = await _whoisClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            var formatted = await _traditionalFormatter.FormatAsync(response);
            return new QueryResult
            {
                Data = formatted,
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "Traditional",
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryWhoisLlmAsync(string query)
    {
        if (_llmFormatter == null)
            return new QueryResult { IsSuccessful = false, ErrorMessage = "LLM not configured" };

        try
        {
            var response = await _whoisClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            var formatted = await _llmFormatter.FormatAsync(response);
            return new QueryResult
            {
                Data = formatted,
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "LLM",
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
    }
}
