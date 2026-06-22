using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Core;
using ArashiDNS.WhoisLib.Data;
using ArashiDNS.WhoisLib.Data.Cache;
using ArashiDNS.WhoisLib.Formatting;
using ArashiDNS.WhoisLib.ServerDiscovery;

namespace ArashiDNS.WhoisLib;

public class WhoisLookup : IDisposable
{
    private readonly WhoisClientOptions _options;
    private readonly WhoisClient _whoisClient;
    private readonly RdapClient _rdapClient;
    private readonly TraditionalFormatter _traditionalFormatter;
    private readonly LlmFormatter? _llmFormatter;
    private bool _disposed;

    public WhoisLookup(WhoisClientOptions? options = null)
    {
        _options = options ?? new WhoisClientOptions();

        var cache = new FileCacheProvider(_options.CacheDirectory);
        var downloader = new IanaDataDownloader();
        var registrarProvider = new RegistrarListProvider(cache, downloader);
        var ipProvider = new IpAllocationProvider(cache, downloader);

        var serverFinder = new CompositeServerFinder(
            new KnownServerLookup(), new DnsServerLookup(),
            new IanaServerLookup(), ipProvider);

        _whoisClient = new WhoisClient(serverFinder);
        _rdapClient = new RdapClient();
        _traditionalFormatter = new TraditionalFormatter(registrarProvider);

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

    public async Task<QueryResult> QueryAsync(string query)
    {
        return _options.Strategy switch
        {
            QueryStrategy.RdapFirst => await RunAsync(query, Steps.RdapTrad, Steps.WhoisTrad, Steps.WhoisLlm),
            QueryStrategy.WhoisFirst => await RunAsync(query, Steps.WhoisTrad, Steps.RdapTrad, Steps.WhoisLlm),
            QueryStrategy.RdapFirstWhoisLlmFallback => await RunAsync(query, Steps.RdapTrad, Steps.WhoisLlm),
            QueryStrategy.RdapTraditionOnly => await RunAsync(query, Steps.RdapTrad),
            QueryStrategy.WhoisTraditionOnly => await RunAsync(query, Steps.WhoisTrad),
            QueryStrategy.RdapLlmOnly => await RunAsync(query, Steps.RdapLlm),
            QueryStrategy.WhoisLlmOnly => await RunAsync(query, Steps.WhoisLlm),
            _ => await RunAsync(query, Steps.RdapTrad, Steps.WhoisTrad, Steps.WhoisLlm)
        };
    }

    private async Task<QueryResult> RunAsync(string query, params Steps[] steps)
    {
        foreach (var step in steps)
        {
            var result = step switch
            {
                Steps.RdapTrad => await TryRdapTraditionalAsync(query),
                Steps.WhoisTrad => await TryWhoisTraditionalAsync(query),
                Steps.RdapLlm => await TryRdapLlmAsync(query),
                Steps.WhoisLlm => await TryWhoisLlmAsync(query),
                _ => new QueryResult { IsSuccessful = false }
            };
            if (result.IsSuccessful) return result;
        }

        return new QueryResult { IsSuccessful = false, ErrorMessage = "All query methods failed" };
    }

    private async Task<QueryResult> TryRdapTraditionalAsync(string query)
    {
        try
        {
            var response = await _rdapClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _traditionalFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP",
                UsedFormatter = "Traditional",
                IsSuccessful = true
            };
        }
        catch (Exception ex) { return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message }; }
    }

    private async Task<QueryResult> TryWhoisTraditionalAsync(string query)
    {
        try
        {
            var response = await _whoisClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _traditionalFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "Traditional",
                IsSuccessful = true
            };
        }
        catch (Exception ex) { return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message }; }
    }

    private async Task<QueryResult> TryRdapLlmAsync(string query)
    {
        if (_llmFormatter == null)
            return new QueryResult { IsSuccessful = false, ErrorMessage = "LLM not configured" };

        try
        {
            var response = await _rdapClient.QueryAsync(query);
            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _llmFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP",
                UsedFormatter = "LLM",
                IsSuccessful = true
            };
        }
        catch (Exception ex) { return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message }; }
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

            return new QueryResult
            {
                Data = await _llmFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "LLM",
                IsSuccessful = true
            };
        }
        catch (Exception ex) { return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message }; }
    }

    private enum Steps { RdapTrad, WhoisTrad, RdapLlm, WhoisLlm }

    public void Dispose()
    {
        if (!_disposed) _disposed = true;
    }
}
