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
        var trace = new List<TraceEntry>();
        _rdapClient.OnRequest = (endpoint, success, error) =>
            trace.Add(new TraceEntry { Protocol = "RDAP", Endpoint = endpoint, Success = success, Error = error });

        foreach (var step in steps)
        {
            var result = step switch
            {
                Steps.RdapTrad => await TryRdapTraditionalAsync(query, trace),
                Steps.WhoisTrad => await TryWhoisTraditionalAsync(query, trace),
                Steps.RdapLlm => await TryRdapLlmAsync(query, trace),
                Steps.WhoisLlm => await TryWhoisLlmAsync(query, trace),
                _ => new QueryResult { IsSuccessful = false }
            };

            result.Trace = trace;
            if (result.IsSuccessful) return result;
        }

        return new QueryResult { IsSuccessful = false, ErrorMessage = "All query methods failed", Trace = trace };
    }

    private async Task<QueryResult> TryRdapTraditionalAsync(string query, List<TraceEntry> trace)
    {
        try
        {
            var response = await _rdapClient.QueryAsync(query);
            trace.Add(new TraceEntry
            {
                Protocol = "RDAP",
                Endpoint = response.WhoisServer,
                Formatter = "Traditional",
                Success = response.IsSuccessful,
                Error = response.ErrorMessage
            });

            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _traditionalFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP",
                UsedFormatter = "Traditional",
                FinalEndpoint = response.WhoisServer,
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "RDAP", Formatter = "Traditional", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryWhoisTraditionalAsync(string query, List<TraceEntry> trace)
    {
        try
        {
            var response = await _whoisClient.QueryAsync(query);

            foreach (var server in response.ReferralChain)
            {
                trace.Add(new TraceEntry
                {
                    Protocol = "WHOIS",
                    Endpoint = server,
                    Formatter = "Traditional",
                    Success = true
                });
            }

            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _traditionalFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "Traditional",
                FinalEndpoint = response.WhoisServer,
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = "Traditional", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryRdapLlmAsync(string query, List<TraceEntry> trace)
    {
        if (_llmFormatter == null)
        {
            trace.Add(new TraceEntry { Protocol = "RDAP", Formatter = "LLM", Success = false, Error = "LLM not configured" });
            return new QueryResult { IsSuccessful = false, ErrorMessage = "LLM not configured" };
        }

        try
        {
            var response = await _rdapClient.QueryAsync(query);
            trace.Add(new TraceEntry
            {
                Protocol = "RDAP",
                Endpoint = response.WhoisServer,
                Formatter = "LLM",
                Success = response.IsSuccessful,
                Error = response.ErrorMessage
            });

            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _llmFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP",
                UsedFormatter = "LLM",
                FinalEndpoint = response.WhoisServer,
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "RDAP", Formatter = "LLM", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryWhoisLlmAsync(string query, List<TraceEntry> trace)
    {
        if (_llmFormatter == null)
        {
            trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = "LLM", Success = false, Error = "LLM not configured" });
            return new QueryResult { IsSuccessful = false, ErrorMessage = "LLM not configured" };
        }

        try
        {
            var response = await _whoisClient.QueryAsync(query);

            foreach (var server in response.ReferralChain)
            {
                trace.Add(new TraceEntry
                {
                    Protocol = "WHOIS",
                    Endpoint = server,
                    Formatter = "LLM",
                    Success = true
                });
            }

            if (!response.IsSuccessful)
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };

            return new QueryResult
            {
                Data = await _llmFormatter.FormatAsync(response),
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS",
                UsedFormatter = "LLM",
                FinalEndpoint = response.WhoisServer,
                IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = "LLM", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private enum Steps { RdapTrad, WhoisTrad, RdapLlm, WhoisLlm }

    public void Dispose()
    {
        if (!_disposed) _disposed = true;
    }
}
