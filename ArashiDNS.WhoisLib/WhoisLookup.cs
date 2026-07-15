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
    private readonly MultiLayerFormatter _formatter;
    private bool _disposed;

    public WhoisLookup(WhoisClientOptions? options = null)
    {
        _options = options ?? new WhoisClientOptions();

        var cache = new FileCacheProvider(_options.CacheDirectory);
        var downloader = new IanaDataDownloader(userAgent: _options.UserAgent);
        var registrarProvider = new RegistrarListProvider(cache, downloader);
        var ipProvider = new IpAllocationProvider(cache, downloader);
        var rdapBootstrap = new RdapBootstrapProvider(cache, userAgent: _options.UserAgent);

        var serverFinder = new CompositeServerFinder(
            new TldServerLookup(), new DnsServerLookup(),
            new IanaServerLookup(), ipProvider);

        _whoisClient = new WhoisClient(serverFinder);
        _rdapClient = new RdapClient(bootstrapProvider: rdapBootstrap, userAgent: _options.UserAgent);

        var traditionalFormatter = new TraditionalFormatter(registrarProvider);

        LlmFormatter? llmFormatter = null;
        var apiKey = _options.LlmApiKey ?? Environment.GetEnvironmentVariable("DEEPSEEK_API_KEY");
        if (!string.IsNullOrEmpty(apiKey))
        {
            llmFormatter = new LlmFormatter(new LlmFormatterOptions
            {
                ApiKey = apiKey,
                ApiEndpoint = _options.LlmApiEndpoint ?? "https://api.deepseek.com/chat/completions",
                Model = _options.LlmModel ?? "deepseek-v4-flash",
                EnableThinking = _options.LlmEnableThinking
            });
        }

        _formatter = new MultiLayerFormatter(traditionalFormatter, llmFormatter, registrarProvider);
    }

    public async Task<QueryResult> QueryAsync(string query)
    {
        return _options.Strategy switch
        {
            QueryStrategy.RdapFirst => await RunAsync(query, Steps.Rdap, Steps.Whois),
            QueryStrategy.WhoisFirst => await RunAsync(query, Steps.Whois, Steps.Rdap),
            QueryStrategy.RdapFirstWhoisLlmFallback => await RunAsync(query, Steps.Rdap, Steps.Whois),
            QueryStrategy.RdapTraditionOnly => await RunAsync(query, Steps.Rdap),
            QueryStrategy.WhoisTraditionOnly => await RunAsync(query, Steps.Whois),
            QueryStrategy.RdapLlmOnly => await RunAsync(query, Steps.Rdap),
            QueryStrategy.WhoisLlmOnly => await RunAsync(query, Steps.Whois),
            _ => await RunAsync(query, Steps.Rdap, Steps.Whois)
        };
    }

    private async Task<QueryResult> RunAsync(string query, params Steps[] steps)
    {
        var trace = new List<TraceEntry>();
        _rdapClient.OnRequest = (endpoint, success, error) =>
            trace.Add(new TraceEntry { Protocol = "RDAP", Endpoint = endpoint, Success = success, Error = error });

        foreach (var step in steps)
        {
            QueryResult result = step switch
            {
                Steps.Rdap => await TryRdapAsync(query, trace),
                Steps.Whois => await TryWhoisAsync(query, trace),
                _ => new QueryResult { IsSuccessful = false }
            };

            result.Trace = trace;

            if (result.IsSuccessful)
                return PostProcess(result);
        }

        return new QueryResult { IsSuccessful = false, ErrorMessage = "All query methods failed", Trace = trace };
    }

    private async Task<QueryResult> TryRdapAsync(string query, List<TraceEntry> trace)
    {
        try
        {
            WhoisResponse response;

            if (!string.IsNullOrEmpty(_options.CustomRdapEndpoint))
                response = await _rdapClient.QueryAsync(query, _options.CustomRdapEndpoint);
            else
                response = await _rdapClient.QueryAsync(query);

            if (!response.IsSuccessful)
            {
                trace.Add(new TraceEntry
                {
                    Protocol = "RDAP", Endpoint = response.WhoisServer,
                    Formatter = "MultiLayer", Success = false, Error = response.ErrorMessage
                });
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };
            }

            var result = await _formatter.FormatAsync(response);

            trace.Add(new TraceEntry
            {
                Protocol = "RDAP", Endpoint = response.WhoisServer,
                Formatter = _formatter.LastUsedLayer, Success = true
            });

            return new QueryResult
            {
                Data = result,
                RawResponse = response.RawResponse,
                UsedProtocol = "RDAP", UsedFormatter = _formatter.LastUsedLayer,
                FinalEndpoint = response.WhoisServer, IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "RDAP", Formatter = "MultiLayer", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private async Task<QueryResult> TryWhoisAsync(string query, List<TraceEntry> trace)
    {
        try
        {
            WhoisResponse response;

            if (!string.IsNullOrEmpty(_options.CustomWhoisServer))
                response = await _whoisClient.QueryAsync(query, _options.CustomWhoisServer);
            else
                response = await _whoisClient.QueryAsync(query);

            foreach (var server in response.ReferralChain)
            {
                trace.Add(new TraceEntry
                {
                    Protocol = "WHOIS", Endpoint = server,
                    Formatter = "MultiLayer", Success = response.IsSuccessful
                });
            }

            if (!response.IsSuccessful)
            {
                trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = "MultiLayer", Success = false, Error = response.ErrorMessage });
                return new QueryResult { IsSuccessful = false, ErrorMessage = response.ErrorMessage };
            }

            var result = await _formatter.FormatAsync(response);

            trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = _formatter.LastUsedLayer, Success = true, Endpoint = response.WhoisServer });

            return new QueryResult
            {
                Data = result,
                RawResponse = response.RawResponse,
                UsedProtocol = "WHOIS", UsedFormatter = _formatter.LastUsedLayer,
                FinalEndpoint = response.WhoisServer, IsSuccessful = true
            };
        }
        catch (Exception ex)
        {
            trace.Add(new TraceEntry { Protocol = "WHOIS", Formatter = "MultiLayer", Success = false, Error = ex.Message });
            return new QueryResult { IsSuccessful = false, ErrorMessage = ex.Message };
        }
    }

    private QueryResult PostProcess(QueryResult result)
    {
        if (_options.FilterEmptyContacts && result.Data?.Contacts != null)
        {
            result.Data.Contacts = result.Data.Contacts.Where(c =>
                !string.IsNullOrEmpty(c.Name) ||
                !string.IsNullOrEmpty(c.Organization) ||
                !string.IsNullOrEmpty(c.Email) ||
                !string.IsNullOrEmpty(c.Phone) ||
                !string.IsNullOrEmpty(c.Country)
            ).ToList();
        }
        return result;
    }

    private enum Steps { Rdap, Whois }

    public void Dispose()
    {
        if (!_disposed) _disposed = true;
    }
}
