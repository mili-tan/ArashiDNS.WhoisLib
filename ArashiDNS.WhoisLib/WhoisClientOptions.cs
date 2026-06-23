using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib;

/// <summary>
/// Query strategy
/// </summary>
public enum QueryStrategy
{
    /// <summary>Rdap first: RDAP+Traditional → WHOIS+Traditional → WHOIS+LLM</summary>
    RdapFirst,
    /// <summary>Whois first: WHOIS+Traditional → RDAP+Traditional → WHOIS+LLM</summary>
    WhoisFirst,
    /// <summary>Rdap+Traditional first, skip WHOIS+Traditional, LLM as fallback: RDAP+Traditional → WHOIS+LLM</summary>
    RdapFirstWhoisLlmFallback,
    /// <summary>RDAP+Traditional only</summary>
    RdapTraditionOnly,
    /// <summary>WHOIS+Traditional only</summary>
    WhoisTraditionOnly,
    /// <summary>RDAP+LLM only</summary>
    RdapLlmOnly,
    /// <summary>WHOIS+LLM only</summary>
    WhoisLlmOnly
}

/// <summary>
/// Query result
/// </summary>
public class QueryResult
{
    public FormattedResult Data { get; set; } = new();
    public string RawResponse { get; set; } = string.Empty;
    public string UsedProtocol { get; set; } = string.Empty;
    public string UsedFormatter { get; set; } = string.Empty;
    public string? FinalEndpoint { get; set; }
    public List<TraceEntry> Trace { get; set; } = new();
    public bool IsSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Trace entry
/// </summary>
public class TraceEntry
{
    public string Protocol { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
    public string Formatter { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Client configuration
/// </summary>
public class WhoisClientOptions
{
    /// <summary>Query strategy (default: RdapFirst)</summary>
    public QueryStrategy Strategy { get; set; } = QueryStrategy.RdapFirst;

    /// <summary>LLM API endpoint</summary>
    public string? LlmApiEndpoint { get; set; }

    /// <summary>LLM model name</summary>
    public string? LlmModel { get; set; }

    /// <summary>LLM API Key (default: read from environment variable DEEPSEEK_API_KEY)</summary>
    public string? LlmApiKey { get; set; }

    /// <summary>Enable LLM thinking mode (true=enabled, false=disabled, null=not specified)</summary>
    public bool? LlmEnableThinking { get; set; }

    /// <summary>Custom cache directory</summary>
    public string? CacheDirectory { get; set; }

    /// <summary>User-Agent string (default: ArashiDNS.WhoisLib/1.0)</summary>
    public string UserAgent { get; set; } = "ArashiDNS.WhoisLib/1.0";

    /// <summary>Whether to filter empty contacts (default: true)</summary>
    public bool FilterEmptyContacts { get; set; } = true;

    /// <summary>Custom RDAP server endpoint (overrides auto-discovery)</summary>
    public string? CustomRdapEndpoint { get; set; }

    /// <summary>Custom WHOIS server (overrides auto-discovery)</summary>
    public string? CustomWhoisServer { get; set; }
}
