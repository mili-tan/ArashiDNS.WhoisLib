using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib;

/// <summary>
/// 查询策略
/// </summary>
public enum QueryStrategy
{
    /// <summary>Rdap优先: RDAP+传统 → WHOIS+传统 → WHOIS+LLM</summary>
    RdapFirst,
    /// <summary>Whois优先: WHOIS+传统 → RDAP+传统 → WHOIS+LLM</summary>
    WhoisFirst,
    /// <summary>Rdap+传统优先，跳过WHOIS+传统，LLM兜底: RDAP+传统 → WHOIS+LLM</summary>
    RdapFirstWhoisLlmFallback,
    /// <summary>仅RDAP+传统</summary>
    RdapTraditionOnly,
    /// <summary>仅WHOIS+传统</summary>
    WhoisTraditionOnly,
    /// <summary>仅RDAP+LLM</summary>
    RdapLlmOnly,
    /// <summary>仅WHOIS+LLM</summary>
    WhoisLlmOnly
}

/// <summary>
/// 查询结果
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
/// 追踪条目
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
/// 客户端配置
/// </summary>
public class WhoisClientOptions
{
    /// <summary>查询策略（默认Rdap优先）</summary>
    public QueryStrategy Strategy { get; set; } = QueryStrategy.RdapFirst;

    /// <summary>LLM API端点</summary>
    public string? LlmApiEndpoint { get; set; }

    /// <summary>LLM模型名称</summary>
    public string? LlmModel { get; set; }

    /// <summary>LLM API Key（默认从环境变量DEEPSEEK_API_KEY读取）</summary>
    public string? LlmApiKey { get; set; }

    /// <summary>是否启用LLM思考模式（true=启用, false=禁用, null=不指定）</summary>
    public bool? LlmEnableThinking { get; set; }

    /// <summary>自定义缓存目录</summary>
    public string? CacheDirectory { get; set; }

    /// <summary>User-Agent字符串（默认 ArashiDNS.WhoisLib/1.0）</summary>
    public string UserAgent { get; set; } = "ArashiDNS.WhoisLib/1.0";

    /// <summary>是否过滤空联系人（默认true）</summary>
    public bool FilterEmptyContacts { get; set; } = true;
}
