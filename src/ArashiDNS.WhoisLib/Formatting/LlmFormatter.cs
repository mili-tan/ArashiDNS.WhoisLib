using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Formatting;

/// <summary>
/// LLM格式化器配置
/// </summary>
public class LlmFormatterOptions
{
    /// <summary>
    /// API端点（默认DeepSeek�?    /// </summary>
    public string ApiEndpoint { get; set; } = "https://api.deepseek.com/chat/completions";

    /// <summary>
    /// 模型名称（默认deepseek-v4-flash�?    /// </summary>
    public string Model { get; set; } = "deepseek-v4-flash";

    /// <summary>
    /// API密钥
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// 是否启用思考模式（默认关闭�?    /// </summary>
    public bool EnableThinking { get; set; } = false;

    /// <summary>
    /// 思考努力程度（low/medium/high，默认medium�?    /// </summary>
    public string ReasoningEffort { get; set; } = "medium";

    /// <summary>
    /// 温度参数（默�?.1，输出更确定�?    /// </summary>
    public float Temperature { get; set; } = 0.1f;

    /// <summary>
    /// 最大token�?    /// </summary>
    public int MaxTokens { get; set; } = 4096;

    /// <summary>
    /// 自定义系统提示词（为null则使用默认）
    /// </summary>
    public string? CustomSystemPrompt { get; set; }

    /// <summary>
    /// 自定义JSON格式化提示词（为null则使用默认）
    /// </summary>
    public string? CustomJsonPrompt { get; set; }

    /// <summary>
    /// 自定义实体类格式化提示词（为null则使用默认）
    /// </summary>
    public string? CustomEntityPrompt { get; set; }
}

/// <summary>
/// LLM格式化器
/// 使用大语言模型解析和格式化WHOIS数据
/// </summary>
public class LlmFormatter : IWhoisFormatter
{
    private readonly LlmFormatterOptions _options;
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public LlmFormatter(LlmFormatterOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrEmpty(_options.ApiKey))
            throw new ArgumentException("API key is required", nameof(options));

        _httpClient = httpClient ?? new HttpClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(120);

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
    }

    /// <summary>
    /// 使用LLM格式化为JSON
    /// </summary>
    public async Task<FormattedResult> FormatAsync(WhoisResponse response)
    {
        var systemPrompt = _options.CustomSystemPrompt ?? Prompts.SystemPrompt;
        var userPrompt = (_options.CustomJsonPrompt ?? Prompts.JsonFormatPrompt)
            .Replace("{0}", response.RawResponse);

        var aiResponse = await CallLlmApiAsync(systemPrompt, userPrompt);

        try
        {
            var result = JsonSerializer.Deserialize<FormattedResult>(aiResponse, _jsonOptions);
            if (result != null)
            {
                result.RawJson = aiResponse;
                return result;
            }
        }
        catch
        {
            // 解析失败，返回原始JSON
        }

        return new FormattedResult
        {
            Domain = response.Domain,
            RawJson = aiResponse
        };
    }

    /// <summary>
    /// 使用LLM格式化为C#实体类代�?    /// </summary>
    public async Task<string> FormatAsEntityClassAsync(WhoisResponse response)
    {
        var systemPrompt = _options.CustomSystemPrompt ?? Prompts.SystemPrompt;
        var userPrompt = (_options.CustomEntityPrompt ?? Prompts.EntityFormatPrompt)
            .Replace("{0}", response.RawResponse);

        return await CallLlmApiAsync(systemPrompt, userPrompt);
    }

    private async Task<string> CallLlmApiAsync(string systemPrompt, string userPrompt)
    {
        var messages = new object[]
        {
            new { role = "system", content = systemPrompt },
            new { role = "user", content = userPrompt }
        };

        // 构建请求�?        object requestBody;

        if (_options.EnableThinking)
        {
            // 启用思考模�?            requestBody = new
            {
                model = _options.Model,
                messages,
                thinking = new { type = "enabled" },
                reasoning_effort = _options.ReasoningEffort,
                temperature = _options.Temperature,
                max_tokens = _options.MaxTokens,
                stream = false
            };
        }
        else
        {
            // 非思考模�?            requestBody = new
            {
                model = _options.Model,
                messages,
                temperature = _options.Temperature,
                max_tokens = _options.MaxTokens,
                stream = false
            };
        }

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _options.ApiEndpoint);
        httpRequest.Headers.Add("Authorization", $"Bearer {_options.ApiKey}");
        httpRequest.Content = JsonContent.Create(requestBody, options: _jsonOptions);

        using var response = await _httpClient.SendAsync(httpRequest);
        var responseJson = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"LLM API returned {response.StatusCode}: {responseJson}");
        }

        var apiResponse = JsonSerializer.Deserialize<LlmApiResponse>(responseJson, _jsonOptions);

        // 提取思考内容（如果有）
        var thinkingContent = apiResponse?.Choices?.FirstOrDefault()?.Message?.ReasoningContent;
        var content = apiResponse?.Choices?.FirstOrDefault()?.Message?.Content ?? string.Empty;

        return content;
    }

    #region API Response Models

    private class LlmApiResponse
    {
        [JsonPropertyName("choices")]
        public List<LlmChoice>? Choices { get; set; }
    }

    private class LlmChoice
    {
        [JsonPropertyName("message")]
        public LlmMessage? Message { get; set; }
    }

    private class LlmMessage
    {
        [JsonPropertyName("content")]
        public string? Content { get; set; }

        [JsonPropertyName("reasoning_content")]
        public string? ReasoningContent { get; set; }
    }

    #endregion
}
