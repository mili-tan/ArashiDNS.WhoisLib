using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Formatting;

public class LlmFormatterOptions
{
    public string ApiEndpoint { get; set; } = "https://api.deepseek.com/chat/completions";
    public string Model { get; set; } = "deepseek-v4-flash";
    public string ApiKey { get; set; } = string.Empty;
    public bool EnableThinking { get; set; } = false;
    public string ReasoningEffort { get; set; } = "medium";
    public float Temperature { get; set; } = 0.1f;
    public int MaxTokens { get; set; } = 4096;
    public string? CustomSystemPrompt { get; set; }
    public string? CustomJsonPrompt { get; set; }
    public string? CustomEntityPrompt { get; set; }
}

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
        catch { }

        return new FormattedResult
        {
            Domain = response.Domain,
            RawJson = aiResponse
        };
    }

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

        object requestBody = _options.EnableThinking
            ? new
            {
                model = _options.Model, messages,
                thinking = new { type = "enabled" },
                reasoning_effort = _options.ReasoningEffort,
                temperature = _options.Temperature,
                max_tokens = _options.MaxTokens,
                stream = false
            }
            : new
            {
                model = _options.Model, messages,
                temperature = _options.Temperature,
                max_tokens = _options.MaxTokens,
                stream = false
            };

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _options.ApiEndpoint);
        httpRequest.Headers.Add("Authorization", $"Bearer {_options.ApiKey}");
        httpRequest.Content = JsonContent.Create(requestBody, options: _jsonOptions);

        using var response = await _httpClient.SendAsync(httpRequest);
        var responseJson = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"LLM API returned {response.StatusCode}: {responseJson}");

        var apiResponse = JsonSerializer.Deserialize<LlmApiResponse>(responseJson, _jsonOptions);
        return apiResponse?.Choices?.FirstOrDefault()?.Message?.Content ?? string.Empty;
    }

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
}
