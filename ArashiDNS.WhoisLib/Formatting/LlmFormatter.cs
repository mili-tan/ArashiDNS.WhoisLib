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
    public bool? EnableThinking { get; set; }
    public string ReasoningEffort { get; set; } = "high";
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
        var prompt = (_options.CustomJsonPrompt ?? Prompts.JsonFormatPrompt)
            .Replace("{0}", response.RawResponse);

        var json = await CallApiAsync(prompt);

        var result = TryDeserialize<FormattedResult>(json);
        if (result != null)
        {
            result.RawJson = json;
            return result;
        }

        return new FormattedResult { Domain = response.Domain, RawJson = json };
    }

    public async Task<string> FormatAsEntityClassAsync(WhoisResponse response)
    {
        var prompt = (_options.CustomEntityPrompt ?? Prompts.EntityFormatPrompt)
            .Replace("{0}", response.RawResponse);

        return await CallApiAsync(prompt);
    }

    private async Task<string> CallApiAsync(string userPrompt)
    {
        var systemPrompt = _options.CustomSystemPrompt ?? Prompts.SystemPrompt;

        // Build request body
        var body = new Dictionary<string, object?>
        {
            ["model"] = _options.Model,
            ["messages"] = new[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userPrompt }
            },
            ["max_tokens"] = _options.MaxTokens,
            ["stream"] = false
        };

        // Add thinking config if specified
        if (_options.EnableThinking.HasValue)
        {
            body["thinking"] = new { type = _options.EnableThinking.Value ? "enabled" : "disabled" };

            if (_options.EnableThinking.Value)
                body["reasoning_effort"] = _options.ReasoningEffort;
        }
        else
        {
            body["temperature"] = _options.Temperature;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.ApiEndpoint);
        request.Headers.Add("Authorization", $"Bearer {_options.ApiKey}");
        request.Content = JsonContent.Create(body, options: _jsonOptions);

        using var response = await _httpClient.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"LLM API error {response.StatusCode}: {json}");

        return TryDeserialize<LlmResponse>(json)?.Choices?.FirstOrDefault()?.Message?.Content ?? string.Empty;
    }

    private T? TryDeserialize<T>(string json)
    {
        try { return JsonSerializer.Deserialize<T>(json, _jsonOptions); }
        catch { return default; }
    }

    private class LlmResponse
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
    }
}
