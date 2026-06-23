using System.Text;
using System.Text.Json;
using ArashiDNS.WhoisLib;
using ArashiDNS.WhoisLib.Contracts.Models;
using McMaster.Extensions.CommandLineUtils;

namespace ArashiDNS.WhoisDemo;

class Program
{
    static Task<int> Main(string[] args) => CommandLineApplication.ExecuteAsync<WhoisCommand>(args);
}

[Command(Name = "whois", Description = "WHOIS/RDAP lookup tool")]
[HelpOption("-h|--help")]
class WhoisCommand
{
    [Argument(0, "query", "Domain, IP address, or ASN to query")]
    public string Query { get; set; } = "";

    [Option("-j|--json", "Output as JSON", CommandOptionType.NoValue)]
    public bool OutputJson { get; set; }

    [Option("--raw", "Output raw WHOIS/RDAP response", CommandOptionType.NoValue)]
    public bool OutputRaw { get; set; }

    [Option("--rdap", "Use RDAP (optionally specify server URL)", CommandOptionType.SingleOrNoValue)]
    public string? RdapServer { get; set; }

    [Option("--whois", "Use WHOIS (optionally specify server)", CommandOptionType.SingleOrNoValue)]
    public string? WhoisServer { get; set; }

    [Option("--llm", "Use LLM formatter (optionally specify API key)", CommandOptionType.SingleOrNoValue)]
    public string? LlmApiKey { get; set; }

    [Option("-t|--trace", "Show trace information", CommandOptionType.NoValue)]
    public bool TraceMode { get; set; }

    [Option("--endpoint", "Show endpoint only", CommandOptionType.NoValue)]
    public bool ShowEndpoint { get; set; }

    [Option("--model", "LLM model name", CommandOptionType.SingleValue)]
    public string? Model { get; set; }

    [Option("--think", "Enable LLM thinking mode", CommandOptionType.NoValue)]
    public bool EnableThinking { get; set; }

    private async Task<int> OnExecuteAsync(IConsole console)
    {
        if (string.IsNullOrEmpty(Query))
        {
            console.Error.WriteLine("Error: Query parameter is required.");
            return 1;
        }

        var options = new WhoisClientOptions
        {
            Strategy = QueryStrategy.RdapFirst,
            LlmApiKey = LlmApiKey,
            LlmModel = Model,
            LlmEnableThinking = EnableThinking,
            CustomRdapEndpoint = RdapServer,
            CustomWhoisServer = WhoisServer
        };

        // Determine strategy based on options
        if (!string.IsNullOrEmpty(RdapServer))
            options.Strategy = QueryStrategy.RdapTraditionOnly;
        else if (!string.IsNullOrEmpty(WhoisServer))
            options.Strategy = QueryStrategy.WhoisTraditionOnly;
        else if (LlmApiKey != null) // --llm was specified (with or without value)
            options.Strategy = QueryStrategy.WhoisLlmOnly;

        var result = await Whois.LookupAsync(Query, options);

        List<object>? traceData = null;
        if (TraceMode && result.Trace.Count > 0)
        {
            traceData = result.Trace.Select(t => (object)new
            {
                status = t.Success ? "ok" : "fail",
                protocol = t.Protocol,
                formatter = t.Formatter,
                endpoint = t.Endpoint,
                error = t.Error
            }).ToList();
        }

        if (!result.IsSuccessful)
        {
            if (OutputJson)
            {
                var errorOutput = new { error = result.ErrorMessage, trace = traceData };
                Console.WriteLine(JsonSerializer.Serialize(errorOutput, new JsonSerializerOptions { WriteIndented = true }));
            }
            else
            {
                if (traceData != null) OutputYamlTrace(result.Trace);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                Console.ResetColor();
            }
            return 1;
        }

        if (ShowEndpoint)
        {
            if (OutputJson)
            {
                var endpointOutput = new { protocol = result.UsedProtocol, formatter = result.UsedFormatter, endpoint = result.FinalEndpoint };
                Console.WriteLine(JsonSerializer.Serialize(endpointOutput, new JsonSerializerOptions { WriteIndented = true }));
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"Protocol: {result.UsedProtocol}");
                Console.WriteLine($"Formatter: {result.UsedFormatter}");
                Console.WriteLine($"Endpoint: {result.FinalEndpoint}");
                Console.ResetColor();
            }
            return 0;
        }

        if (OutputRaw)
        {
            Console.Write(result.RawResponse);
            return 0;
        }

        if (OutputJson)
            OutputJsonResult(result, traceData);
        else
        {
            if (traceData != null) OutputYamlTrace(result.Trace);
            OutputYaml(result);
        }

        return 0;
    }

    private static void OutputYamlTrace(List<TraceEntry> trace)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("Trace:");
        foreach (var entry in trace)
        {
            var status = entry.Success ? "OK" : "FAIL";
            var color = entry.Success ? ConsoleColor.Green : ConsoleColor.Red;
            Console.ForegroundColor = color;
            Console.Write($"  - Status: {status}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"  Protocol: {entry.Protocol}  Formatter: {entry.Formatter}");
            if (!string.IsNullOrEmpty(entry.Endpoint))
                Console.Write($"  Endpoint: {EscapeYaml(entry.Endpoint)}");
            if (!string.IsNullOrEmpty(entry.Error))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"  Error: {EscapeYaml(entry.Error)}");
            }
            Console.WriteLine();
        }
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void OutputYaml(QueryResult result)
    {
        var data = result.Data;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Domain: {EscapeYaml(data.Domain)}");
        Console.ResetColor();

        if (data.Registry?.Name is { Length: > 0 })
        {
            Console.WriteLine("Registry:");
            Console.WriteLine($"  Name: {EscapeYaml(data.Registry.Name)}");
            if (data.Registry.Website is { Length: > 0 })
                Console.WriteLine($"  Website: {EscapeYaml(data.Registry.Website)}");
            if (data.Registry.WhoisServer is { Length: > 0 })
                Console.WriteLine($"  WhoisServer: {EscapeYaml(data.Registry.WhoisServer)}");
        }

        if (data.Registrar?.Name is { Length: > 0 })
        {
            Console.WriteLine("Registrar:");
            Console.WriteLine($"  Name: {EscapeYaml(data.Registrar.Name)}");
            if (data.Registrar.IanaId is { Length: > 0 })
                Console.WriteLine($"  IanaId: {EscapeYaml(data.Registrar.IanaId)}");
            if (data.Registrar.Website is { Length: > 0 })
                Console.WriteLine($"  Website: {EscapeYaml(data.Registrar.Website)}");
        }

        if (data.Privacy?.IsPrivate == true)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Privacy:");
            Console.WriteLine("  IsPrivate: true");
            if (data.Privacy.Provider is { Length: > 0 })
                Console.WriteLine($"  Provider: {EscapeYaml(data.Privacy.Provider)}");
            Console.ResetColor();
        }

        if (data.Dates != null)
        {
            Console.WriteLine("Dates:");
            if (data.Dates.Created.HasValue)
                Console.WriteLine($"  Created: {data.Dates.Created:yyyy-MM-dd}");
            if (data.Dates.Updated.HasValue)
                Console.WriteLine($"  Updated: {data.Dates.Updated:yyyy-MM-dd}");
            if (data.Dates.Expires.HasValue)
                Console.WriteLine($"  Expires: {data.Dates.Expires:yyyy-MM-dd}");
        }

        if (data.Contacts.Count > 0)
        {
            Console.WriteLine("Contacts:");
            foreach (var c in data.Contacts)
            {
                Console.WriteLine($"  - Roles: [{string.Join(", ", c.Roles)}]");
                if (c.Name is { Length: > 0 }) Console.WriteLine($"    Name: {EscapeYaml(c.Name)}");
                if (c.Organization is { Length: > 0 }) Console.WriteLine($"    Organization: {EscapeYaml(c.Organization)}");
                if (c.Email is { Length: > 0 }) Console.WriteLine($"    Email: {EscapeYaml(c.Email)}");
                if (c.Phone is { Length: > 0 }) Console.WriteLine($"    Phone: {EscapeYaml(c.Phone)}");
                if (c.Country is { Length: > 0 }) Console.WriteLine($"    Country: {EscapeYaml(c.Country)}");
            }
        }

        if (data.NameServers.Count > 0)
        {
            Console.WriteLine("NameServers:");
            foreach (var ns in data.NameServers)
                Console.WriteLine($"  - {EscapeYaml(ns)}");
        }

        if (data.Statuses.Count > 0)
        {
            Console.WriteLine("Status:");
            foreach (var s in data.Statuses)
                Console.WriteLine($"  - {EscapeYaml(s)}");
        }

        if (data.Dnssec != null)
        {
            Console.WriteLine("Dnssec:");
            Console.WriteLine($"  Signed: {data.Dnssec.Signed.ToString().ToLower()}");
            Console.WriteLine($"  DelegationSigned: {data.Dnssec.DelegationSigned.ToString().ToLower()}");
            if (data.Dnssec.DsRecords.Count > 0)
            {
                Console.WriteLine("  DsRecords:");
                foreach (var ds in data.Dnssec.DsRecords)
                {
                    Console.WriteLine($"    - KeyTag: {ds.KeyTag}");
                    Console.WriteLine($"      Algorithm: {ds.Algorithm}");
                    Console.WriteLine($"      DigestType: {ds.DigestType}");
                }
            }
        }

        Console.WriteLine("Meta:");
        Console.WriteLine($"  Protocol: {EscapeYaml(result.UsedProtocol)}");
        Console.WriteLine($"  Formatter: {EscapeYaml(result.UsedFormatter)}");
        Console.WriteLine($"  Endpoint: {EscapeYaml(result.FinalEndpoint ?? "")}");
    }

    private static string EscapeYaml(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        if (value.Contains(':') || value.Contains('#') || value.Contains('"') ||
            value.Contains('\n') || value.StartsWith(' ') || value.EndsWith(' '))
        {
            return $"\"{value.Replace("\"", "\\\"").Replace("\n", "\\n")}\"";
        }
        return value;
    }

    private static void OutputJsonResult(QueryResult result, List<object>? traceData)
    {
        var output = new
        {
            result.Data.Domain,
            result.Data.Registry,
            result.Data.Registrar,
            result.Data.Privacy,
            result.Data.Dates,
            Contacts = result.Data.Contacts,
            result.Data.NameServers,
            result.Data.Statuses,
            result.Data.Dnssec,
            Trace = traceData,
            Meta = new { result.UsedProtocol, result.UsedFormatter, result.FinalEndpoint }
        };

        Console.WriteLine(JsonSerializer.Serialize(output, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        }));
    }
}
