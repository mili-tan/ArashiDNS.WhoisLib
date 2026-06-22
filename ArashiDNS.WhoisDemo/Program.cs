using System.Text;
using System.Text.Json;
using ArashiDNS.WhoisLib;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisDemo;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return;
        }

        var query = args[0];
        var outputJson = args.Contains("--json");
        var useRdap = args.Contains("--rdap");
        var useWhois = args.Contains("--whois");
        var useLlm = args.Contains("--llm");
        var traceMode = args.Contains("-t");
        var showEndpoint = args.Contains("--endpoint");
        var enableThinking = args.Contains("--think");
        string? apiKey = null;
        string? model = null;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--api-key" && i + 1 < args.Length)
                apiKey = args[++i];
            if (args[i] == "--model" && i + 1 < args.Length)
                model = args[++i];
        }

        var options = new WhoisClientOptions
        {
            Strategy = QueryStrategy.RdapFirst,
            LlmApiKey = apiKey,
            LlmModel = model,
            LlmEnableThinking = enableThinking
        };

        if (useRdap) options.Strategy = QueryStrategy.RdapTraditionOnly;
        else if (useWhois) options.Strategy = QueryStrategy.WhoisTraditionOnly;
        else if (useLlm) options.Strategy = QueryStrategy.WhoisLlmOnly;

        var result = await Whois.LookupAsync(query, options);

        List<object>? traceData = null;
        if (traceMode && result.Trace.Count > 0)
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
            if (outputJson)
            {
                var errorOutput = new { error = result.ErrorMessage, trace = traceData };
                Console.WriteLine(JsonSerializer.Serialize(errorOutput, new JsonSerializerOptions { WriteIndented = true }));
            }
            else
            {
                if (traceData != null) OutputYamlTrace(result.Trace);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {result.ErrorMessage}");
                Console.ResetColor();
            }
            return;
        }

        if (showEndpoint)
        {
            if (outputJson)
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
            return;
        }

        if (outputJson)
            OutputJson(result, traceData);
        else
        {
            if (traceData != null) OutputYamlTrace(result.Trace);
            OutputYaml(result);
        }
    }

    static void PrintUsage()
    {
        Console.WriteLine("ArashiDNS WHOIS/RDAP Lookup");
        Console.WriteLine("==========================\n");
        Console.WriteLine("Usage: whois-demo <query> [options]\n");
        Console.WriteLine("Query: domain, IP address, or ASN\n");
        Console.WriteLine("Options:");
        Console.WriteLine("  --json          Output as JSON");
        Console.WriteLine("  --rdap          Use RDAP only");
        Console.WriteLine("  --whois         Use WHOIS only");
        Console.WriteLine("  --llm           Use LLM formatter");
        Console.WriteLine("  -t              Trace mode");
        Console.WriteLine("  --endpoint      Show endpoint only");
        Console.WriteLine("  --api-key KEY   API key for LLM");
        Console.WriteLine("  --model NAME    LLM model name");
        Console.WriteLine("  --think         Enable LLM thinking\n");
        Console.WriteLine("Examples:");
        Console.WriteLine("  whois-demo google.com");
        Console.WriteLine("  whois-demo google.com --rdap -t");
        Console.WriteLine("  whois-demo google.com --json");
    }

    static void OutputYamlTrace(List<TraceEntry> trace)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("--- Trace ---");
        foreach (var entry in trace)
        {
            var status = entry.Success ? "OK" : "FAIL";
            var color = entry.Success ? ConsoleColor.Green : ConsoleColor.Red;
            Console.ForegroundColor = color;
            Console.Write($"  [{status}]");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" {entry.Protocol}/{entry.Formatter}");
            if (!string.IsNullOrEmpty(entry.Endpoint))
                Console.Write($" -> {entry.Endpoint}");
            if (!string.IsNullOrEmpty(entry.Error))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($" ({entry.Error})");
            }
            Console.WriteLine();
        }
        Console.ResetColor();
        Console.WriteLine();
    }

    static void OutputYaml(QueryResult result)
    {
        var data = result.Data;
        var sb = new StringBuilder();

        sb.AppendLine($"Query: {EscapeYaml(result.UsedProtocol)}");
        sb.AppendLine($"Formatter: {EscapeYaml(result.UsedFormatter)}");
        sb.AppendLine($"Endpoint: {EscapeYaml(result.FinalEndpoint ?? "")}");
        sb.AppendLine($"Domain: {EscapeYaml(data.Domain)}");

        if (data.Registry?.Name is { Length: > 0 })
        {
            sb.AppendLine("Registry:");
            sb.AppendLine($"  Name: {EscapeYaml(data.Registry.Name)}");
            if (data.Registry.Website is { Length: > 0 })
                sb.AppendLine($"  Website: {EscapeYaml(data.Registry.Website)}");
            if (data.Registry.WhoisServer is { Length: > 0 })
                sb.AppendLine($"  WhoisServer: {EscapeYaml(data.Registry.WhoisServer)}");
        }

        if (data.Registrar?.Name is { Length: > 0 })
        {
            sb.AppendLine("Registrar:");
            sb.AppendLine($"  Name: {EscapeYaml(data.Registrar.Name)}");
            if (data.Registrar.IanaId is { Length: > 0 })
                sb.AppendLine($"  IanaId: {EscapeYaml(data.Registrar.IanaId)}");
            if (data.Registrar.Website is { Length: > 0 })
                sb.AppendLine($"  Website: {EscapeYaml(data.Registrar.Website)}");
        }

        if (data.Privacy?.IsPrivate == true)
        {
            sb.AppendLine("Privacy:");
            sb.AppendLine("  IsPrivate: true");
            if (data.Privacy.Provider is { Length: > 0 })
                sb.AppendLine($"  Provider: {EscapeYaml(data.Privacy.Provider)}");
        }

        if (data.Dates != null)
        {
            sb.AppendLine("Dates:");
            if (data.Dates.Created.HasValue)
                sb.AppendLine($"  Created: {data.Dates.Created:yyyy-MM-dd}");
            if (data.Dates.Updated.HasValue)
                sb.AppendLine($"  Updated: {data.Dates.Updated:yyyy-MM-dd}");
            if (data.Dates.Expires.HasValue)
                sb.AppendLine($"  Expires: {data.Dates.Expires:yyyy-MM-dd}");
        }

        if (data.Contacts.Count > 0)
        {
            sb.AppendLine("Contacts:");
            foreach (var c in data.Contacts)
            {
                sb.AppendLine($"  - Roles: [{string.Join(", ", c.Roles)}]");
                if (c.Name is { Length: > 0 }) sb.AppendLine($"    Name: {EscapeYaml(c.Name)}");
                if (c.Organization is { Length: > 0 }) sb.AppendLine($"    Organization: {EscapeYaml(c.Organization)}");
                if (c.Email is { Length: > 0 }) sb.AppendLine($"    Email: {EscapeYaml(c.Email)}");
                if (c.Phone is { Length: > 0 }) sb.AppendLine($"    Phone: {EscapeYaml(c.Phone)}");
                if (c.Country is { Length: > 0 }) sb.AppendLine($"    Country: {EscapeYaml(c.Country)}");
            }
        }

        if (data.NameServers.Count > 0)
        {
            sb.AppendLine("NameServers:");
            foreach (var ns in data.NameServers)
                sb.AppendLine($"  - {EscapeYaml(ns)}");
        }

        if (data.Statuses.Count > 0)
        {
            sb.AppendLine("Status:");
            foreach (var s in data.Statuses)
                sb.AppendLine($"  - {EscapeYaml(s)}");
        }

        if (data.Dnssec != null)
        {
            sb.AppendLine("Dnssec:");
            sb.AppendLine($"  Signed: {data.Dnssec.Signed.ToString().ToLower()}");
            sb.AppendLine($"  DelegationSigned: {data.Dnssec.DelegationSigned.ToString().ToLower()}");
            if (data.Dnssec.DsRecords.Count > 0)
            {
                sb.AppendLine("  DsRecords:");
                foreach (var ds in data.Dnssec.DsRecords)
                {
                    sb.AppendLine($"    - KeyTag: {ds.KeyTag}");
                    sb.AppendLine($"      Algorithm: {ds.Algorithm}");
                    sb.AppendLine($"      DigestType: {ds.DigestType}");
                }
            }
        }

        Console.WriteLine(sb.ToString());
    }

    static string EscapeYaml(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        if (value.Contains(':') || value.Contains('#') || value.Contains('"') ||
            value.Contains('\n') || value.StartsWith(' ') || value.EndsWith(' '))
        {
            return $"\"{value.Replace("\"", "\\\"").Replace("\n", "\\n")}\"";
        }
        return value;
    }

    static void OutputJson(QueryResult result, List<object>? traceData)
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
