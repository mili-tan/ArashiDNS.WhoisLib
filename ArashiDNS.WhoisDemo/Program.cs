using System.Text.Json;
using ArashiDNS.WhoisLib;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisDemo;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("ArashiDNS WHOIS/RDAP Demo");
        Console.WriteLine("=========================\n");

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

        Console.WriteLine($"Querying: {query}\n");

        var result = await Whois.LookupAsync(query, options);

        // Print trace if enabled
        if (traceMode && result.Trace.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("--- Trace ---");
            foreach (var entry in result.Trace)
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

        if (!result.IsSuccessful)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error: {result.ErrorMessage}");
            
            // Show detailed failure reasons from trace
            if (result.Trace.Count > 0)
            {
                Console.WriteLine("\nDetailed failures:");
                foreach (var entry in result.Trace.Where(t => !t.Success))
                {
                    Console.WriteLine($"  - {entry.Protocol}/{entry.Formatter}: {entry.Error ?? "Unknown error"}");
                }
            }
            
            Console.ResetColor();
            return;
        }

        // Show endpoint only
        if (showEndpoint)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Protocol: {result.UsedProtocol}");
            Console.WriteLine($"Formatter: {result.UsedFormatter}");
            Console.WriteLine($"Endpoint: {result.FinalEndpoint}");
            Console.ResetColor();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"Protocol: {result.UsedProtocol} | Formatter: {result.UsedFormatter}");
        Console.ResetColor();

        if (outputJson)
            OutputJson(result);
        else
            OutputFormatted(result);
    }

    static void PrintUsage()
    {
        Console.WriteLine("Usage: whois-demo <query> [options]");
        Console.WriteLine("\nQuery: domain, IP address, or ASN");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --json          Output as JSON");
        Console.WriteLine("  --rdap          Use RDAP only");
        Console.WriteLine("  --whois         Use WHOIS only");
        Console.WriteLine("  --llm           Use LLM formatter");
        Console.WriteLine("  -t              Trace mode (show each request step)");
        Console.WriteLine("  --endpoint      Show final endpoint only");
        Console.WriteLine("  --api-key KEY   DeepSeek API key");
        Console.WriteLine("  --model NAME    LLM model name");
        Console.WriteLine("  --think         Enable LLM thinking");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  whois-demo google.com");
        Console.WriteLine("  whois-demo google.com -t");
        Console.WriteLine("  whois-demo google.com --endpoint");
        Console.WriteLine("  whois-demo google.com --rdap --json");
        Console.WriteLine("  whois-demo google.com --llm");
    }

    static void OutputFormatted(QueryResult result)
    {
        var data = result.Data;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"\nDomain: {data.Domain}");
        Console.ResetColor();

        if (data.Registry?.Name is { Length: > 0 })
        {
            Console.WriteLine($"\nRegistry: {data.Registry.Name}");
            if (data.Registry.Website is { Length: > 0 })
                Console.WriteLine($"  Website: {data.Registry.Website}");
        }

        if (data.Registrar?.Name is { Length: > 0 })
        {
            Console.WriteLine($"\nRegistrar: {data.Registrar.Name}");
            if (data.Registrar.IanaId is { Length: > 0 })
                Console.WriteLine($"  IANA ID: {data.Registrar.IanaId}");
            if (data.Registrar.Website is { Length: > 0 })
                Console.WriteLine($"  Website: {data.Registrar.Website}");
        }

        if (data.Privacy?.IsPrivate == true)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nPrivacy: YES ({data.Privacy.Provider})");
            Console.ResetColor();
        }

        if (data.Dates != null)
        {
            Console.WriteLine("\nDates:");
            if (data.Dates.Created.HasValue)
                Console.WriteLine($"  Created: {data.Dates.Created:yyyy-MM-dd}");
            if (data.Dates.Updated.HasValue)
                Console.WriteLine($"  Updated: {data.Dates.Updated:yyyy-MM-dd}");
            if (data.Dates.Expires.HasValue)
                Console.WriteLine($"  Expires: {data.Dates.Expires:yyyy-MM-dd}");
        }

        if (data.Contacts.Count > 0)
        {
            Console.WriteLine("\nContacts:");
            foreach (var c in data.Contacts)
            {
                Console.WriteLine($"  [{string.Join(", ", c.Roles)}]");
                if (c.Name is { Length: > 0 }) Console.WriteLine($"    Name: {c.Name}");
                if (c.Organization is { Length: > 0 }) Console.WriteLine($"    Org: {c.Organization}");
                if (c.Email is { Length: > 0 }) Console.WriteLine($"    Email: {c.Email}");
                if (c.Phone is { Length: > 0 }) Console.WriteLine($"    Phone: {c.Phone}");
                if (c.Country is { Length: > 0 }) Console.WriteLine($"    Country: {c.Country}");
            }
        }

        if (data.NameServers.Count > 0)
        {
            Console.WriteLine("\nName Servers:");
            foreach (var ns in data.NameServers) Console.WriteLine($"  - {ns}");
        }

        if (data.Dnssec != null)
        {
            Console.WriteLine("\nDNSSEC:");
            Console.WriteLine($"  Signed: {(data.Dnssec.Signed ? "Yes" : "No")}");
            Console.WriteLine($"  Delegation Signed: {(data.Dnssec.DelegationSigned ? "Yes" : "No")}");
            if (data.Dnssec.DsRecords.Count > 0)
            {
                Console.WriteLine("  DS Records:");
                foreach (var ds in data.Dnssec.DsRecords)
                    Console.WriteLine($"    KeyTag={ds.KeyTag}, Algorithm={ds.Algorithm}, DigestType={ds.DigestType}");
            }
        }
    }

    static void OutputJson(QueryResult result)
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
            Meta = new { result.UsedProtocol, result.UsedFormatter, result.FinalEndpoint }
        };

        Console.WriteLine(JsonSerializer.Serialize(output, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        }));
    }
}
