using System.Text.Json;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;
using ArashiDNS.WhoisLib.Core;
using ArashiDNS.WhoisLib.Data;
using ArashiDNS.WhoisLib.Data.Cache;
using ArashiDNS.WhoisLib.Formatting;
using ArashiDNS.WhoisLib.ServerDiscovery;

namespace ArashiDNS.WhoisDemo;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("WHOIS/RDAP Lookup Demo");
        Console.WriteLine("======================\n");

        if (args.Length == 0)
        {
            PrintUsage();
            return;
        }

        var query = args[0];
        var outputJson = args.Contains("--json");
        var useRdap = args.Contains("--rdap");
        var enableThinking = args.Contains("--think");
        string? apiKey = null;
        string? model = null;
        string? apiEndpoint = null;

        // 解析命令行参�?        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--llm":
                case "--ai":
                    if (i + 1 < args.Length) apiKey = args[++i];
                    break;
                case "--model":
                    if (i + 1 < args.Length) model = args[++i];
                    break;
                case "--endpoint":
                    if (i + 1 < args.Length) apiEndpoint = args[++i];
                    break;
            }
        }

        try
        {
            var cache = new FileCacheProvider();
            var downloader = new IanaDataDownloader();
            var registrarProvider = new RegistrarListProvider(cache, downloader);
            var ipProvider = new IpAllocationProvider(cache, downloader);

            var knownLookup = new KnownServerLookup();
            var dnsLookup = new DnsServerLookup();
            var ianaLookup = new IanaServerLookup();

            var serverFinder = new CompositeServerFinder(knownLookup, dnsLookup, ianaLookup, ipProvider);
            var whoisClient = new WhoisClient(serverFinder);
            var rdapClient = new RdapClient();

            Console.WriteLine($"Querying: {query} (Protocol: {(useRdap ? "RDAP" : "WHOIS")})\n");

            WhoisResponse response;

            if (useRdap)
            {
                response = await rdapClient.QueryAsync(query);
            }
            else
            {
                response = await whoisClient.QueryAsync(query);

                if (!response.IsSuccessful)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"WHOIS failed: {response.ErrorMessage}");
                    Console.WriteLine("Trying RDAP...\n");
                    Console.ResetColor();

                    response = await rdapClient.QueryAsync(query);
                }
            }

            if (!response.IsSuccessful)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {response.ErrorMessage}");
                Console.ResetColor();
                return;
            }

            // 选择格式化器
            IWhoisFormatter formatter;
            if (!string.IsNullOrEmpty(apiKey))
            {
                var options = new LlmFormatterOptions
                {
                    ApiKey = apiKey,
                    EnableThinking = enableThinking
                };

                if (!string.IsNullOrEmpty(model))
                    options.Model = model;

                if (!string.IsNullOrEmpty(apiEndpoint))
                    options.ApiEndpoint = apiEndpoint;

                formatter = new LlmFormatter(options);
            }
            else
            {
                formatter = new TraditionalFormatter(registrarProvider);
            }

            var result = await formatter.FormatAsync(response);

            if (outputJson || !string.IsNullOrEmpty(apiKey))
            {
                OutputJson(result);
            }
            else
            {
                OutputFormatted(result, response);
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Fatal error: {ex.Message}");
            Console.ResetColor();
        }
    }

    static void PrintUsage()
    {
        Console.WriteLine("Usage: whois-demo <domain|ip|asn> [options]");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --json              Output as JSON");
        Console.WriteLine("  --rdap              Use RDAP protocol");
        Console.WriteLine("  --llm <api-key>     Use LLM for formatting");
        Console.WriteLine("  --model <name>      LLM model name (default: deepseek-v4-flash)");
        Console.WriteLine("  --endpoint <url>    LLM API endpoint");
        Console.WriteLine("  --think             Enable LLM thinking mode");
        Console.WriteLine("\nExamples:");
        Console.WriteLine("  whois-demo google.com");
        Console.WriteLine("  whois-demo google.com --rdap");
        Console.WriteLine("  whois-demo google.com --json");
        Console.WriteLine("  whois-demo google.com --llm sk-xxx");
        Console.WriteLine("  whois-demo google.com --llm sk-xxx --model deepseek-v4-pro --think");
    }

    static void OutputFormatted(FormattedResult result, WhoisResponse response)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Domain: {result.Domain}");
        Console.ResetColor();

        if (result.Registry != null && !string.IsNullOrEmpty(result.Registry.Name))
        {
            Console.WriteLine($"\nRegistry: {result.Registry.Name}");
            if (!string.IsNullOrEmpty(result.Registry.Website))
                Console.WriteLine($"  Website: {result.Registry.Website}");
            if (!string.IsNullOrEmpty(result.Registry.WhoisServer))
                Console.WriteLine($"  WHOIS Server: {result.Registry.WhoisServer}");
        }

        if (result.Registrar != null && !string.IsNullOrEmpty(result.Registrar.Name))
        {
            Console.WriteLine($"\nRegistrar: {result.Registrar.Name}");
            if (!string.IsNullOrEmpty(result.Registrar.IanaId))
                Console.WriteLine($"  IANA ID: {result.Registrar.IanaId}");
            if (!string.IsNullOrEmpty(result.Registrar.Website))
                Console.WriteLine($"  Website: {result.Registrar.Website}");
            if (!string.IsNullOrEmpty(result.Registrar.WhoisServer))
                Console.WriteLine($"  WHOIS Server: {result.Registrar.WhoisServer}");
        }

        if (result.Privacy?.IsPrivate == true)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nPrivacy Protection: YES");
            if (!string.IsNullOrEmpty(result.Privacy.Provider))
                Console.WriteLine($"  Provider: {result.Privacy.Provider}");
            Console.ResetColor();
        }

        if (result.Dates != null)
        {
            Console.WriteLine("\nDates:");
            if (result.Dates.Created.HasValue)
                Console.WriteLine($"  Created: {result.Dates.Created:yyyy-MM-dd}");
            if (result.Dates.Updated.HasValue)
                Console.WriteLine($"  Updated: {result.Dates.Updated:yyyy-MM-dd}");
            if (result.Dates.Expires.HasValue)
                Console.WriteLine($"  Expires: {result.Dates.Expires:yyyy-MM-dd}");
        }

        if (result.Contacts.Count > 0)
        {
            Console.WriteLine("\nContacts:");
            foreach (var contact in result.Contacts)
            {
                Console.WriteLine($"  [{string.Join(", ", contact.Roles)}]");
                if (!string.IsNullOrEmpty(contact.Name))
                    Console.WriteLine($"    Name: {contact.Name}");
                if (!string.IsNullOrEmpty(contact.Organization))
                    Console.WriteLine($"    Organization: {contact.Organization}");
                if (!string.IsNullOrEmpty(contact.Email))
                    Console.WriteLine($"    Email: {contact.Email}");
                if (!string.IsNullOrEmpty(contact.Phone))
                    Console.WriteLine($"    Phone: {contact.Phone}");
                if (!string.IsNullOrEmpty(contact.Country))
                    Console.WriteLine($"    Country: {contact.Country}");
            }
        }

        if (result.NameServers.Count > 0)
        {
            Console.WriteLine("\nName Servers:");
            foreach (var ns in result.NameServers)
                Console.WriteLine($"  - {ns}");
        }

        if (result.Statuses.Count > 0)
        {
            Console.WriteLine("\nStatus:");
            foreach (var status in result.Statuses)
                Console.WriteLine($"  - {status}");
        }

        Console.WriteLine($"\nQuery Details:");
        Console.WriteLine($"  Server: {response.WhoisServer}");
        if (response.ReferralChain.Count > 1)
            Console.WriteLine($"  Referral Chain: {string.Join(" -> ", response.ReferralChain)}");
    }

    static void OutputJson(FormattedResult result)
    {
        var json = result.RawJson ?? JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        try
        {
            var jsonDoc = JsonDocument.Parse(json);
            Console.WriteLine(JsonSerializer.Serialize(jsonDoc, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            Console.WriteLine(json);
        }
    }
}
