using System.Net.Sockets;
using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.ServerDiscovery;

public class IanaServerLookup : IServerFinder
{
    private const string IanaWhoisServer = "whois.iana.org";
    private const int WhoisPort = 43;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static readonly Regex WhoisServerRegex = new(
        @"whois:\s+(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<string?> FindServerAsync(string query, WhoisQueryType queryType)
    {
        var ianaQuery = queryType switch
        {
            WhoisQueryType.Domain => ExtractTld(query),
            WhoisQueryType.Asn => query,
            WhoisQueryType.Ipv4 => query,
            WhoisQueryType.Ipv6 => query,
            _ => query
        };

        if (string.IsNullOrEmpty(ianaQuery))
            return null;

        try
        {
            using var client = new TcpClient();
            using var cts = new CancellationTokenSource(Timeout);
            await client.ConnectAsync(IanaWhoisServer, WhoisPort, cts.Token);

            using var stream = client.GetStream();
            using var writer = new StreamWriter(stream) { AutoFlush = true };
            using var reader = new StreamReader(stream);

            await writer.WriteLineAsync(ianaQuery);

            string? server = null;
            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                var match = WhoisServerRegex.Match(line);
                if (match.Success)
                {
                    server = match.Groups[1].Value;
                    break;
                }
            }

            return server;
        }
        catch
        {
            return null;
        }
    }

    private static string ExtractTld(string domain)
    {
        var parts = domain.TrimEnd('.').Split('.');
        if (parts.Length < 2)
            return string.Empty;

        return parts[^1].ToLowerInvariant();
    }
}
