using System.Text.RegularExpressions;
using ArashiDNS.WhoisLib.Contracts;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Core;

public class WhoisClient : IWhoisClient
{
    private readonly IServerFinder _serverFinder;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
    private const int MaxReferrals = 5;

    private static readonly Regex ReferralRegex = new(
        @"(?:ReferralServer|Whois Server|refer|whois):\s*(?:whois://)?([^\s:\r\n]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public WhoisClient(IServerFinder serverFinder)
    {
        _serverFinder = serverFinder;
    }

    public async Task<WhoisResponse> QueryAsync(string query)
    {
        var queryType = DetectQueryType(query);
        return await QueryAsync(query, queryType);
    }

    public async Task<WhoisResponse> QueryAsync(string query, string server)
    {
        return await QueryWithReferralAsync(query, server, DetectQueryType(query));
    }

    public async Task<WhoisResponse> QueryAsync(string query, WhoisQueryType queryType)
    {
        var server = await _serverFinder.FindServerAsync(query, queryType);
        if (string.IsNullOrEmpty(server))
        {
            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                IsSuccessful = false,
                ErrorMessage = $"Could not find WHOIS server for {query}"
            };
        }

        return await QueryWithReferralAsync(query, server, queryType);
    }

    private async Task<WhoisResponse> QueryWithReferralAsync(string query, string server, WhoisQueryType queryType)
    {
        var referralChain = new List<string>();
        var currentServer = server;
        string? rawResponse = null;

        for (int i = 0; i < MaxReferrals; i++)
        {
            if (string.IsNullOrEmpty(currentServer))
                break;

            referralChain.Add(currentServer);

            try
            {
                using var connection = new WhoisTcpConnection();
                var formattedQuery = FormatQuery(currentServer, query, queryType);
                rawResponse = await connection.QueryAsync(currentServer, formattedQuery, DefaultTimeout);

                var referralServer = ExtractReferral(rawResponse);
                if (string.IsNullOrEmpty(referralServer) || referralChain.Contains(referralServer))
                    break;

                currentServer = referralServer;
            }
            catch (Exception ex)
            {
                if (i == 0)
                {
                    return new WhoisResponse
                    {
                        Query = query,
                        QueryType = queryType,
                        WhoisServer = server,
                        ReferralChain = referralChain,
                        IsSuccessful = false,
                        ErrorMessage = $"Failed to query WHOIS server {currentServer}: {ex.Message}"
                    };
                }
                break;
            }
        }

        if (string.IsNullOrEmpty(rawResponse))
        {
            return new WhoisResponse
            {
                Query = query,
                QueryType = queryType,
                WhoisServer = server,
                ReferralChain = referralChain,
                IsSuccessful = false,
                ErrorMessage = "No response received from WHOIS server"
            };
        }

        return new WhoisResponse
        {
            Query = query,
            QueryType = queryType,
            RawResponse = rawResponse,
            WhoisServer = server,
            ReferralChain = referralChain,
            IsSuccessful = true
        };
    }

    private static string FormatQuery(string server, string query, WhoisQueryType queryType)
    {
        var normalizedServer = server.ToLowerInvariant();

        if (normalizedServer.Contains("verisign-grs.com"))
            return $"domain {query}";

        if (normalizedServer.Contains("arin.net"))
        {
            if (queryType == WhoisQueryType.Ipv4 || queryType == WhoisQueryType.Ipv6)
                return $"n + {query}";
            return query;
        }

        if (normalizedServer.Contains("ripe.net"))
            return query;

        if (normalizedServer.Contains("apnic.net"))
            return query;

        return query;
    }

    private static string? ExtractReferral(string response)
    {
        var match = ReferralRegex.Match(response);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static WhoisQueryType DetectQueryType(string query)
    {
        var normalized = query.Trim();

        if (normalized.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("as", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(normalized[2..], out _))
                return WhoisQueryType.Asn;
        }

        if (long.TryParse(normalized, out _))
            return WhoisQueryType.Asn;

        if (System.Net.IPAddress.TryParse(normalized, out var ip))
        {
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? WhoisQueryType.Ipv4
                : WhoisQueryType.Ipv6;
        }

        return WhoisQueryType.Domain;
    }
}
