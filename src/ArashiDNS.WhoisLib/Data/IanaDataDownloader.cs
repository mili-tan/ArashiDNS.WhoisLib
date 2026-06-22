using System.Globalization;
using System.Net.Http;
using ArashiDNS.WhoisLib.Contracts.Models;

namespace ArashiDNS.WhoisLib.Data;

public static class IanaUrls
{
    public const string Registrars = "https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv";
    public const string Ipv4Allocations = "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv";
    public const string Ipv6Allocations = "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv";
    public const string AsAllocations = "https://www.iana.org/assignments/as-numbers/as-numbers-1.csv";
    public const string TldList = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
}

public class IanaDataDownloader
{
    private readonly HttpClient _httpClient;

    public IanaDataDownloader(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "WhoisLib/1.0");
    }

    public async Task<List<RegistrarEntry>> DownloadRegistrarsAsync()
    {
        var csv = await _httpClient.GetStringAsync(IanaUrls.Registrars);
        return ParseRegistrarCsv(csv);
    }

    public async Task<List<IpAllocation>> DownloadIpv4AllocationsAsync()
    {
        var csv = await _httpClient.GetStringAsync(IanaUrls.Ipv4Allocations);
        return ParseIpv4Csv(csv);
    }

    public async Task<List<IpAllocation>> DownloadIpv6AllocationsAsync()
    {
        var csv = await _httpClient.GetStringAsync(IanaUrls.Ipv6Allocations);
        return ParseIpv6Csv(csv);
    }

    public async Task<List<AsAllocation>> DownloadAsAllocationsAsync()
    {
        var csv = await _httpClient.GetStringAsync(IanaUrls.AsAllocations);
        return ParseAsCsv(csv);
    }

    public async Task<List<string>> DownloadTldListAsync()
    {
        var text = await _httpClient.GetStringAsync(IanaUrls.TldList);
        return text.Split('\n')
            .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'))
            .Select(line => line.Trim().ToLowerInvariant())
            .ToList();
    }

    private static List<RegistrarEntry> ParseRegistrarCsv(string csv)
    {
        var result = new List<RegistrarEntry>();
        var lines = csv.Split('\n');

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line)) continue;

            var fields = ParseCsvLine(line);
            if (fields.Length < 4) continue;

            result.Add(new RegistrarEntry
            {
                Id = fields[0].Trim('"'),
                Name = fields[1].Trim('"'),
                Status = fields[2].Trim('"'),
                RdapBaseUrl = fields[3].Trim('"')
            });
        }

        return result;
    }

    private static List<IpAllocation> ParseIpv4Csv(string csv)
    {
        var result = new List<IpAllocation>();
        var lines = csv.Split('\n');

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line)) continue;

            var fields = ParseCsvLine(line);
            if (fields.Length < 6) continue;

            var prefixStr = fields[0].Trim('"').Replace("/8", "");
            if (string.IsNullOrEmpty(prefixStr)) prefixStr = "0";

            result.Add(new IpAllocation
            {
                Prefix = prefixStr,
                PrefixLength = 8,
                Designation = fields[1].Trim('"'),
                WhoisServer = fields[3].Trim('"'),
                RdapUrl = fields[4].Trim('"'),
                Status = fields[5].Trim('"')
            });
        }

        return result;
    }

    private static List<IpAllocation> ParseIpv6Csv(string csv)
    {
        var result = new List<IpAllocation>();
        var lines = csv.Split('\n');

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line)) continue;

            var fields = ParseCsvLine(line);
            if (fields.Length < 6) continue;

            var prefix = fields[0].Trim('"');
            var prefixLength = ExtractPrefixLength(prefix);

            result.Add(new IpAllocation
            {
                Prefix = prefix,
                PrefixLength = prefixLength,
                Designation = fields[1].Trim('"'),
                WhoisServer = fields[3].Trim('"'),
                RdapUrl = fields[4].Trim('"'),
                Status = fields[5].Trim('"')
            });
        }

        return result;
    }

    private static List<AsAllocation> ParseAsCsv(string csv)
    {
        var result = new List<AsAllocation>();
        var lines = csv.Split('\n');

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrEmpty(line)) continue;

            var fields = ParseCsvLine(line);
            if (fields.Length < 4) continue;

            var numberField = fields[0].Trim('"');
            long start, end;

            if (numberField.Contains('-'))
            {
                var parts = numberField.Split('-');
                start = long.Parse(parts[0]);
                end = long.Parse(parts[1]);
            }
            else
            {
                start = end = long.Parse(numberField);
            }

            result.Add(new AsAllocation
            {
                RangeStart = start,
                RangeEnd = end,
                Description = fields[1].Trim('"'),
                WhoisServer = fields[2].Trim('"'),
                RdapUrl = fields[3].Trim('"')
            });
        }

        return result;
    }

    private static int ExtractPrefixLength(string prefix)
    {
        var slashIndex = prefix.IndexOf('/');
        if (slashIndex >= 0 && int.TryParse(prefix.AsSpan(slashIndex + 1), out var length))
            return length;
        return 0;
    }

    private static string[] ParseCsvLine(string line)
    {
        var fields = new List<string>();
        bool inQuotes = false;
        int start = 0;

        for (int i = 0; i < line.Length; i++)
        {
            if (line[i] == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (line[i] == ',' && !inQuotes)
            {
                fields.Add(line[start..i]);
                start = i + 1;
            }
        }

        fields.Add(line[start..]);
        return fields.ToArray();
    }
}
