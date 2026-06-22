# Whois.Lib

A C# WHOIS lookup library that queries domain, IP, and ASN information with support for registry/registrar identification and AI-powered formatting.

## Features

- **Three-level WHOIS server discovery**: Known list → DNS lookup → IANA query
- **Registry (NIC) identification**: Automatic detection with official website
- **Registrar identification**: Using IANA Registrar IDs database
- **Privacy protection detection**: Identifies WHOIS privacy services
- **Contact merging**: Merges identical contact info with role array
- **AI formatting**: DeepSeek API integration for structured output
- **Local file caching**: IANA data cached for 7 days

## Project Structure

```
src/Whois.Lib/          # Core library
samples/Whois.Demo/     # Demo CLI application
```

## Usage

### CLI Demo

```bash
# Basic lookup
dotnet run --project samples/Whois.Demo -- google.com

# JSON output
dotnet run --project samples/Whois.Demo -- google.com --json

# AI-formatted output (requires DeepSeek API key)
dotnet run --project samples/Whois.Demo -- google.com --ai sk-your-api-key

# IP lookup
dotnet run --project samples/Whois.Demo -- 8.8.8.8

# ASN lookup
dotnet run --project samples/Whois.Demo -- AS15169
```

### Library Usage

```csharp
using Whois.Lib.Core;
using Whois.Lib.Data;
using Whois.Lib.Data.Cache;
using Whois.Lib.Detection;
using Whois.Lib.Formatting;
using Whois.Lib.ServerDiscovery;

// Initialize components
var cache = new FileCacheProvider();
var downloader = new IanaDataDownloader();
var registrarProvider = new RegistrarListProvider(cache, downloader);
var ipProvider = new IpAllocationProvider(cache, downloader);

var serverFinder = new CompositeServerFinder(
    new KnownServerLookup(),
    new DnsServerLookup(),
    new IanaServerLookup(),
    ipProvider);

var parser = new WhoisResponseParser();
var client = new WhoisClient(serverFinder, parser);

// Query WHOIS
var response = await client.QueryAsync("google.com");

// Detect privacy protection
var privacyDetector = new PrivacyDetector();
response.Privacy = privacyDetector.Detect(response);

// Identify registry/registrar
var registryIdentifier = new RegistryIdentifier(registrarProvider);
response.Registry = await registryIdentifier.IdentifyRegistryAsync(response);
response.Registrar = await registryIdentifier.IdentifyRegistrarAsync(response);

// Get merged contacts
var contacts = response.Contacts.GetMergedContacts();

// AI formatting (requires API key)
var formatter = new DeepSeekFormatter("sk-your-api-key");
var result = await formatter.FormatAsJsonAsync(response);
```

## Data Sources

| Data | Source | Cache Duration |
|------|--------|----------------|
| Registrar List | IANA Registrar IDs CSV | 7 days |
| IPv4 Allocations | IANA IPv4 Address Space CSV | 7 days |
| IPv6 Allocations | IANA IPv6 Unicast Address Assignments CSV | 7 days |
| ASN Allocations | IANA AS Numbers CSV | 7 days |
| TLD List | IANA TLD List | 7 days |

## WHOIS Server Discovery

1. **Known List**: Built-in list of ~50 common TLD WHOIS servers
2. **DNS Lookup**: Queries `{tld}.whois-servers.net` DNS records
3. **IANA WHOIS**: Falls back to querying `whois.iana.org`

## Privacy Detection

Detects privacy services from major providers:
- Domains By Proxy (GoDaddy)
- WhoisGuard (Namecheap)
- Contact Privacy (Google)
- Withheld for Privacy (Namecheap)
- Perfect Privacy (Network Solutions)
- GDPR redaction patterns

## License

MIT
