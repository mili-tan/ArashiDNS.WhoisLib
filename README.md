# ArashiDNS WhoisLib

A C# WHOIS/RDAP lookup library with multi-layer parsing, registry/registrar identification, privacy detection, and LLM-powered formatting.

## Features

- **Multi-layer parsing**: Tokenizer + Regex + FieldMapping + Section + LLM
- **WHOIS & RDAP support**: Query domain, IP, and ASN information
- **Three-level server discovery**: Known list → DNS lookup → IANA query
- **RDAP referral following**: Automatically follows registrar referrals
- **Registry/Registrar identification**: With official websites from IANA data
- **Privacy protection detection**: Identifies WHOIS privacy services and reasons
- **Contact merging**: Merges identical contact info with role array
- **LLM formatting**: DeepSeek API integration for structured output
- **Auto fallback**: Multiple parsing layers with automatic fallback
- **Local file caching**: IANA data cached for 7 days
- **145+ server templates**: Tokenizer templates for specific WHOIS servers
- **250+ regex patterns**: Covering 199+ weppos/whois-parser server formats

## Multi-Layer Parsing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│            MultiLayerParser (WhoisLookup)                    │
│                                                             │
│  Layer 1: TokenizerParser (template-based)                  │
│           - 145+ server-specific templates (flipbit)        │
│           - Pattern matching with transformers              │
│                                                             │
│  Layer 2: RegexParser (regex-based) ← Primary               │
│           - 250+ regex patterns (weppos)                    │
│           - Covers 199+ WHOIS server formats                │
│                                                             │
│  Layer 3: TraditionalFormatter (field mapping)              │
│           - Original implementation, backward compatible    │
│                                                             │
│  Layer 4: SectionParser (section-based)                     │
│           - Handles .kg, .cn, and similar formats           │
│                                                             │
│  Layer 5: LlmFormatter (LLM-based)                         │
│           - DeepSeek API integration, final fallback        │
│                                                             │
│  PostProcessors:                                            │
│           - AvailabilityDetector (not registered detection) │
│           - GeoNormalizer (country/region standardization)  │
│           - PrivacyDetector (privacy service detection)     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Parsing Trace

The `MultiLayerFormatter` reports which layer and parser was used:

```
Trace: MultiLayer(Regex/RegexParser:15fields)
Trace: MultiLayer(Tokenizer/TemplateParser:12fields)
Trace: MultiLayer(Traditional/FieldMapping:10fields)
Trace: MultiLayer(LLM/DeepSeek:18fields)
```

## Quick Start

### WhoisLookup (Recommended)

```csharp
using ArashiDNS.WhoisLib;

var result = await new WhoisLookup().QueryAsync("google.com");

using var client = new WhoisLookup(new WhoisClientOptions
{
    Strategy = QueryStrategy.RdapFirst,
    LlmApiKey = "sk-xxx"
});

foreach (var domain in new[] { "google.com", "github.com", "example.com" })
{
    var result = await client.QueryAsync(domain);
    Console.WriteLine($"{result.Data.Domain} - {result.Data.Registrar?.Name}");
}
```

### Static Helper

```csharp
using ArashiDNS.WhoisLib;

var result = await Whois.LookupAsync("google.com");

var result = await Whois.LookupAsync("google.com", new WhoisClientOptions
{
    Strategy = QueryStrategy.WhoisLlmOnly,
    LlmApiKey = "sk-xxx"
});
```

### Direct RDAP Query

```csharp
using ArashiDNS.WhoisLib.Core;

var client = new RdapClient();
var response = await client.QueryAsync("google.com");

Console.WriteLine(response.RawResponse);
Console.WriteLine(response.Domain);
```

### Direct WHOIS Query

```csharp
using ArashiDNS.WhoisLib.Core;
using ArashiDNS.WhoisLib.ServerDiscovery;

var serverFinder = new CompositeServerFinder();
var client = new WhoisClient(serverFinder);
var response = await client.QueryAsync("google.com");

Console.WriteLine(response.RawResponse);
```

### Traditional Formatter

```csharp
using ArashiDNS.WhoisLib.Formatting;
using ArashiDNS.WhoisLib.Data;

var registrarProvider = new RegistrarListProvider();
var formatter = new TraditionalFormatter(registrarProvider);

var result = await formatter.FormatAsync(whoisResponse);
Console.WriteLine(result.Domain);
Console.WriteLine(result.Registrar?.Name);
Console.WriteLine(result.Dates?.Created);
```

### LLM Formatter

```csharp
using ArashiDNS.WhoisLib.Formatting;

var options = new LlmFormatterOptions
{
    ApiKey = "sk-xxx",
    Model = "deepseek-v4-flash",
    ApiEndpoint = "https://api.deepseek.com/chat/completions",
    EnableThinking = false
};
var formatter = new LlmFormatter(options);

var result = await formatter.FormatAsync(whoisResponse);
Console.WriteLine(result.RawJson);
```

## CLI Usage

```bash
# Basic lookup (RDAP → WHOIS → LLM fallback)
ArashiDNS.WhoisCLI google.com

# RDAP only
ArashiDNS.WhoisCLI google.com --rdap

# WHOIS only
ArashiDNS.WhoisCLI google.com --whois

# With LLM formatting
ArashiDNS.WhoisCLI google.com --llm

# With custom LLM endpoint
ArashiDNS.WhoisCLI google.com --llm --llm-endpoint "https://api.example.com/v1"

# Trace mode (show each request step)
ArashiDNS.WhoisCLI google.com -t

# Show final endpoint
ArashiDNS.WhoisCLI google.com --show-endpoint

# JSON output
ArashiDNS.WhoisCLI google.com --json
```

## Query Strategies

| Strategy | Flow |
|----------|------|
| `RdapFirst` | RDAP+Traditional → WHOIS+Traditional → WHOIS+LLM |
| `WhoisFirst` | WHOIS+Traditional → RDAP+Traditional → WHOIS+LLM |
| `RdapFirstWhoisLlmFallback` | RDAP+Traditional → WHOIS+LLM |
| `RdapTraditionOnly` | RDAP+Traditional only |
| `WhoisTraditionOnly` | WHOIS+Traditional only |
| `RdapLlmOnly` | RDAP+LLM only |
| `WhoisLlmOnly` | WHOIS+LLM only |

## LLM Configuration

```csharp
var options = new WhoisClientOptions
{
    LlmApiKey = "sk-xxx",                          // Or set DEEPSEEK_API_KEY env var
    LlmModel = "deepseek-v4-flash",                // Default model
    LlmApiEndpoint = "https://api.deepseek.com/...", // Custom endpoint
    LlmEnableThinking = false                       // Enable thinking mode
};
```

## Output Examples

### RDAP Mode
```
Domain: GOOGLE.COM
Registry: Verisign
  Website: https://www.verisign.com
Registrar: Markmonitor Inc.
  IANA ID: 292
Privacy: YES (GDPR Redaction)
Dates:
  Created: 1997-09-15
  Expires: 2028-09-14
Contacts:
  [registrant]
    Org: Google LLC
```

### Trace Mode (-t)
```
--- Trace ---
  [OK] RDAP/ -> https://rdap.verisign.com/com/v1/domain/GOOGLE.COM
  [OK] RDAP/ -> https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM
  [OK] RDAP/Traditional -> https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM
```

## Data Sources

| Data | Source | Cache |
|------|--------|-------|
| RDAP Endpoints | IANA RDAP Bootstrap (dns.json) | 7 days |
| Registrar List | IANA Registrar IDs CSV | 7 days |
| IPv4/IPv6 Allocations | IANA CSV | 7 days |
| ASN Allocations | IANA CSV | 7 days |
| Registry Info | tldlist.us | Built-in |

## Project Structure

```
ArashiDNS.WhoisLib/
├── Contracts/          # Interfaces and models
├── Core/               # WHOIS/RDAP clients and parsers
├── Data/               # IANA data providers and cache
├── Detection/          # Privacy and registry detection
├── Formatting/         # Traditional and LLM formatters
├── Parsing/            # Multi-layer parsing engine
│   ├── Templates/      # Tokenizer templates (145+ servers)
│   ├── RegexParser.cs  # Regex-based parser (250+ patterns)
│   ├── TokenizerParser.cs  # Template-based parser
│   ├── MultiLayerParser.cs # Multi-layer orchestrator
│   ├── AvailabilityDetector.cs  # Not-registered detection
│   └── GeoNormalizer.cs  # Country/region normalization
└── ServerDiscovery/    # Server lookup implementations

ArashiDNS.WhoisCLI/    # CLI demo application
```

## Acknowledgments

This project's parsing engine is inspired by and references the following open-source projects:

| Project | Language | Reference |
|---------|----------|-----------|
| [weppos/whois](https://github.com/weppos/whois) | Ruby | WHOIS client architecture, server discovery |
| [weppos/whois-parser](https://github.com/weppos/whois-parser) | Ruby | 199+ server-specific parsers, field patterns, Scanner/Tokenizer pattern |
| [flipbit/whois](https://github.com/flipbit/whois) | .NET | Tokenizer template-based parsing, 145+ server templates |

### What we learned from each project:

- **weppos/whois**: Clean separation of client/parser, `property_supported` pattern, `available?`/`registered?` state detection
- **weppos/whois-parser**: Per-server parser classes, Scanner-based tokenization, comprehensive field mappings for 199+ WHOIS servers
- **flipbit/whois**: Tokenizer template syntax (`{ FieldName : Transformer }`), template matching with fallback, `CleanDomainStatus`/`ToHostName` transformers

## License

MIT
