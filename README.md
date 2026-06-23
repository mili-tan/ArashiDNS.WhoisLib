# ArashiDNS WhoisLib

A C# WHOIS/RDAP lookup library with registry/registrar identification, privacy detection, and LLM-powered formatting.

## Features

- **WHOIS & RDAP support**: Query domain, IP, and ASN information
- **Three-level server discovery**: Known list → DNS lookup → IANA query
- **RDAP referral following**: Automatically follows registrar referrals
- **Registry/Registrar identification**: With official websites from IANA data
- **Privacy protection detection**: Identifies WHOIS privacy services and reasons
- **Contact merging**: Merges identical contact info with role array
- **LLM formatting**: DeepSeek API integration for structured output
- **Auto fallback**: WHOIS Traditional → WHOIS LLM (when registrar/dates empty)
- **Local file caching**: IANA data cached for 7 days

## Quick Start

```csharp
using ArashiDNS.WhoisLib;

// Simple usage
var result = await Whois.LookupAsync("google.com");
Console.WriteLine(result.Data.Domain);
Console.WriteLine(result.Data.Registrar?.Name);

// With options
var options = new WhoisClientOptions
{
    Strategy = QueryStrategy.RdapFirst,
    LlmApiKey = "sk-xxx"
};
var result = await Whois.LookupAsync("google.com", options);
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
└── ServerDiscovery/    # Server lookup implementations

ArashiDNS.WhoisCLI/    # CLI demo application
```

## License

MIT
