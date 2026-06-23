# ArashiDNS.WhoisWorker

Cloudflare Worker WHOIS/RDAP lookup API, ported from [ArashiDNS.WhoisLib](../ArashiDNS.WhoisLib/).

## Features

- **Dual Protocol**: RDAP (HTTP) + WHOIS (TCP port 43)
- **Auto Mode**: RDAP first, falls back to WHOIS on failure
- **Referral Following**: WHOIS up to 5 hops, RDAP up to 3 hops
- **IANA Bootstrap**: RDAP endpoint auto-discovery with KV cache (7 days TTL)
- **Privacy Detection**: GDPR, WhoisGuard, Domains By Proxy, etc.
- **LLM Parsing**: Optional DeepSeek API for complex WHOIS responses, with Thinking mode support
- **Rate Limiting**: Configurable per-IP RPM
- **API Key**: Optional Bearer / Header / Query parameter authentication
- **CORS**: Allow any origin

## API

```
GET /?domain=google.com
GET /?ip=8.8.8.8
GET /?asn=13335
```

### Parameters

| Param | Description |
|-------|-------------|
| `domain` | Domain lookup |
| `ip` | IP address lookup |
| `asn` | ASN lookup |
| `mode` | `auto` (default) / `rdap` / `whois` |
| `raw=1` | Include raw RDAP/WHOIS response |
| `trace=1` | Include query trace |
| `llm=1` | Enable LLM parsing (requires API key) |

### Response

```json
{
  "domain": "google.com",
  "registry": { "name": "VeriSign Global Registry Services", "website": "..." },
  "registrar": { "ianaId": "292", "name": "MarkMonitor, Inc.", "website": "..." },
  "privacy": { "isPrivate": true, "provider": "GDPR Redaction" },
  "contacts": [{ "name": "...", "organization": "...", "email": "...", "roles": ["registrant"] }],
  "dates": { "created": "1997-09-15", "updated": "2024-08-02", "expires": "2028-09-13" },
  "nameServers": ["ns1.google.com", "ns2.google.com"],
  "status": ["clientdeleteprohibited", "clienttransferprohibited"],
  "dnssec": { "signed": false, "delegationSigned": true, "dsData": [...] }
}
```

### Health Check

```
GET /health
```

```json
{ "status": "ok", "llm": false, "modes": ["rdap", "whois", "auto"] }
```

## Deployment

### Prerequisites

- Node.js >= 18
- Cloudflare account

### Steps

```bash
cd ArashiDNS.WhoisWorker

# 1. Install dependencies
npm install

# 2. Login to Cloudflare
npx wrangler login

# 3. Create KV namespace
npx wrangler kv namespace create A_WHOIS_CACHE_KV
# Note the returned ID, e.g.: { binding = "A_WHOIS_CACHE_KV", id = "xxxxxxxxxxxx" }

# 4. Update KV ID in wrangler.toml
#    Replace id = "placeholder" with the actual ID from step 3

# 5. Deploy
npx wrangler deploy
```

### Temporary Deploy (for testing)

```bash
npx wrangler deploy --temporary
```

### Local Development

```bash
npx wrangler dev --local
# Access http://localhost:8787
```

## Environment Variables

Configure in `wrangler.toml` `[vars]` section, or via Cloudflare Dashboard:

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEY` | No | API access key, empty = no auth |
| `DEEPSEEK_API_KEY` | No | DeepSeek API key, empty = LLM disabled |
| `DEEPSEEK_API_ENDPOINT` | No | LLM API endpoint, default `https://api.deepseek.com/chat/completions` |
| `DEEPSEEK_MODEL` | No | LLM model name, default `deepseek-v4-flash` |
| `DEEPSEEK_ENABLE_THINKING` | No | Enable thinking mode, `true`/`false`, default `false` |
| `DEEPSEEK_REASONING_EFFORT` | No | Reasoning effort, `high`/`medium`/`low`, default `high` |
| `RATE_LIMIT_RPM` | No | Requests per minute per IP, default `60` |

> **Thinking Mode**: When enabled, DeepSeek reasons before outputting results, useful for complex WHOIS parsing.
> The `temperature` parameter is not supported when thinking is enabled and will be ignored automatically.
> See [DeepSeek API docs](https://api-docs.deepseek.com/) for details.

### API Key Authentication

After configuring `API_KEY`, pass it via:

```bash
# Bearer Token
curl -H "Authorization: Bearer YOUR_KEY" "https://your-worker.dev/?domain=example.com"

# X-API-Key Header
curl -H "X-API-Key: YOUR_KEY" "https://your-worker.dev/?domain=example.com"

# Query Parameter
curl "https://your-worker.dev/?domain=example.com&key=YOUR_KEY"
```

## Project Structure

```
ArashiDNS.WhoisWorker/
├── wrangler.toml              # Worker configuration
├── package.json
├── tsconfig.json
└── src/
    ├── index.ts               # HTTP entry, routing, auth, rate limiting
    ├── types.ts               # TypeScript type definitions
    ├── rdap-client.ts         # RDAP query + referral following
    ├── rdap-parser.ts         # RDAP JSON/vCard parser
    ├── whois-tcp-client.ts    # WHOIS TCP query + referral following
    ├── bootstrap-provider.ts  # IANA RDAP endpoint discovery (KV cached)
    ├── tld-registry.ts        # TLD->Registry static dictionary (1542 entries)
    ├── registry-identifier.ts # Registry/Registrar identification
    ├── registrar-provider.ts  # IANA Registrar CSV (KV cached)
    ├── privacy-detector.ts    # Privacy protection detection
    └── llm-formatter.ts       # LLM parsing integration (Thinking supported)
```

## Limitations

- WHOIS TCP connections depend on Cloudflare Workers TCP Socket API
- TLDs without RDAP (e.g. `.cn`) only work in WHOIS mode
- LLM feature requires a DeepSeek API key
