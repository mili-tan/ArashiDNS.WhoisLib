import type { Env, FormattedResult, TraceEntry, ContactInfo, WhoisResponse } from './types';
import { RdapClient, detectQueryType } from './rdap-client';
import { WhoisTcpClient } from './whois-tcp-client';
import { BootstrapProvider } from './bootstrap-provider';
import { RegistrarProvider, identifyRegistry, identifyRegistrar } from './registry-identifier';
import { detectPrivacy } from './privacy-detector';
import { LlmFormatter } from './llm-formatter';

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data: unknown, status = 200, origin: string | null = null): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
      ...corsHeaders(origin),
    },
  });
}

function errorResponse(message: string, status: number, origin: string | null = null): Response {
  return jsonResponse({ error: message }, status, origin);
}

async function checkRateLimit(kv: KVNamespace, ip: string, rpm: number): Promise<boolean> {
  const key = `ratelimit:${ip}`;
  const now = Date.now();
  const windowMs = 60 * 1000;

  const data = await kv.get<{ timestamps: number[] }>(key, 'json');
  const timestamps = data?.timestamps || [];

  // Filter to current window
  const recent = timestamps.filter(t => now - t < windowMs);

  if (recent.length >= rpm) {
    return false; // Rate limited
  }

  recent.push(now);
  await kv.put(key, JSON.stringify({ timestamps: recent }), { expirationTtl: 120 });
  return true;
}

function getClientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Real-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown';
}

function checkApiKey(request: Request, env: Env): boolean {
  if (!env.API_KEY) return true; // No API key configured, allow all

  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7) === env.API_KEY;
  }

  const apiKeyHeader = request.headers.get('X-API-Key');
  if (apiKeyHeader) return apiKeyHeader === env.API_KEY;

  const url = new URL(request.url);
  const queryKey = url.searchParams.get('key');
  if (queryKey) return queryKey === env.API_KEY;

  return false;
}

async function handleQuery(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get('Origin');
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  const ip = url.searchParams.get('ip');
  const asn = url.searchParams.get('asn');
  const query = domain || ip || asn;

  if (!query) {
    return errorResponse('Missing query parameter: domain, ip, or asn', 400, origin);
  }

  const raw = url.searchParams.get('raw') === '1';
  const trace = url.searchParams.get('trace') === '1';
  const useLlm = url.searchParams.get('llm') === '1';
  const mode = url.searchParams.get('mode') || 'auto'; // auto | rdap | whois

  const queryType = detectQueryType(query);
  const bootstrap = new BootstrapProvider(env.A_WHOIS_CACHE_KV);
  const registrarProvider = new RegistrarProvider(env.A_WHOIS_CACHE_KV);

  let response: WhoisResponse;
  let traceEntries: TraceEntry[] = [];

  if (mode === 'whois') {
    // WHOIS TCP mode
    const whoisClient = new WhoisTcpClient();
    const result = await whoisClient.query(query, queryType);
    response = result.response;
    traceEntries = result.trace;
  } else if (mode === 'auto') {
    // Auto mode: try RDAP first, fallback to WHOIS TCP
    const rdapClient = new RdapClient(bootstrap);
    const rdapResult = await rdapClient.query(query, queryType);
    response = rdapResult.response;
    traceEntries = rdapResult.trace;

    if (!response.isSuccessful) {
      const whoisClient = new WhoisTcpClient();
      const whoisResult = await whoisClient.query(query, queryType);
      response = whoisResult.response;
      traceEntries.push(...whoisResult.trace);
    }
  } else {
    // RDAP mode (default, also for IP/ASN)
    const rdapClient = new RdapClient(bootstrap);
    const rdapResult = await rdapClient.query(query, queryType);
    response = rdapResult.response;
    traceEntries = rdapResult.trace;
  }

  if (!response.isSuccessful) {
    // Try LLM if RDAP failed and LLM is enabled
    if (useLlm && env.DEEPSEEK_API_KEY) {
      const llmFormatter = new LlmFormatter(env);
      if (llmFormatter.isEnabled && response.rawResponse) {
        const llmResult = await llmFormatter.format(response.rawResponse);
        if (llmResult) {
          return jsonResponse({
            ...llmResult,
            ...(raw ? { rawResponse: response.rawResponse } : {}),
            ...(trace ? { trace: traceEntries } : {}),
          }, 200, origin);
        }
      }
    }

    return jsonResponse({
      error: response.errorMessage,
      query,
      queryType,
      ...(raw ? { rawResponse: response.rawResponse } : {}),
      ...(trace ? { trace: traceEntries } : {}),
    }, 404, origin);
  }

  // Enrich with privacy detection
  response.privacy = detectPrivacy(response);

  // Enrich with registry identification
  response.registry = identifyRegistry(response);

  // Enrich with registrar identification
  response.registrar = await identifyRegistrar(response, registrarProvider);

  // Merge contacts
  const contacts = mergeContacts(response.contacts);

  // Try LLM if registrar/dates are missing and LLM is enabled
  if (useLlm && env.DEEPSEEK_API_KEY && response.rawResponse) {
    const needsLlm = !response.registrar?.name || !response.dates?.expires;
    if (needsLlm) {
      const llmFormatter = new LlmFormatter(env);
      if (llmFormatter.isEnabled) {
        const llmResult = await llmFormatter.format(response.rawResponse);
        if (llmResult) {
          traceEntries.push({
            protocol: 'LLM',
            endpoint: env.DEEPSEEK_API_ENDPOINT || 'deepseek',
            formatter: 'LLM',
            success: true,
          });

          return jsonResponse({
            ...llmResult,
            ...(raw ? { rawResponse: response.rawResponse } : {}),
            ...(trace ? { trace: traceEntries } : {}),
          }, 200, origin);
        }
      }
    }
  }

  const result: FormattedResult = {
    domain: response.domain,
    registry: response.registry,
    registrar: response.registrar,
    privacy: response.privacy,
    contacts,
    dates: response.dates,
    nameServers: response.nameServers,
    status: response.statuses,
    dnssec: response.dnssec,
    ...(raw ? { rawResponse: response.rawResponse || undefined } : {}),
    ...(trace ? { trace: traceEntries } : {}),
  };

  return jsonResponse(result, 200, origin);
}

interface RawContactCollection {
  registrant?: ContactInfo | null;
  admin?: ContactInfo | null;
  tech?: ContactInfo | null;
  billing?: ContactInfo | null;
}

function mergeContacts(contacts: RawContactCollection): ContactInfo[] {
  const all: ContactInfo[] = [];
  const entries: [ContactInfo | null | undefined, string][] = [
    [contacts.registrant, 'registrant'],
    [contacts.admin, 'admin'],
    [contacts.tech, 'tech'],
    [contacts.billing, 'billing'],
  ];

  const processed = new Map<string, ContactInfo>();

  for (const [contact, role] of entries) {
    if (!contact) continue;
    const hash = contactHash(contact);
    const existing = processed.get(hash);
    if (existing) {
      if (!existing.roles.includes(role)) existing.roles.push(role);
    } else {
      const newContact = { ...contact, roles: [role] };
      processed.set(hash, newContact);
      all.push(newContact);
    }
  }

  return all.filter(c => c.name || c.organization || c.email);
}

function contactHash(c: ContactInfo): string {
  return [c.name, c.organization, c.email, c.phone, c.street, c.city, c.state, c.postalCode, c.country].join('|');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Only allow GET
    if (request.method !== 'GET') {
      return errorResponse('Method not allowed', 405, origin);
    }

    // Check API key
    if (!checkApiKey(request, env)) {
      return errorResponse('Invalid API key', 401, origin);
    }

    // Check rate limit
    const clientIp = getClientIp(request);
    const rpm = parseInt(env.RATE_LIMIT_RPM || '60', 10);
    const allowed = await checkRateLimit(env.A_WHOIS_CACHE_KV, clientIp, rpm);
    if (!allowed) {
      return errorResponse('Rate limit exceeded', 429, origin);
    }

    // Handle health check
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return jsonResponse({
        status: 'ok',
        llm: !!env.DEEPSEEK_API_KEY,
        modes: ['rdap', 'whois', 'auto'],
      }, 200, origin);
    }

    // Handle query
    try {
      return await handleQuery(request, env);
    } catch (ex) {
      return errorResponse(`Internal error: ${(ex as Error).message}`, 500, origin);
    }
  },
};
