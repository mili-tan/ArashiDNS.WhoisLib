import type { Env, FormattedResult, TraceEntry, ContactInfo, WhoisResponse } from './types';
import { RdapClient, detectQueryType } from './core/rdap-client';
import { WhoisTcpClient } from './core/whois-client';
import { BootstrapProvider } from './data/bootstrap-provider';
import { RegistrarProvider, identifyRegistry, identifyRegistryFromTldData, identifyRegistrar, identifyRegistrarFromData } from './data/registry-identifier';
import { TldDataProvider } from './data/tld-data-provider';
import { RegistrarDataProvider } from './data/registrar-data-provider';
import { detectPrivacy } from './detection/privacy-detector';
import { LlmFormatter } from './formatting/llm-formatter';

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400',
  };
}

function htmlResponse(html: string, origin: string | null = null): Response {
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      ...corsHeaders(origin),
    },
  });
}

function jsonResponse(data: unknown, status = 200, origin: string | null = null, compact = false): Response {
  return new Response(JSON.stringify(compact ? stripEmpty(data) : data, null, 2), {
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
  const showEmpty = url.searchParams.get('show_empty') === '1';
  const mode = url.searchParams.get('mode') || 'auto'; // auto | rdap | whois

  const queryType = detectQueryType(query);

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
    const bootstrap = new BootstrapProvider(env.A_WHOIS_CACHE_KV);
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
    // RDAP mode
    const bootstrap = new BootstrapProvider(env.A_WHOIS_CACHE_KV);
    const rdapClient = new RdapClient(bootstrap);
    const rdapResult = await rdapClient.query(query, queryType);
    response = rdapResult.response;
    traceEntries = rdapResult.trace;
  }

  const rawResponse = response.rawResponse;

  // If query failed, try LLM fallback
  if (!response.isSuccessful) {
    if (useLlm && env.DEEPSEEK_API_KEY && rawResponse) {
      const llmFormatter = new LlmFormatter(env);
      if (llmFormatter.isEnabled) {
        const llmResult = await llmFormatter.format(rawResponse);
        if (llmResult) {
          return jsonResponse({
            ...llmResult,
            ...(raw ? { rawResponse } : {}),
            ...(trace ? { trace: traceEntries } : {}),
          }, 200, origin, !showEmpty);
        }
      }
    }

    return jsonResponse({
      error: response.errorMessage,
      query,
      queryType,
      ...(raw ? { rawResponse } : {}),
      ...(trace ? { trace: traceEntries } : {}),
    }, 404, origin);
  }

  // Enrich response
  response.privacy = detectPrivacy(response);

  // Use TLD data for richer registry info
  const tldProvider = new TldDataProvider(env.A_WHOIS_CACHE_KV);
  const tldRegistry = await identifyRegistryFromTldData(response, tldProvider);
  if (tldRegistry) {
    response.registry = tldRegistry;
  } else {
    response.registry = identifyRegistry(response);
  }

  // Use registrar data for richer registrar info
  const llmAvailable = useLlm && env.DEEPSEEK_API_KEY;
  const registrarDataProvider = new RegistrarDataProvider(env.A_WHOIS_CACHE_KV);

  if (response.registrar?.ianaId || response.registrar?.name) {
    const enriched = await identifyRegistrarFromData(response, registrarDataProvider);
    if (enriched) response.registrar = enriched;
  }

  if (!response.registrar?.name && !llmAvailable) {
    const registrarProvider = new RegistrarProvider(env.A_WHOIS_CACHE_KV);
    response.registrar = await identifyRegistrar(response, registrarProvider);
  }

  const contacts = mergeContacts(response.contacts);

  // Try LLM if registrar/dates are missing
  if (llmAvailable && rawResponse) {
    const needsLlm = !response.registrar?.name || !response.dates?.expires;
    if (needsLlm) {
      const llmFormatter = new LlmFormatter(env);
      if (llmFormatter.isEnabled) {
        const llmResult = await llmFormatter.format(rawResponse);
        if (llmResult) {
          traceEntries.push({
            protocol: 'LLM',
            endpoint: env.DEEPSEEK_API_ENDPOINT || 'deepseek',
            formatter: 'LLM',
            success: true,
          });
          return jsonResponse({
            ...llmResult,
            ...(raw ? { rawResponse } : {}),
            ...(trace ? { trace: traceEntries } : {}),
          }, 200, origin, !showEmpty);
        }
      }
    }

    // LLM didn't run or failed, fill registrar if missing
    if (!response.registrar?.name) {
      const enriched = await identifyRegistrarFromData(response, registrarDataProvider);
      if (enriched) response.registrar = enriched;

      if (!response.registrar?.name) {
        const registrarProvider = new RegistrarProvider(env.A_WHOIS_CACHE_KV);
        response.registrar = await identifyRegistrar(response, registrarProvider);
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
    ...(raw ? { rawResponse: rawResponse || undefined } : {}),
    ...(trace ? { trace: traceEntries } : {}),
  };

  return jsonResponse(result, 200, origin, !showEmpty);
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

function stripEmpty(obj: unknown): unknown {
  if (Array.isArray(obj)) {
    const arr = obj.map(stripEmpty).filter(v => v !== undefined && v !== null && v !== '');
    return arr.length > 0 ? arr : undefined;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      const stripped = stripEmpty(v);
      if (stripped !== undefined && stripped !== null && stripped !== '') {
        result[k] = stripped;
      }
    }
    return Object.keys(result).length > 0 ? result : undefined;
  }
  if (obj === '' || obj === null) return undefined;
  return obj;
}

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en" data-theme="cupcake">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WhoisWorker - Domain Lookup</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.14/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        html, body {
            height: 100%;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #faf7f5;
            margin: 0;
            overflow-x: hidden;
            display: flex;
            flex-direction: column;
        }

        .globe-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            pointer-events: none;
        }

        .globe-bg canvas {
            width: 100%;
            height: 100%;
        }

        .main-wrap {
            position: relative;
            z-index: 10;
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 4rem 2rem 2rem;
        }

        .site-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: #78716c;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }

        .hero-title {
            font-size: clamp(2.5rem, 5vw, 4rem);
            font-weight: 700;
            color: #44403c;
            text-align: center;
            margin-bottom: 1rem;
            letter-spacing: -0.025em;
            line-height: 1.1;
        }

        .hero-sub {
            font-size: 1.125rem;
            color: #a8a29e;
            text-align: center;
            max-width: 520px;
            margin: 0 auto 3rem;
            line-height: 1.6;
        }

        .search-box {
            width: 100%;
            max-width: 720px;
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(16px);
            border: 1px solid #e7e5e4;
            border-radius: 1rem;
            padding: 1.5rem 1.5rem 1rem;
            box-shadow: 0 4px 24px rgba(120, 113, 108, 0.06);
            transition: box-shadow 0.3s ease;
        }

        .search-box:hover {
            box-shadow: 0 8px 40px rgba(120, 113, 108, 0.1);
        }

        .input-row {
            display: flex;
            gap: 0.75rem;
        }

        .query-input {
            flex: 1;
            padding: 0.875rem 1.25rem;
            font-size: 1rem;
            border: 1.5px solid #d6d3d1;
            border-radius: 0.75rem;
            background: #fff;
            color: #44403c;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .query-input:focus {
            border-color: #78716c;
            box-shadow: 0 0 0 3px rgba(120, 113, 108, 0.12);
        }

        .query-input::placeholder {
            color: #c4b5a6;
        }

        .submit-btn {
            padding: 0.875rem 1.75rem;
            background: #44403c;
            color: #faf7f5;
            border: none;
            border-radius: 0.75rem;
            font-size: 0.9375rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.15s;
            white-space: nowrap;
        }

        .submit-btn:hover {
            background: #292524;
            transform: translateY(-1px);
        }

        .submit-btn:active {
            transform: translateY(0);
        }

        .options-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.375rem;
            width: 100%;
            margin-top: 0.75rem;
            padding: 0;
            background: none;
            border: none;
            color: #a8a29e;
            font-size: 0.75rem;
            cursor: pointer;
            transition: color 0.2s;
        }

        .options-toggle:hover {
            color: #78716c;
        }

        .options-toggle svg {
            width: 14px;
            height: 14px;
            transition: transform 0.25s ease;
        }

        .options-toggle.open svg {
            transform: rotate(180deg);
        }

        .options-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.75rem;
            margin-top: 0.75rem;
            max-height: 0;
            overflow: hidden;
            opacity: 0;
            transition: max-height 0.3s ease, opacity 0.25s ease, margin-top 0.25s ease;
        }

        .options-row.show {
            max-height: 200px;
            opacity: 1;
        }

        .opt-select {
            padding: 0.625rem 0.875rem;
            border: 1.5px solid #d6d3d1;
            border-radius: 0.625rem;
            background: #fff;
            font-size: 0.875rem;
            color: #57534e;
            outline: none;
            cursor: pointer;
            transition: border-color 0.2s;
        }

        .opt-select:focus {
            border-color: #78716c;
        }

        .result-panel {
            width: 100%;
            max-width: 720px;
            margin-top: 2rem;
            display: none;
            animation: slideUp 0.4s ease;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .result-card {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(16px);
            border: 1px solid #e7e5e4;
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: 0 4px 24px rgba(120, 113, 108, 0.06);
        }

        .result-head {
            padding-bottom: 1.25rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid #e7e5e4;
        }

        .result-domain {
            font-size: 1.5rem;
            font-weight: 700;
            color: #44403c;
        }

        .result-meta {
            font-size: 0.875rem;
            color: #a8a29e;
            margin-top: 0.25rem;
        }

        .section {
            margin-bottom: 1.5rem;
        }

        .section-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: #78716c;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .section-label.hidden {
            display: none;
        }

        .info-item.has-toggle {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            grid-column: 1 / -1;
        }

        .info-item-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
        }

        .toggle-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            padding: 0;
            background: none;
            border: 1.5px solid #d6d3d1;
            border-radius: 0.375rem;
            cursor: pointer;
            color: #a8a29e;
            transition: all 0.2s;
            flex-shrink: 0;
        }

        .toggle-btn:hover {
            border-color: #78716c;
            color: #78716c;
        }

        .toggle-btn svg {
            width: 14px;
            height: 14px;
            transition: transform 0.25s ease;
        }

        .toggle-btn.open svg {
            transform: rotate(180deg);
        }

        .toggle-detail {
            display: none;
            grid-column: 1 / -1;
        }

        .toggle-detail.open {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 0.75rem;
            margin-top: 0.75rem;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 0.75rem;
        }

        .info-item {
            background: #faf7f5;
            border: 1px solid #e7e5e4;
            border-radius: 0.75rem;
            padding: 1rem;
            transition: border-color 0.2s;
        }

        .info-item:hover {
            border-color: #d6d3d1;
        }

        .info-key {
            font-size: 0.6875rem;
            font-weight: 500;
            color: #a8a29e;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 0.375rem;
        }

        .info-val {
            font-size: 0.875rem;
            color: #44403c;
            line-height: 1.4;
            word-break: break-all;
        }

        .ns-list {
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.8125rem;
        }

        .status-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .status-tag {
            display: inline-block;
            padding: 0.375rem 0.75rem;
            background: #faf7f5;
            border: 1px solid #e7e5e4;
            border-radius: 2rem;
            font-size: 0.75rem;
            color: #57534e;
            line-height: 1;
        }

        .trace-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .trace-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.625rem 1rem;
            background: #faf7f5;
            border: 1px solid #e7e5e4;
            border-radius: 0.625rem;
            font-size: 0.8125rem;
        }

        .trace-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .trace-dot.ok { background: #16a34a; }
        .trace-dot.fail { background: #dc2626; }

        .trace-proto {
            font-weight: 600;
            color: #44403c;
            min-width: 48px;
        }

        .trace-endpoint {
            color: #78716c;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .trace-status {
            font-size: 0.6875rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .trace-status.ok { color: #16a34a; }
        .trace-status.fail { color: #dc2626; }

        .raw-block {
            position: relative;
        }

        .raw-pre {
            background: #292524;
            color: #e7e5e4;
            border-radius: 0.75rem;
            padding: 1.25rem;
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            line-height: 1.6;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .loading-state {
            display: none;
            text-align: center;
            padding: 2.5rem;
        }

        .spinner {
            width: 32px;
            height: 32px;
            border: 3px solid #e7e5e4;
            border-top-color: #78716c;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 1rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading-text {
            color: #a8a29e;
            font-size: 0.875rem;
        }

        .error-box {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 0.75rem;
            padding: 1.25rem;
            color: #991b1b;
            font-size: 0.875rem;
            line-height: 1.5;
        }

        .actions-row {
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            padding-top: 1.25rem;
            border-top: 1px solid #e7e5e4;
            flex-wrap: wrap;
        }

        .btn-action {
            padding: 0.625rem 1.25rem;
            border-radius: 0.625rem;
            font-size: 0.8125rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-new {
            background: transparent;
            color: #78716c;
            border: 1.5px solid #d6d3d1;
        }

        .btn-new:hover {
            border-color: #78716c;
            color: #44403c;
        }

        .btn-copy {
            background: #44403c;
            color: #faf7f5;
            border: 1.5px solid #44403c;
        }

        .btn-copy:hover {
            background: #292524;
        }

        .btn-raw {
            background: transparent;
            color: #78716c;
            border: 1.5px solid #d6d3d1;
            margin-left: auto;
        }

        .btn-raw:hover {
            border-color: #78716c;
            color: #44403c;
        }

        .info-item.full {
            grid-column: 1 / -1;
        }

        .info-item.border-green {
            border-color: #86efac;
            background: #f0fdf4;
        }

        .info-item.border-amber {
            border-color: #fcd34d;
            background: #fffbeb;
        }

        .detail-card {
            background: #faf7f5;
            border: 1px solid #e7e5e4;
            border-radius: 0.75rem;
            overflow: hidden;
            transition: border-color 0.15s;
        }

        .detail-card:hover {
            border-color: #d6d3d1;
        }

        .detail-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.875rem 1rem;
            cursor: pointer;
            gap: 0.75rem;
        }

        .detail-title {
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
            min-width: 0;
        }

        .detail-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: #44403c;
        }

        .detail-hint {
            font-size: 0.6875rem;
            color: #a8a29e;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .detail-arrow {
            width: 16px;
            height: 16px;
            color: #a8a29e;
            transition: transform 0.25s ease;
            flex-shrink: 0;
        }

        .detail-card.open .detail-arrow {
            transform: rotate(180deg);
        }

        .detail-body {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .detail-card.open .detail-body {
            max-height: 800px;
        }

        .detail-list {
            padding: 0 1rem 0.75rem;
            display: grid;
            grid-template-columns: 1fr;
            gap: 0.5rem;
            border-top: 1px solid #e7e5e4;
            padding-top: 0.75rem;
        }

        .dl-item {
            background: #fff;
            border: 1px solid #e7e5e4;
            border-radius: 0.625rem;
            padding: 0.75rem 1rem;
            transition: border-color 0.15s;
        }

        .dl-item:hover {
            border-color: #d6d3d1;
        }

        .dl-key {
            font-size: 0.625rem;
            font-weight: 500;
            color: #a8a29e;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 0.25rem;
        }

        .dl-val {
            font-size: 0.8125rem;
            color: #44403c;
            word-break: break-all;
        }

        a.dl-val {
            color: #78716c;
            text-decoration: underline;
            text-underline-offset: 0.15em;
        }

        a.dl-val:hover {
            color: #44403c;
        }

        .footer {
            text-align: center;
            padding: 1.5rem 2rem;
            color: #c4b5a6;
            font-size: 0.75rem;
            line-height: 1.6;
        }

        .footer p {
            margin: 0;
        }

        @media (max-width: 640px) {
            .input-row {
                flex-direction: column;
            }
            .options-row {
                grid-template-columns: 1fr;
            }
            .info-grid {
                grid-template-columns: 1fr;
            }
            .actions-row {
                gap: 0.5rem;
            }
            .btn-action {
                flex: 1;
                justify-content: center;
                min-width: 0;
            }
            .btn-raw {
                margin-left: 0;
                order: 3;
            }
        }
    </style>
</head>
<body>
    <div class="globe-bg">
        <canvas id="globeCanvas"></canvas>
    </div>

    <div class="main-wrap">
        <div class="site-title">WhoisWorker</div>
        <h1 class="hero-title">Domain Lookup</h1>
        <p class="hero-sub">Look up domain, IP address, and ASN registration data via RDAP and WHOIS protocols.</p>

        <div class="search-box">
            <form id="searchForm">
                <div class="input-row">
                    <input type="text" id="queryInput" class="query-input"
                           placeholder="example.com / 8.8.8.8 / AS15169"
                           required autofocus>
                    <button type="submit" class="submit-btn">Lookup</button>
                </div>
                <div id="optRow" class="options-row">
                    <select id="queryType" class="opt-select">
                        <option value="auto">Auto Detect</option>
                        <option value="domain">Domain</option>
                        <option value="ip">IP Address</option>
                        <option value="asn">ASN</option>
                    </select>
                    <select id="queryMode" class="opt-select">
                        <option value="auto">RDAP + WHOIS</option>
                        <option value="rdap">RDAP Only</option>
                        <option value="whois">WHOIS Only</option>
                    </select>
                </div>
            </form>
        </div>
        <button type="button" id="optToggle" class="options-toggle">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
            </svg>
            Options
        </button>

        <div id="loading" class="loading-state">
            <div class="spinner"></div>
            <div class="loading-text">Looking up...</div>
        </div>

        <div id="resultPanel" class="result-panel">
            <div class="result-card">
                <div class="result-head">
                    <div id="resultTitle" class="result-domain"></div>
                    <div id="resultMeta" class="result-meta"></div>
                </div>
                <div id="resultBody"></div>
                <div class="actions-row">
                    <button id="btnNew" class="btn-action btn-new">New Lookup</button>
                    <button id="btnCopyRaw" class="btn-action btn-raw">Copy Raw</button>
                    <button id="btnCopy" class="btn-action btn-copy">Copy JSON</button>
                </div>
            </div>
        </div>

    </div>

    <footer class="footer">
        WhoisWorker &middot; RDAP + WHOIS &middot; For reference only
    </footer>

    <script>
        // ── Options Toggle ──
        const optToggle = document.getElementById('optToggle');
        const optRow = document.getElementById('optRow');
        optToggle.addEventListener('click', () => {
            optRow.classList.toggle('show');
            optToggle.classList.toggle('open');
        });

        // ── Globe Wireframe ──
        (function () {
            const canvas = document.getElementById('globeCanvas');
            const ctx = canvas.getContext('2d');
            let w, h, cx, cy, r;

            function resize() {
                const dpr = window.devicePixelRatio || 1;
                w = window.innerWidth;
                h = window.innerHeight;
                canvas.width = w * dpr;
                canvas.height = h * dpr;
                canvas.style.width = w + 'px';
                canvas.style.height = h + 'px';
                ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
                cx = w / 2;
                cy = h / 2;
                r = Math.min(w, h) * 0.45;
            }

            window.addEventListener('resize', resize);
            resize();

            const lonCount = 12;
            const latCount = 8;
            let angle = 0;

            function project(lat, lon, a) {
                const cosLat = Math.cos(lat);
                const sinLat = Math.sin(lat);
                const cosLon = Math.cos(lon + a);
                const sinLon = Math.sin(lon + a);
                const x = cosLat * sinLon;
                const y = -sinLat;
                const z = cosLat * cosLon;
                return { x: cx + x * r, y: cy + y * r, z };
            }

            function draw() {
                ctx.clearRect(0, 0, w, h);
                angle += 0.002;

                for (let i = 0; i < lonCount; i++) {
                    const lon = (i / lonCount) * Math.PI * 2;
                    ctx.beginPath();
                    let started = false;
                    for (let j = 0; j <= 64; j++) {
                        const lat = (j / 64) * Math.PI - Math.PI / 2;
                        const p = project(lat, lon, angle);
                        if (p.z < 0) { started = false; continue; }
                        if (!started) { ctx.moveTo(p.x, p.y); started = true; }
                        else ctx.lineTo(p.x, p.y);
                    }
                    ctx.strokeStyle = 'rgba(168,162,158,0.18)';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }

                for (let i = 1; i < latCount; i++) {
                    const lat = (i / latCount) * Math.PI - Math.PI / 2;
                    ctx.beginPath();
                    let started = false;
                    for (let j = 0; j <= 64; j++) {
                        const lon = (j / 64) * Math.PI * 2;
                        const p = project(lat, lon, angle);
                        if (p.z < 0) { started = false; continue; }
                        if (!started) { ctx.moveTo(p.x, p.y); started = true; }
                        else ctx.lineTo(p.x, p.y);
                    }
                    ctx.strokeStyle = 'rgba(168,162,158,0.18)';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }

                ctx.beginPath();
                let started = false;
                for (let j = 0; j <= 64; j++) {
                    const lon = (j / 64) * Math.PI * 2;
                    const p = project(0, lon, angle);
                    if (p.z < 0) { started = false; continue; }
                    if (!started) { ctx.moveTo(p.x, p.y); started = true; }
                    else ctx.lineTo(p.x, p.y);
                }
                ctx.strokeStyle = 'rgba(168,162,158,0.3)';
                ctx.lineWidth = 1.2;
                ctx.stroke();

                ctx.beginPath();
                ctx.arc(cx, cy, r, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(168,162,158,0.12)';
                ctx.lineWidth = 1;
                ctx.stroke();

                requestAnimationFrame(draw);
            }

            draw();
        })();

        // ── Whois Query Logic ──
        const API_BASE = location.origin;
        const $ = id => document.getElementById(id);

        const form = $('searchForm');
        const input = $('queryInput');
        const typeSel = $('queryType');
        const modeSel = $('queryMode');
        const loading = $('loading');
        const panel = $('resultPanel');
        const body = $('resultBody');

        form.addEventListener('submit', async e => {
            e.preventDefault();
            const q = input.value.trim();
            if (!q) return;
            loading.style.display = 'block';
            panel.style.display = 'none';
            try {
                const p = new URLSearchParams();
                const t = typeSel.value;
                if (t === 'domain' || (t === 'auto' && q.match(/^(https?:\\/\\/)?[\\w.-]+\\.[a-z]{2,}$/i)))
                    p.set('domain', q);
                else if (t === 'ip' || (t === 'auto' && q.match(/^\\d{1,3}(\\.\\d{1,3}){3}$/)))
                    p.set('ip', q);
                else if (t === 'asn' || (t === 'auto' && q.match(/^AS\\d+$/i)))
                    p.set('asn', q);
                else p.set('domain', q);
                p.set('mode', modeSel.value);
                p.set('raw', '1');
                p.set('trace', '1');
                const res = await fetch(\`\${API_BASE}?\${p}\`);
                const data = await res.json();
                loading.style.display = 'none';
                if (res.ok) renderResult(data);
                else renderError(data.error || 'Lookup failed');
            } catch (err) {
                loading.style.display = 'none';
                renderError(err.message);
            }
        });

        function esc(s) {
            if (s == null) return '\\u2014';
            if (typeof s === 'object') return s.name || JSON.stringify(s);
            return String(s);
        }

        function renderResult(data) {
            panel.style.display = 'block';
            $('resultTitle').textContent = data.domain || data.ip || data.asn || 'Result';
            $('resultMeta').textContent = data.queryType || '';

            let html = '';

            // Status tags — first
            if (data.status?.length) {
                html += '<div class="section"><div class="section-label">Status</div><div class="status-tags">';
                data.status.forEach(s => { html += '<span class="status-tag">' + esc(s) + '</span>'; });
                html += '</div></div>';
            }

            // Domain
            if (data.domain) {
                const TB = '<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd"/></svg>';
                const hasReg = data.registrar && (typeof data.registrar === 'object' ? data.registrar.name : data.registrar);
                const hasRegy = data.registry && (typeof data.registry === 'object' ? data.registry.name : data.registry);
                if (hasReg || hasRegy) {
                    html += '<div class="section"><div class="section-label">Domain</div><div class="info-grid">';

                // Registrar
                if (data.registrar && typeof data.registrar === 'object' && data.registrar.name) {
                    const r = data.registrar;
                    html += '<div class="info-item has-toggle"><div class="info-item-head"><div><div class="info-key">Registrar</div><div class="info-val">' + esc(r.name) + '</div></div><button class="toggle-btn" onclick="this.classList.toggle(\\'open\\');var d=this.closest(\\'.has-toggle\\').querySelector(\\'.toggle-detail\\');d.classList.toggle(\\'open\\')">' + TB + '</button></div><div class="toggle-detail">';
                    if (r.website) html += '<div class="info-item full"><div class="info-key">Website</div><a class="info-val" href="' + esc(r.website) + '" target="_blank" rel="noopener" style="color:#78716c;text-decoration:underline">' + esc(r.website) + '</a></div>';
                    if (r.ianaId) html += ii('IANA ID', r.ianaId);
                    if (r.whoisServer) html += ii('WHOIS Server', r.whoisServer);
                    if (r.rdapUrl) html += ii('RDAP URL', r.rdapUrl);
                    if (r.status) html += ii('Status', r.status);
                    if (r.country) html += ii('Country', r.country);
                    if (r.contact) {
                        if (r.contact.name) html += ii('Contact', r.contact.name);
                        if (r.contact.email) html += il('Email', 'mailto:' + r.contact.email, r.contact.email);
                        if (r.contact.phone) html += ii('Phone', r.contact.phone);
                    }
                    html += '</div></div>';
                } else if (data.registrar && typeof data.registrar === 'string' && data.registrar.trim()) {
                    html += ii('Registrar', data.registrar);
                }

                // Registry
                if (data.registry && typeof data.registry === 'object' && data.registry.name) {
                    const g = data.registry;
                    html += '<div class="info-item has-toggle"><div class="info-item-head"><div><div class="info-key">Registry</div><div class="info-val">' + esc(g.name) + '</div></div><button class="toggle-btn" onclick="this.classList.toggle(\\'open\\');var d=this.closest(\\'.has-toggle\\').querySelector(\\'.toggle-detail\\');d.classList.toggle(\\'open\\')">' + TB + '</button></div><div class="toggle-detail">';
                    if (g.website) html += '<div class="info-item full"><div class="info-key">Website</div><a class="info-val" href="' + esc(g.website) + '" target="_blank" rel="noopener" style="color:#78716c;text-decoration:underline">' + esc(g.website) + '</a></div>';
                    if (g.type) html += ii('Type', g.type);
                    if (g.manager) html += ii('Manager', g.manager);
                    if (g.whoisServer) html += ii('WHOIS Server', g.whoisServer);
                    if (g.rdapEndpoint) html += ii('RDAP Endpoint', g.rdapEndpoint);
                    if (g.registrationDate) html += ii('Registration Date', g.registrationDate);
                    if (g.lastUpdated) html += ii('Last Updated', g.lastUpdated);
                    if (g.adminContact) {
                        if (g.adminContact.name) html += ii('Admin Contact', g.adminContact.name);
                        if (g.adminContact.email) html += il('Admin Email', 'mailto:' + g.adminContact.email, g.adminContact.email);
                    }
                    if (g.techContact) {
                        if (g.techContact.name) html += ii('Tech Contact', g.techContact.name);
                        if (g.techContact.email) html += il('Tech Email', 'mailto:' + g.techContact.email, g.techContact.email);
                    }
                    if (g.sponsoringOrganisation) html += '<div class="info-item full"><div class="info-key">Sponsoring Organisation</div><div class="info-val">' + esc(g.sponsoringOrganisation) + '</div></div>';
                    html += '</div></div>';
                } else if (data.registry && typeof data.registry === 'string' && data.registry.trim()) {
                    html += ii('Registry', data.registry);
                }

                html += '</div></div>';
                }
            }

            // Contacts
            if (data.contacts?.length) {
                data.contacts.forEach((c, i) => {
                    const items = [];
                    if (c.name) items.push(['Name', c.name]);
                    if (c.organization) items.push(['Organization', c.organization]);
                    if (c.email) items.push(['Email', c.email]);
                    if (c.phone) items.push(['Phone', c.phone]);
                    if (c.roles) items.push(['Roles', c.roles.join(', ')]);
                    if (items.length) {
                        const label = c.roles?.[0] ? c.roles[0].charAt(0).toUpperCase() + c.roles[0].slice(1) : 'Contact ' + (i + 1);
                        html += sec(label, items);
                    }
                });
            }

            // Privacy — full width, amber border when private
            if (data.privacy) {
                const isPrivate = data.privacy.isPrivate;
                const cls = isPrivate ? 'info-item full border-amber' : 'info-item full';
                let inner = '<div class="info-key">Privacy Protection</div><div class="info-val">' + (isPrivate ? 'Yes' : 'No') + '</div>';
                if (data.privacy.registrar) inner += '<div class="info-key" style="margin-top:0.5rem">Provider</div><div class="info-val">' + esc(data.privacy.registrar) + '</div>';
                html += '<div class="section"><div class="section-label">Privacy</div><div class="info-grid">'
                    + '<div class="' + cls + '">' + inner + '</div>'
                    + '</div></div>';
            }

            // DNSSEC — full width, green border when signed
            if (data.dnssec) {
                const signed = data.dnssec.signed || data.dnssec.delegationSigned;
                const cls = signed ? 'info-item full border-green' : 'info-item full';
                html += '<div class="section"><div class="section-label">DNSSEC</div><div class="info-grid">'
                    + '<div class="' + cls + '"><div class="info-key">Status</div><div class="info-val">' + (signed ? 'Signed' : 'Unsigned') + '</div></div>'
                    + '</div></div>';
            }

            // Dates
            if (data.dates) {
                const d = [];
                if (data.dates.created) d.push(['Created', fmt(data.dates.created)]);
                if (data.dates.updated) d.push(['Updated', fmt(data.dates.updated)]);
                if (data.dates.expires) d.push(['Expires', fmt(data.dates.expires)]);
                if (d.length) html += sec('Dates', d);
            }

            // Nameservers
            if (data.nameServers?.length) {
                html += '<div class="section"><div class="section-label">Nameservers</div><div class="info-item ns-list">' + data.nameServers.join('<br>') + '</div></div>';
            }

            // Trace
            if (data.trace?.length) {
                html += '<div class="section"><div class="section-label">Trace</div><div class="trace-list">';
                data.trace.forEach(t => {
                    const ok = t.success;
                    html += '<div class="trace-item">'
                        + '<span class="trace-dot ' + (ok ? 'ok' : 'fail') + '"></span>'
                        + '<span class="trace-proto">' + esc(t.protocol) + '</span>'
                        + '<span class="trace-endpoint">' + esc(t.endpoint) + '</span>'
                        + '<span class="trace-status ' + (ok ? 'ok' : 'fail') + '">' + (ok ? 'OK' : 'FAIL') + '</span>'
                        + '</div>';
                });
                html += '</div></div>';
            }

            // Raw response
            if (data.rawResponse) {
                html += '<div class="section"><div class="section-label">Raw Response</div><div class="raw-block"><pre class="raw-pre">' + esc(data.rawResponse) + '</pre></div></div>';
            }

            body.innerHTML = html;
            const json = JSON.stringify(data, null, 2);
            $('btnCopy').dataset.json = json;
            $('btnCopyRaw').dataset.raw = data.rawResponse || json;
        }

        function sec(title, pairs) {
            let h = '<div class="section"><div class="section-label">' + title + '</div><div class="info-grid">';
            pairs.forEach(function(pair) {
                h += ii(pair[0], pair[1]);
            });
            return h + '</div></div>';
        }

        function ii(key, val) {
            return '<div class="info-item"><div class="info-key">' + key + '</div><div class="info-val">' + esc(val) + '</div></div>';
        }

        function il(key, href, text) {
            return '<div class="info-item"><div class="info-key">' + key + '</div><a class="info-val" href="' + esc(href) + '" target="_blank" rel="noopener" style="color:#78716c;text-decoration:underline">' + esc(text || href) + '</a></div>';
        }

        function fmt(s) {
            try { return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit' }); }
            catch(e) { return s; }
        }

        function renderError(msg) {
            panel.style.display = 'block';
            $('resultTitle').textContent = 'Lookup Failed';
            $('resultMeta').textContent = '';
            body.innerHTML = '<div class="error-box">' + msg + '</div>';
        }

        $('btnNew').addEventListener('click', () => {
            panel.style.display = 'none';
            input.value = '';
            input.focus();
        });

        $('btnCopy').addEventListener('click', () => {
            const j = $('btnCopy').dataset.json;
            if (j) navigator.clipboard.writeText(j).then(() => {
                const orig = $('btnCopy').textContent;
                $('btnCopy').textContent = 'Copied';
                setTimeout(() => $('btnCopy').textContent = orig, 1500);
            });
        });

        $('btnCopyRaw').addEventListener('click', () => {
            const r = $('btnCopyRaw').dataset.raw;
            if (r) navigator.clipboard.writeText(r).then(() => {
                const orig = $('btnCopyRaw').textContent;
                $('btnCopyRaw').textContent = 'Copied';
                setTimeout(() => $('btnCopyRaw').textContent = orig, 1500);
            });
        });

        window.addEventListener('DOMContentLoaded', () => {
            const p = new URLSearchParams(location.search);
            const q = p.get('domain') || p.get('ip') || p.get('asn');
            if (q) { input.value = q; form.dispatchEvent(new Event('submit')); }
        });
    </script>
</body>
</html>
`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Only allow GET
    if (request.method !== 'GET') {
      return errorResponse('Method not allowed', 405, origin);
    }

    // Serve HTML page for browser visits (no query params)
    const hasQuery = url.searchParams.has('domain') || url.searchParams.has('ip') || url.searchParams.has('asn');
    if (!hasQuery && url.pathname === '/') {
      const accept = request.headers.get('Accept') || '';
      if (accept.includes('text/html')) {
        return htmlResponse(HTML_PAGE, origin);
      }
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
