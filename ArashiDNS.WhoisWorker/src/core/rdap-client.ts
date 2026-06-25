import type { WhoisResponse, WhoisQueryType, TraceEntry } from '../types';
import { RdapParser } from './rdap-parser';
import { BootstrapProvider } from '../data/bootstrap-provider';
import { TLD_REGISTRY } from '../data/tld-registry';

export class RdapClient {
  private parser: RdapParser;
  private bootstrap: BootstrapProvider;
  private userAgent: string;

  constructor(bootstrap: BootstrapProvider, userAgent = 'WhoisWorker/1.0') {
    this.parser = new RdapParser();
    this.bootstrap = bootstrap;
    this.userAgent = userAgent;
  }

  async query(query: string, queryType: WhoisQueryType): Promise<{ response: WhoisResponse; trace: TraceEntry[] }> {
    const trace: TraceEntry[] = [];
    try {
      const endpoint = await this.getRdapEndpoint(query, queryType);
      if (!endpoint) {
        return {
          response: {
            query, queryType, domain: '', isSuccessful: false,
            errorMessage: `No RDAP endpoint found for ${query}`,
            whoisServer: '', port43: null, statuses: [], nameServers: [],
            dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
            registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain: [],
          },
          trace,
        };
      }
      return await this.queryWithReferral(query, queryType, endpoint, trace, 0);
    } catch (ex) {
      return {
        response: {
          query, queryType, domain: '', isSuccessful: false,
          errorMessage: `RDAP query error: ${(ex as Error).message}`,
          whoisServer: '', port43: null, statuses: [], nameServers: [],
          dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
          registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain: [],
        },
        trace,
      };
    }
  }

  private async queryWithReferral(
    query: string, queryType: WhoisQueryType, endpoint: string,
    trace: TraceEntry[], depth: number,
  ): Promise<{ response: WhoisResponse; trace: TraceEntry[] }> {
    const maxDepth = 3;
    if (depth >= maxDepth) {
      trace.push({ protocol: 'RDAP', endpoint, formatter: '', success: false, error: 'Referral depth exceeded' });
      return {
        response: {
          query, queryType, domain: '', isSuccessful: false,
          errorMessage: 'RDAP referral depth exceeded',
          whoisServer: endpoint, port43: null, statuses: [], nameServers: [],
          dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
          registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain: [],
        },
        trace,
      };
    }

    const { json, error } = await this.fetchRdap(endpoint);

    if (!json) {
      trace.push({ protocol: 'RDAP', endpoint, formatter: '', success: false, error: error || undefined });
      if (depth === 0) {
        return {
          response: {
            query, queryType, domain: '', isSuccessful: false,
            errorMessage: error || 'Unknown error',
            whoisServer: endpoint, port43: null, statuses: [], nameServers: [],
            dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
            registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain: [],
          },
          trace,
        };
      }
      return {
        response: {
          query, queryType, domain: '', isSuccessful: true,
          whoisServer: endpoint, port43: null, statuses: [], nameServers: [],
          dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
          registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: '', referralChain: [],
          errorMessage: null,
        },
        trace,
      };
    }

    if (!this.parser.isValidRdap(json)) {
      trace.push({ protocol: 'RDAP', endpoint, formatter: '', success: false, error: 'Invalid RDAP response' });
      if (depth === 0) {
        return {
          response: {
            query, queryType, domain: '', isSuccessful: false,
            errorMessage: 'Invalid RDAP response',
            whoisServer: endpoint, port43: null, statuses: [], nameServers: [],
            dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
            registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain: [],
          },
          trace,
        };
      }
      return {
        response: {
          query, queryType, domain: '', isSuccessful: true,
          whoisServer: endpoint, port43: null, statuses: [], nameServers: [],
          dates: null, contacts: { registrant: null, admin: null, tech: null, billing: null },
          registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: '', referralChain: [],
          errorMessage: null,
        },
        trace,
      };
    }

    trace.push({ protocol: 'RDAP', endpoint, formatter: 'Traditional', success: true });
    const result = this.parser.parse(query, queryType, json, endpoint);

    if (result.isSuccessful && depth < maxDepth && this.needsReferral(result)) {
      const relatedLink = this.parser.extractRelatedLink(json);
      if (relatedLink) {
        const { response: referralResult, trace: referralTrace } = await this.queryWithReferral(query, queryType, relatedLink, trace, depth + 1);
        trace.push(...referralTrace);

        if (referralResult.isSuccessful && this.hasUsefulData(referralResult)) {
          this.mergeResults(result, referralResult);
          return { response: referralResult, trace };
        }
      }
    }

    return { response: result, trace };
  }

  private async fetchRdap(endpoint: string): Promise<{ json: string | null; error: string | null }> {
    try {
      const controller = new AbortController();
      const timeout = endpoint.includes('rdap.org') ? 3000 : 15000;
      const timer = setTimeout(() => controller.abort(), timeout);

      const resp = await fetch(endpoint, {
        headers: {
          'Accept': 'application/rdap+json',
          'User-Agent': this.userAgent,
        },
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!resp.ok) return { json: null, error: `RDAP query failed: ${resp.status}` };
      const json = await resp.text();
      return { json, error: null };
    } catch (ex) {
      if (ex instanceof Error && ex.name === 'AbortError') {
        return { json: null, error: 'RDAP query timed out' };
      }
      return { json: null, error: (ex as Error).message };
    }
  }

  private mergeResults(registryResult: WhoisResponse, referralResult: WhoisResponse): void {
    if (registryResult.dates) referralResult.dates = registryResult.dates;
    referralResult.registry = registryResult.registry;
    referralResult.domain = registryResult.domain;
    if (registryResult.statuses.length > 0) referralResult.statuses = registryResult.statuses;
    if (registryResult.nameServers.length > 0) referralResult.nameServers = registryResult.nameServers;
  }

  private hasUsefulData(result: WhoisResponse): boolean {
    const r = result.contacts.registrant;
    if (r && (r.name || r.organization || r.email)) return true;
    const t = result.contacts.tech;
    if (t && (t.name || t.organization || t.email)) return true;
    return false;
  }

  private needsReferral(result: WhoisResponse): boolean {
    if (!result.contacts.registrant && !result.contacts.tech) return true;
    const r = result.contacts.registrant;
    if (r && !r.name && !r.organization && !r.email) return true;
    return false;
  }

  private async getRdapEndpoint(query: string, queryType: WhoisQueryType): Promise<string | null> {
    if (queryType === 'domain') {
      const tld = this.extractTld(query);

      const bootstrapEndpoint = await this.bootstrap.getDnsRdapEndpoint(tld);
      if (bootstrapEndpoint) return this.constructDomainUrl(bootstrapEndpoint, query);

      const builtin = TLD_REGISTRY[tld.toLowerCase()];
      if (builtin?.rdapEndpoint) return this.constructDomainUrl(builtin.rdapEndpoint, query);

      return `https://rdap.org/domain/${encodeURIComponent(query.toLowerCase())}`;
    }

    if (queryType === 'ipv4' || queryType === 'ipv6') {
      const endpoint = await this.bootstrap.getIpRdapEndpoint(query);
      if (endpoint) return endpoint.replace(/\/$/, '') + '/ip/' + encodeURIComponent(query);
      return `https://rdap.org/ip/${encodeURIComponent(query)}`;
    }

    if (queryType === 'asn') {
      const asnStr = query.replace(/^AS/i, '');
      const asn = parseInt(asnStr, 10);
      if (!isNaN(asn)) {
        const endpoint = await this.bootstrap.getAsnRdapEndpoint(asn);
        if (endpoint) return endpoint.replace(/\/$/, '') + '/autnum/' + encodeURIComponent(asnStr);
      }
      return `https://rdap.org/autnum/${encodeURIComponent(asnStr)}`;
    }

    return null;
  }

  private constructDomainUrl(baseUrl: string, domain: string): string {
    const url = baseUrl.endsWith('/') ? baseUrl : baseUrl + '/';
    return url + 'domain/' + encodeURIComponent(domain.toLowerCase());
  }

  private extractTld(domain: string): string {
    const parts = domain.replace(/\.$/, '').split('.');
    return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : '';
  }
}

export function detectQueryType(query: string): WhoisQueryType {
  const normalized = query.trim();
  if (/^AS\d+$/i.test(normalized)) return 'asn';
  if (/^\d+$/.test(normalized)) return 'asn';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(normalized)) return 'ipv4';
  if (normalized.includes(':')) return 'ipv6';
  return 'domain';
}
