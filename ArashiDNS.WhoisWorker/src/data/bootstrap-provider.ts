import type { Env } from '../types';

interface IpRdapRange {
  prefix: string;
  url: string;
}

interface AsnRdapRange {
  start: number;
  end: number;
  url: string;
}

interface BootstrapCache {
  dns: Record<string, string>;
  ipv4: IpRdapRange[];
  ipv6: IpRdapRange[];
  asn: AsnRdapRange[];
  fetchedAt: number;
}

const DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const IPV4_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json";
const IPV6_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv6.json";
const ASN_BOOTSTRAP_URL = "https://data.iana.org/rdap/asn.json";
const CACHE_KEY = "rdap_bootstrap_all";
const CACHE_TTL = 60 * 60 * 24 * 30; // 30 days

export class BootstrapProvider {
  private kv: KVNamespace;
  private cache: BootstrapCache | null = null;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getDnsRdapEndpoint(tld: string): Promise<string | null> {
    await this.ensureLoaded();
    return this.cache?.dns[tld.toLowerCase()] ?? null;
  }

  async getIpRdapEndpoint(ip: string): Promise<string | null> {
    await this.ensureLoaded();
    if (ip.includes(':')) return this.findIpv6Endpoint(ip);
    return this.findIpv4Endpoint(ip);
  }

  async getAsnRdapEndpoint(asn: number): Promise<string | null> {
    await this.ensureLoaded();
    return this.cache?.asn.find(r => asn >= r.start && asn <= r.end)?.url ?? null;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.cache) return;

    const cached = await this.kv.get<BootstrapCache>(CACHE_KEY, 'json');
    if (cached && cached.dns && cached.ipv4 && cached.ipv6 && cached.asn) {
      this.cache = cached;
      return;
    }

    try {
      const [dnsJson, ipv4Json, ipv6Json, asnJson] = await Promise.all([
        fetch(DNS_BOOTSTRAP_URL).then(r => r.json()) as Promise<{ services: [string[], string[]][] }>,
        fetch(IPV4_BOOTSTRAP_URL).then(r => r.json()) as Promise<{ services: [string[], string[]][] }>,
        fetch(IPV6_BOOTSTRAP_URL).then(r => r.json()) as Promise<{ services: [string[], string[]][] }>,
        fetch(ASN_BOOTSTRAP_URL).then(r => r.json()) as Promise<{ services: [string[], string[]][] }>,
      ]);

      const dns: Record<string, string> = {};
      for (const [tlds, urls] of dnsJson.services) {
        if (urls.length > 0) {
          for (const tld of tlds) dns[tld.toLowerCase()] = urls[0];
        }
      }

      const parseIpRanges = (data: { services: [string[], string[]][] }): IpRdapRange[] => {
        const ranges: IpRdapRange[] = [];
        for (const [prefixes, urls] of data.services) {
          if (urls.length > 0) {
            for (const prefix of prefixes) ranges.push({ prefix, url: urls[0] });
          }
        }
        return ranges;
      };

      const parseAsnRanges = (data: { services: [string[], string[]][] }): AsnRdapRange[] => {
        const ranges: AsnRdapRange[] = [];
        for (const [asnRanges, urls] of data.services) {
          if (urls.length > 0) {
            for (const rangeStr of asnRanges) {
              const parts = rangeStr.split('-');
              if (parts.length === 2) {
                const start = parseInt(parts[0], 10);
                const end = parseInt(parts[1], 10);
                if (!isNaN(start) && !isNaN(end)) ranges.push({ start, end, url: urls[0] });
              }
            }
          }
        }
        return ranges;
      };

      this.cache = {
        dns,
        ipv4: parseIpRanges(ipv4Json),
        ipv6: parseIpRanges(ipv6Json),
        asn: parseAsnRanges(asnJson),
        fetchedAt: Date.now(),
      };

      await this.kv.put(CACHE_KEY, JSON.stringify(this.cache), { expirationTtl: CACHE_TTL });
    } catch {
      this.cache = { dns: {}, ipv4: [], ipv6: [], asn: [], fetchedAt: 0 };
    }
  }

  private findIpv4Endpoint(ip: string): string | null {
    if (!this.cache) return null;
    const parts = ip.split('.');
    if (parts.length < 1) return null;
    const prefix = `${parts[0]}.0.0.0/8`;
    return this.cache.ipv4.find(r => r.prefix === prefix)?.url ?? null;
  }

  private findIpv6Endpoint(ip: string): string | null {
    if (!this.cache) return null;
    return this.cache.ipv6.find(r => ip.startsWith(r.prefix.split('/')[0]))?.url ?? null;
  }
}
