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

const DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const IPV4_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json";
const IPV6_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv6.json";
const ASN_BOOTSTRAP_URL = "https://data.iana.org/rdap/asn.json";
const CACHE_TTL = 60 * 60 * 24 * 7; // 7 days in seconds

export class BootstrapProvider {
  private kv: KVNamespace;
  private dnsEndpoints: Map<string, string> | null = null;
  private ipv4Endpoints: IpRdapRange[] | null = null;
  private ipv6Endpoints: IpRdapRange[] | null = null;
  private asnEndpoints: AsnRdapRange[] | null = null;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getDnsRdapEndpoint(tld: string): Promise<string | null> {
    await this.ensureDnsEndpoints();
    return this.dnsEndpoints?.get(tld.toLowerCase()) ?? null;
  }

  async getIpRdapEndpoint(ip: string): Promise<string | null> {
    await this.ensureIpEndpoints();
    if (ip.includes(':')) {
      return this.findIpv6Endpoint(ip);
    }
    return this.findIpv4Endpoint(ip);
  }

  async getAsnRdapEndpoint(asn: number): Promise<string | null> {
    await this.ensureAsnEndpoints();
    return this.asnEndpoints?.find(r => asn >= r.start && asn <= r.end)?.url ?? null;
  }

  private async ensureDnsEndpoints(): Promise<void> {
    if (this.dnsEndpoints) return;

    const cached = await this.kv.get("rdap_bootstrap_dns", "json");
    if (cached) {
      this.dnsEndpoints = new Map(Object.entries(cached as Record<string, string>));
      return;
    }

    try {
      const resp = await fetch(DNS_BOOTSTRAP_URL);
      const data = await resp.json() as { services: [string[], string[]][] };
      const map: Record<string, string> = {};

      for (const [tlds, urls] of data.services) {
        if (urls.length > 0) {
          const url = urls[0];
          for (const tld of tlds) {
            map[tld.toLowerCase()] = url;
          }
        }
      }

      this.dnsEndpoints = new Map(Object.entries(map));
      await this.kv.put("rdap_bootstrap_dns", JSON.stringify(map), { expirationTtl: CACHE_TTL });
    } catch {
      this.dnsEndpoints = new Map();
    }
  }

  private async ensureIpEndpoints(): Promise<void> {
    if (this.ipv4Endpoints && this.ipv6Endpoints) return;

    const [cachedV4, cachedV6] = await Promise.all([
      this.kv.get("rdap_bootstrap_ipv4", "json"),
      this.kv.get("rdap_bootstrap_ipv6", "json"),
    ]);

    if (cachedV4 && cachedV6) {
      this.ipv4Endpoints = cachedV4 as IpRdapRange[];
      this.ipv6Endpoints = cachedV6 as IpRdapRange[];
      return;
    }

    try {
      const [v4, v6] = await Promise.all([
        this.loadIpBootstrap(IPV4_BOOTSTRAP_URL),
        this.loadIpBootstrap(IPV6_BOOTSTRAP_URL),
      ]);

      this.ipv4Endpoints = v4;
      this.ipv6Endpoints = v6;

      await Promise.all([
        this.kv.put("rdap_bootstrap_ipv4", JSON.stringify(v4), { expirationTtl: CACHE_TTL }),
        this.kv.put("rdap_bootstrap_ipv6", JSON.stringify(v6), { expirationTtl: CACHE_TTL }),
      ]);
    } catch {
      this.ipv4Endpoints = [];
      this.ipv6Endpoints = [];
    }
  }

  private async ensureAsnEndpoints(): Promise<void> {
    if (this.asnEndpoints) return;

    const cached = await this.kv.get("rdap_bootstrap_asn", "json");
    if (cached) {
      this.asnEndpoints = cached as AsnRdapRange[];
      return;
    }

    try {
      const resp = await fetch(ASN_BOOTSTRAP_URL);
      const data = await resp.json() as { services: [string[], string[]][] };
      const ranges: AsnRdapRange[] = [];

      for (const [asnRanges, urls] of data.services) {
        if (urls.length > 0) {
          const url = urls[0];
          for (const rangeStr of asnRanges) {
            const parts = rangeStr.split('-');
            if (parts.length === 2) {
              const start = parseInt(parts[0], 10);
              const end = parseInt(parts[1], 10);
              if (!isNaN(start) && !isNaN(end)) {
                ranges.push({ start, end, url });
              }
            }
          }
        }
      }

      this.asnEndpoints = ranges;
      await this.kv.put("rdap_bootstrap_asn", JSON.stringify(ranges), { expirationTtl: CACHE_TTL });
    } catch {
      this.asnEndpoints = [];
    }
  }

  private async loadIpBootstrap(url: string): Promise<IpRdapRange[]> {
    const resp = await fetch(url);
    const data = await resp.json() as { services: [string[], string[]][] };
    const ranges: IpRdapRange[] = [];

    for (const [prefixes, urls] of data.services) {
      if (urls.length > 0) {
        const rdapUrl = urls[0];
        for (const prefix of prefixes) {
          ranges.push({ prefix, url: rdapUrl });
        }
      }
    }

    return ranges;
  }

  private findIpv4Endpoint(ip: string): string | null {
    if (!this.ipv4Endpoints) return null;
    const parts = ip.split('.');
    if (parts.length < 1) return null;
    const prefix = `${parts[0]}.0.0.0/8`;
    return this.ipv4Endpoints.find(r => r.prefix === prefix)?.url ?? null;
  }

  private findIpv6Endpoint(ip: string): string | null {
    if (!this.ipv6Endpoints) return null;
    return this.ipv6Endpoints.find(r => ip.startsWith(r.prefix.split('/')[0]))?.url ?? null;
  }
}
