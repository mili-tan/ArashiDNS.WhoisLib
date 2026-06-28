const TLD_DATA_URL = 'https://github.com/NovaXNS/tlddata/releases/latest/download/iana_tlds.json';
const CACHE_KEY = 'ext_tlddata';
const CACHE_TTL = 60 * 60 * 24 * 90; // 90 days (1 quarter)

export interface TldEntry {
  tld: string;
  domain?: string;
  type?: string;
  manager?: string;
  sponsoring_organisation?: string;
  admin_contact?: { name?: string; email?: string; voice?: string; fax?: string };
  tech_contact?: { name?: string; email?: string; voice?: string; fax?: string };
  name_servers?: string[];
  whois_server?: string;
  rdap_server?: string;
  registration_url?: string;
  record_last_updated?: string;
  registration_date?: string;
}

export class TldDataProvider {
  private kv: KVNamespace;
  private data: Map<string, TldEntry> | null = null;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getTldInfo(tld: string): Promise<TldEntry | null> {
    await this.ensureLoaded();
    return this.data?.get(tld.toLowerCase()) ?? null;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.data) return;

    const cached = await this.kv.get<Record<string, TldEntry>>(CACHE_KEY, 'json');
    if (cached) {
      this.data = new Map(Object.entries(cached));
      return;
    }

    try {
      const resp = await fetch(TLD_DATA_URL);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json() as TldEntry[];

      const map: Record<string, TldEntry> = {};
      for (const entry of json) {
        const key = (entry.tld || entry.domain || '').toLowerCase().replace(/^\./, '');
        if (key) map[key] = entry;
      }

      this.data = new Map(Object.entries(map));
      await this.kv.put(CACHE_KEY, JSON.stringify(map), { expirationTtl: CACHE_TTL });
    } catch {
      this.data = new Map();
    }
  }
}
