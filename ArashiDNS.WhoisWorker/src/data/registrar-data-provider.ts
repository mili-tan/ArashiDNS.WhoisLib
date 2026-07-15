const REGISTRAR_DATA_URL = 'https://github.com/NovaXNS/registrardata/releases/latest/download/merged_registrars.json';
const CACHE_KEY = 'ext_registrardata';
const CACHE_TTL = 60 * 60 * 24 * 90; // 90 days (1 quarter)

export interface RegistrarDataEntry {
  iana_id: string;
  registrar_name: string;
  status?: string;
  website?: string;
  rdap_url?: string;
  whois_server?: string;
  country?: string;
  contact?: {
    name?: string;
    phone?: string;
    email?: string;
  };
}

export class RegistrarDataProvider {
  private kv: KVNamespace;
  private byId: Map<string, RegistrarDataEntry> | null = null;
  private byName: Map<string, RegistrarDataEntry> | null = null;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async findById(ianaId: string): Promise<RegistrarDataEntry | null> {
    await this.ensureLoaded();
    return this.byId?.get(ianaId) ?? null;
  }

  async findByName(name: string): Promise<RegistrarDataEntry | null> {
    await this.ensureLoaded();
    const lower = name.toLowerCase().trim();
    // Exact match first
    if (this.byName!.has(lower)) return this.byName!.get(lower)!;
    // Partial match: input contains key OR key contains input (min 4 chars)
    if (lower.length >= 4) {
      for (const [key, entry] of this.byName!) {
        if (key.length >= 4 && (key.includes(lower) || lower.includes(key))) return entry;
      }
    }
    return null;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.byId && this.byName) return;

    const cached = await this.kv.get<RegistrarDataEntry[]>(CACHE_KEY, 'json');
    if (cached) {
      this.buildMaps(cached);
      return;
    }

    try {
      const resp = await fetch(REGISTRAR_DATA_URL);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json() as RegistrarDataEntry[];

      this.buildMaps(json);
      await this.kv.put(CACHE_KEY, JSON.stringify(json), { expirationTtl: CACHE_TTL });
    } catch {
      this.byId = new Map();
      this.byName = new Map();
    }
  }

  private buildMaps(entries: RegistrarDataEntry[]): void {
    this.byId = new Map();
    this.byName = new Map();
    for (const entry of entries) {
      if (entry.iana_id) this.byId.set(entry.iana_id, entry);
      if (entry.registrar_name) this.byName.set(entry.registrar_name.toLowerCase(), entry);
    }
  }
}
