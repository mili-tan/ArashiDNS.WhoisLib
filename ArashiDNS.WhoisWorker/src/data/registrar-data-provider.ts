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
    const id = ianaId?.trim();
    if (!id || !/^\d+$/.test(id)) return null;
    return this.byId?.get(id) ?? null;
  }

  async findByName(name: string): Promise<RegistrarDataEntry | null> {
    await this.ensureLoaded();
    const lower = name.toLowerCase().trim();
    // Exact match
    if (this.byName!.has(lower)) return this.byName!.get(lower)!;
    // Word match: all words (>=3 chars) from input must appear in key
    const words = lower.split(/\s+/).filter(w => w.length >= 3);
    if (words.length > 0) {
      for (const [key, entry] of this.byName!) {
        if (words.every(w => key.includes(w))) return entry;
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
      if (entry.iana_id) {
        const id = String(entry.iana_id).trim();
        if (/^\d+$/.test(id)) this.byId.set(id, entry);
      }
      if (entry.registrar_name) this.byName.set(entry.registrar_name.toLowerCase(), entry);
    }
  }
}
