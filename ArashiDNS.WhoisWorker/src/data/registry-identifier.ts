import type { WhoisResponse, RegistryInfo, RegistrarInfo, RegistrarEntry } from '../types';
import { TLD_REGISTRY } from './tld-registry';
import { TldDataProvider } from './tld-data-provider';
import { RegistrarDataProvider } from './registrar-data-provider';

const REGISTRARS_URL = 'https://www.iana.org/assignments/registrar-ids/registrar-ids.xhtml';
const CACHE_TTL = 60 * 60 * 24 * 7; // 7 days

export class RegistrarProvider {
  private kv: KVNamespace;
  private registrars: RegistrarEntry[] | null = null;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async getRegistrars(): Promise<RegistrarEntry[]> {
    if (this.registrars) return this.registrars;

    const cached = await this.kv.get('iana_registrars', 'json');
    if (cached) {
      this.registrars = cached as RegistrarEntry[];
      return this.registrars;
    }

    try {
      this.registrars = await this.downloadRegistrars();
      await this.kv.put('iana_registrars', JSON.stringify(this.registrars), { expirationTtl: CACHE_TTL });
    } catch {
      this.registrars = [];
    }

    return this.registrars;
  }

  async findById(ianaId: string): Promise<RegistrarEntry | null> {
    const registrars = await this.getRegistrars();
    return registrars.find(r => r.id === ianaId) ?? null;
  }

  async findByName(name: string): Promise<RegistrarEntry | null> {
    const registrars = await this.getRegistrars();
    const normalizedName = name.toLowerCase().trim();
    return registrars.find(r =>
      r.name.toLowerCase().includes(normalizedName) ||
      normalizedName.includes(r.name.toLowerCase()),
    ) ?? null;
  }

  private async downloadRegistrars(): Promise<RegistrarEntry[]> {
    const resp = await fetch(REGISTRARS_URL);
    const html = await resp.text();
    const entries: RegistrarEntry[] = [];

    const rowRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
    let rowMatch;
    while ((rowMatch = rowRegex.exec(html)) !== null) {
      const row = rowMatch[1];
      const cellRegex = /<td[^>]*>([\s\S]*?)<\/td>/gi;
      const cells: string[] = [];
      let cellMatch;
      while ((cellMatch = cellRegex.exec(row)) !== null) {
        cells.push(cellMatch[1].replace(/<[^>]+>/g, '').trim());
      }

      if (cells.length >= 2) {
        const id = cells[0];
        const name = cells[1];
        const status = cells.length > 2 ? cells[2] : 'unknown';
        const rdapBaseUrl = cells.length > 3 ? cells[3] : '';

        if (id && name && /^\d+$/.test(id)) {
          entries.push({ id, name, status, rdapBaseUrl });
        }
      }
    }

    return entries;
  }
}

export function identifyRegistry(response: WhoisResponse): RegistryInfo | null {
  if (response.registry?.name) return response.registry;

  const tld = extractTld(response.domain);
  if (!tld) return null;

  return TLD_REGISTRY[tld.toLowerCase()] ? {
    name: TLD_REGISTRY[tld.toLowerCase()].registryName,
    website: TLD_REGISTRY[tld.toLowerCase()].website,
    whoisServer: TLD_REGISTRY[tld.toLowerCase()].whoisServer,
  } : { name: '', website: '', whoisServer: response.whoisServer };
}

export async function identifyRegistryFromTldData(
  response: WhoisResponse,
  tldProvider: TldDataProvider,
): Promise<RegistryInfo | null> {
  const tld = extractTld(response.domain);
  if (!tld) return null;

  const entry = await tldProvider.getTldInfo(tld);
  if (!entry) return null;

  return {
    name: entry.manager || entry.sponsoring_organisation || '',
    website: entry.registration_url || '',
    whoisServer: entry.whois_server || '',
    rdapEndpoint: entry.rdap_server || '',
    type: entry.type || '',
    manager: entry.manager || '',
    sponsoringOrganisation: entry.sponsoring_organisation || '',
    registrationDate: entry.registration_date || '',
    lastUpdated: entry.record_last_updated || '',
    adminContact: entry.admin_contact ? {
      name: entry.admin_contact.name,
      email: entry.admin_contact.email,
      voice: entry.admin_contact.voice,
      fax: entry.admin_contact.fax,
    } : undefined,
    techContact: entry.tech_contact ? {
      name: entry.tech_contact.name,
      email: entry.tech_contact.email,
      voice: entry.tech_contact.voice,
      fax: entry.tech_contact.fax,
    } : undefined,
  };
}

export async function identifyRegistrar(response: WhoisResponse, provider: RegistrarProvider): Promise<RegistrarInfo | null> {
  if (!response.registrar?.name) return null;

  const registrar = response.registrar;

  if (registrar.ianaId) {
    const entry = await provider.findById(registrar.ianaId);
    if (entry) {
      registrar.website = entry.rdapBaseUrl || registrar.website;
      return registrar;
    }
  }

  if (registrar.name) {
    const entry = await provider.findByName(registrar.name);
    if (entry) {
      registrar.ianaId = entry.id;
      registrar.website = entry.rdapBaseUrl || registrar.website;
      return registrar;
    }
  }

  return registrar;
}

export async function identifyRegistrarFromData(
  response: WhoisResponse,
  registrarDataProvider: RegistrarDataProvider,
): Promise<RegistrarInfo | null> {
  if (!response.registrar?.name) return null;

  const registrar = response.registrar;

  if (registrar.ianaId) {
    const entry = await registrarDataProvider.findById(registrar.ianaId);
    if (entry) {
      registrar.name = entry.registrar_name || registrar.name;
      registrar.website = entry.website || registrar.website;
      registrar.whoisServer = entry.whois_server || registrar.whoisServer;
      registrar.rdapUrl = entry.rdap_url || '';
      registrar.status = entry.status || '';
      registrar.country = entry.country || '';
      if (entry.contact) {
        registrar.contact = {
          name: entry.contact.name,
          phone: entry.contact.phone,
          email: entry.contact.email,
        };
      }
      return registrar;
    }
  }

  if (registrar.name) {
    const entry = await registrarDataProvider.findByName(registrar.name);
    if (entry) {
      registrar.ianaId = entry.iana_id || registrar.ianaId;
      registrar.name = entry.registrar_name || registrar.name;
      registrar.website = entry.website || registrar.website;
      registrar.whoisServer = entry.whois_server || registrar.whoisServer;
      registrar.rdapUrl = entry.rdap_url || '';
      registrar.status = entry.status || '';
      registrar.country = entry.country || '';
      if (entry.contact) {
        registrar.contact = {
          name: entry.contact.name,
          phone: entry.contact.phone,
          email: entry.contact.email,
        };
      }
      return registrar;
    }
  }

  return registrar;
}

function extractTld(domain: string): string {
  if (!domain) return '';
  const parts = domain.replace(/\.$/, '').split('.');
  return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : '';
}
