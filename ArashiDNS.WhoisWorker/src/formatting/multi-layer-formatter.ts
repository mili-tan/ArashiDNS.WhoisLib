import type { WhoisResponse, FormattedResult, Env, ContactInfo, PrivacyInfo } from '../types';
import { detectPrivacy } from '../detection/privacy-detector';
import { detectAvailability } from '../detection/availability-detector';
import { LlmFormatter } from './llm-formatter';
import { identifyRegistry } from '../data/registry-identifier';

export class MultiLayerFormatter {
  private llmFormatter: LlmFormatter | null = null;
  lastUsedLayer = '';

  constructor(env: Env) {
    if (env.DEEPSEEK_API_KEY) {
      this.llmFormatter = new LlmFormatter(env);
    }
  }

  get hasLlm(): boolean {
    return this.llmFormatter?.isEnabled ?? false;
  }

  async format(response: WhoisResponse): Promise<FormattedResult> {
    // Check availability first
    if (response.rawResponse) {
      const availability = detectAvailability(response.rawResponse);
      if (availability.isAvailable) {
        this.lastUsedLayer = 'Availability';
        return {
          domain: response.query,
          registry: null,
          registrar: null,
          privacy: { isPrivate: false, provider: null },
          contacts: [],
          dates: null,
          nameServers: [],
          status: ['available'],
          dnssec: null,
        };
      }
    }

    // Layer 1: Traditional (already parsed in whois-client.ts)
    if (this.hasUsefulData(response)) {
      this.lastUsedLayer = 'Traditional';
      return this.buildResult(response);
    }

    // Layer 2: LLM fallback
    if (this.llmFormatter?.isEnabled && response.rawResponse) {
      const llmResult = await this.llmFormatter.format(response.rawResponse);
      if (llmResult) {
        this.lastUsedLayer = 'LLM';
        return llmResult;
      }
    }

    // Fallback
    this.lastUsedLayer = 'Fallback';
    return this.buildResult(response);
  }

  private hasUsefulData(response: WhoisResponse): boolean {
    if (response.domain && response.domain !== response.query.toUpperCase()) return true;
    if (response.nameServers.length > 0) return true;
    if (response.statuses.length > 0) return true;
    if (response.dates?.created || response.dates?.expires) return true;
    if (response.registrar?.name) return true;

    const contacts = [
      response.contacts.registrant,
      response.contacts.admin,
      response.contacts.tech,
      response.contacts.billing,
    ].filter(Boolean);

    for (const c of contacts) {
      if (c && (c.name || c.organization || c.email)) return true;
    }

    return false;
  }

  private buildResult(response: WhoisResponse): FormattedResult {
    const privacy = detectPrivacy(response);
    const registry = identifyRegistry(response);

    const contacts = this.mergeContacts(response.contacts);

    return {
      domain: response.domain || response.query,
      registry,
      registrar: response.registrar,
      privacy,
      contacts,
      dates: response.dates,
      nameServers: response.nameServers,
      status: response.statuses,
      dnssec: response.dnssec,
    };
  }

  private mergeContacts(contacts: {
    registrant?: ContactInfo | null;
    admin?: ContactInfo | null;
    tech?: ContactInfo | null;
    billing?: ContactInfo | null;
  }): ContactInfo[] {
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
      const hash = this.contactHash(contact);
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

  private contactHash(c: ContactInfo): string {
    return [c.name, c.organization, c.email, c.phone, c.street, c.city, c.state, c.postalCode, c.country].join('|');
  }
}
