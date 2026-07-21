import type { WhoisResponse, FormattedResult, Env, ContactInfo } from '../types';
import { detectPrivacy } from '../detection/privacy-detector';
import { detectAvailability } from '../detection/availability-detector';
import { normalizeGeo, extractCountryFromAddress } from '../detection/geo-normalizer';
import { RegexWhoisParserFormatter } from './regex-whois-parser-formatter';
import { LlmFormatter } from './llm-formatter';
import { identifyRegistry } from '../data/registry-identifier';

export class MultiLayerFormatter {
  private regexParser = new RegexWhoisParserFormatter();
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
    // Layer 0: Availability check
    if (response.rawResponse) {
      const availability = detectAvailability(response.rawResponse);
      if (availability.isAvailable) {
        this.lastUsedLayer = 'Availability';
        return {
          domain: response.query,
          registry: null, registrar: null,
          privacy: { isPrivate: false, provider: null },
          contacts: [], dates: null, nameServers: [],
          status: ['available'], dnssec: null,
        };
      }
    }

    // Layer 1: RegexWhoisParser (primary)
    if (response.rawResponse) {
      const regexResult = this.regexParser.parse(response.rawResponse, response.query, response.queryType, response.whoisServer);
      if (regexResult && this.hasUsefulData(regexResult)) {
        // Check if critical data is missing
        if (this.hasCriticalData(regexResult)) {
          this.lastUsedLayer = 'RegexWhoisParser';
          return this.postProcess(regexResult);
        }
        // Missing critical data, try Traditional layer and merge
        if (this.hasUsefulData(response)) {
          this.mergeMissingFields(regexResult, response);
        }
        // Still missing critical data, try LLM
        if (!this.hasCriticalData(regexResult) && this.llmFormatter?.isEnabled) {
          const llmResult = await this.llmFormatter.format(response.rawResponse);
          if (llmResult) {
            this.mergeMissingFieldsFromFormatted(regexResult, llmResult);
          }
        }
        this.lastUsedLayer = 'RegexWhoisParser+Merge';
        return this.postProcess(regexResult);
      }
    }

    // Layer 2: Traditional (already parsed in whois-client.ts)
    if (this.hasUsefulData(response)) {
      if (this.hasCriticalData(response)) {
        this.lastUsedLayer = 'Traditional';
        return this.postProcess(response);
      }
      // Missing critical data, try LLM
      if (response.rawResponse && this.llmFormatter?.isEnabled) {
        const llmResult = await this.llmFormatter.format(response.rawResponse);
        if (llmResult) {
          this.mergeMissingFieldsFromFormatted(response, llmResult);
        }
      }
      this.lastUsedLayer = 'Traditional+Merge';
      return this.postProcess(response);
    }

    // Layer 3: LLM fallback
    if (this.llmFormatter?.isEnabled && response.rawResponse) {
      const llmResult = await this.llmFormatter.format(response.rawResponse);
      if (llmResult) {
        this.lastUsedLayer = 'LLM';
        return llmResult;
      }
    }

    // Fallback
    this.lastUsedLayer = 'Fallback';
    return this.postProcess(response);
  }

  private hasUsefulData(response: WhoisResponse): boolean {
    if (response.domain && response.domain !== response.query.toUpperCase()) return true;
    if (response.nameServers.length > 0) return true;
    if (response.statuses.length > 0) return true;
    if (response.dates?.created || response.dates?.expires) return true;
    if (response.registrar?.name) return true;

    const contacts = [
      response.contacts.registrant, response.contacts.admin,
      response.contacts.tech, response.contacts.billing,
    ].filter(Boolean);

    for (const c of contacts) {
      if (c && (c.name || c.organization || c.email)) return true;
    }
    return false;
  }

  private hasCriticalData(response: WhoisResponse): boolean {
    // Has creation or expiration date
    if (response.dates?.created || response.dates?.expires) return true;

    // Has registrant contact info
    const r = response.contacts.registrant;
    if (r && (r.name || r.organization || r.email)) return true;

    return false;
  }

  private mergeMissingFields(target: WhoisResponse, source: WhoisResponse): void {
    // Merge dates
    if (source.dates) {
      if (!target.dates) target.dates = { created: null, updated: null, expires: null };
      if (!target.dates.created && source.dates.created) target.dates.created = source.dates.created;
      if (!target.dates.updated && source.dates.updated) target.dates.updated = source.dates.updated;
      if (!target.dates.expires && source.dates.expires) target.dates.expires = source.dates.expires;
    }

    // Merge registrant contact
    if (source.contacts.registrant) {
      if (!target.contacts.registrant) {
        target.contacts.registrant = source.contacts.registrant;
      } else {
        const t = target.contacts.registrant;
        const s = source.contacts.registrant;
        if (!t.name && s.name) t.name = s.name;
        if (!t.organization && s.organization) t.organization = s.organization;
        if (!t.email && s.email) t.email = s.email;
        if (!t.phone && s.phone) t.phone = s.phone;
        if (!t.street && s.street) t.street = s.street;
        if (!t.city && s.city) t.city = s.city;
        if (!t.state && s.state) t.state = s.state;
        if (!t.postalCode && s.postalCode) t.postalCode = s.postalCode;
        if (!t.country && s.country) t.country = s.country;
      }
    }

    // Merge other contacts
    if (source.contacts.admin && !target.contacts.admin) {
      target.contacts.admin = source.contacts.admin;
    }
    if (source.contacts.tech && !target.contacts.tech) {
      target.contacts.tech = source.contacts.tech;
    }
    if (source.contacts.billing && !target.contacts.billing) {
      target.contacts.billing = source.contacts.billing;
    }

    // Merge registrar
    if (source.registrar) {
      if (!target.registrar) {
        target.registrar = source.registrar;
      } else {
        if (!target.registrar.name && source.registrar.name) target.registrar.name = source.registrar.name;
        if (!target.registrar.ianaId && source.registrar.ianaId) target.registrar.ianaId = source.registrar.ianaId;
        if (!target.registrar.website && source.registrar.website) target.registrar.website = source.registrar.website;
        if (!target.registrar.whoisServer && source.registrar.whoisServer) target.registrar.whoisServer = source.registrar.whoisServer;
      }
    }

    // Merge nameservers
    if (source.nameServers.length > 0 && target.nameServers.length === 0) {
      target.nameServers = source.nameServers;
    }

    // Merge statuses
    if (source.statuses.length > 0 && target.statuses.length === 0) {
      target.statuses = source.statuses;
    }
  }

  private mergeMissingFieldsFromFormatted(target: WhoisResponse, source: FormattedResult): void {
    // Merge dates
    if (source.dates) {
      if (!target.dates) target.dates = { created: null, updated: null, expires: null };
      if (!target.dates.created && source.dates.created) target.dates.created = source.dates.created;
      if (!target.dates.updated && source.dates.updated) target.dates.updated = source.dates.updated;
      if (!target.dates.expires && source.dates.expires) target.dates.expires = source.dates.expires;
    }

    // Merge registrant from contacts array
    const sourceRegistrant = source.contacts.find(c => c.roles.includes('registrant'));
    if (sourceRegistrant) {
      if (!target.contacts.registrant) {
        target.contacts.registrant = sourceRegistrant;
      } else {
        const t = target.contacts.registrant;
        if (!t.name && sourceRegistrant.name) t.name = sourceRegistrant.name;
        if (!t.organization && sourceRegistrant.organization) t.organization = sourceRegistrant.organization;
        if (!t.email && sourceRegistrant.email) t.email = sourceRegistrant.email;
        if (!t.phone && sourceRegistrant.phone) t.phone = sourceRegistrant.phone;
        if (!t.street && sourceRegistrant.street) t.street = sourceRegistrant.street;
        if (!t.city && sourceRegistrant.city) t.city = sourceRegistrant.city;
        if (!t.state && sourceRegistrant.state) t.state = sourceRegistrant.state;
        if (!t.postalCode && sourceRegistrant.postalCode) t.postalCode = sourceRegistrant.postalCode;
        if (!t.country && sourceRegistrant.country) t.country = sourceRegistrant.country;
      }
    }

    // Merge registrar
    if (source.registrar) {
      if (!target.registrar) {
        target.registrar = source.registrar;
      } else {
        if (!target.registrar.name && source.registrar.name) target.registrar.name = source.registrar.name;
        if (!target.registrar.ianaId && source.registrar.ianaId) target.registrar.ianaId = source.registrar.ianaId;
        if (!target.registrar.website && source.registrar.website) target.registrar.website = source.registrar.website;
        if (!target.registrar.whoisServer && source.registrar.whoisServer) target.registrar.whoisServer = source.registrar.whoisServer;
      }
    }

    // Merge nameservers
    if (source.nameServers.length > 0 && target.nameServers.length === 0) {
      target.nameServers = source.nameServers;
    }

    // Merge statuses
    if (source.status.length > 0 && target.statuses.length === 0) {
      target.statuses = source.status;
    }
  }

  private postProcess(response: WhoisResponse): FormattedResult {
    // Privacy detection
    const privacy = detectPrivacy(response);

    // Registry identification
    const registry = identifyRegistry(response);

    // Geo normalization for contacts
    const contacts = this.mergeAndNormalizeContacts(response.contacts);

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

  private mergeAndNormalizeContacts(contacts: {
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

      // Geo normalize
      if (contact.country) {
        const geo = normalizeGeo(contact.country);
        if (geo.countryCode) contact.country = geo.countryCode;
      } else if (contact.street) {
        const countryCode = extractCountryFromAddress(contact.street);
        if (countryCode) contact.country = countryCode;
      }

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
