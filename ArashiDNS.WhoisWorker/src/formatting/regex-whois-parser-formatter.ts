import { parse, ParserBase, ParserRegistry } from 'whois-parser';
import type { WhoisResponse, WhoisQueryType, ContactInfo, RegistrarInfo, DomainDates, DnssecInfo } from '../types';
import type { Contact, Nameserver, Registrar } from 'whois-parser';

export class RegexWhoisParserFormatter {
  parse(rawResponse: string, query: string, queryType: WhoisQueryType, whoisServer?: string): WhoisResponse | null {
    if (!rawResponse) return null;

    try {
      const parser = parse(rawResponse, whoisServer);
      if (!parser) return null;

      return this.mapToWhoisResponse(parser, query, queryType, rawResponse);
    } catch {
      return null;
    }
  }

  private mapToWhoisResponse(parser: ParserBase, query: string, queryType: WhoisQueryType, rawResponse: string): WhoisResponse | null {
    const domain = parser.domain?.toLowerCase() || query;
    const registrar = this.mapRegistrar(parser.registrar);
    const dates = this.mapDates(parser);
    const contacts = this.mapContacts(parser);
    const nameServers = this.mapNameservers(parser.nameservers);
    const status = this.mapStatus(parser.status);
    const dnssec = this.mapDnssec(parser);

    return {
      query,
      queryType,
      domain,
      isSuccessful: true,
      whoisServer: '',
      port43: null,
      rawResponse,
      referralChain: [],
      errorMessage: null,
      statuses: status,
      nameServers,
      dates,
      contacts,
      registrar,
      registry: null,
      privacy: null,
      dnssec,
    };
  }

  private mapRegistrar(registrar: Registrar | null | undefined): RegistrarInfo | null {
    if (!registrar) return null;
    return {
      name: registrar.name || '',
      ianaId: registrar.id || '',
      website: registrar.url || '',
      whoisServer: '',
    };
  }

  private mapDates(parser: ParserBase): DomainDates | null {
    const created = parser.createdOn;
    const updated = parser.updatedOn;
    const expires = parser.expiresOn;

    if (!created && !updated && !expires) return null;

    return {
      created: created ? this.formatDate(created) : null,
      updated: updated ? this.formatDate(updated) : null,
      expires: expires ? this.formatDate(expires) : null,
    };
  }

  private formatDate(date: Date): string {
    try {
      return date.toISOString().split('T')[0];
    } catch {
      return '';
    }
  }

  private mapContacts(parser: ParserBase): { registrant: ContactInfo | null; admin: ContactInfo | null; tech: ContactInfo | null; billing: ContactInfo | null } {
    const registrant = this.findContactByType(parser.registrantContacts, 'registrant');
    const admin = this.findContactByType(parser.adminContacts, 'admin');
    const tech = this.findContactByType(parser.technicalContacts, 'tech');

    return {
      registrant: registrant ? this.mapContact(registrant) : null,
      admin: admin ? this.mapContact(admin) : null,
      tech: tech ? this.mapContact(tech) : null,
      billing: null,
    };
  }

  private findContactByType(contacts: Contact[] | null | undefined, type: string): Contact | null {
    if (!contacts || contacts.length === 0) return null;
    return contacts[0] || null;
  }

  private mapContact(contact: Contact): ContactInfo {
    return {
      name: contact.name || '',
      organization: contact.organization || '',
      email: contact.email || '',
      phone: contact.phone || '',
      street: contact.address || '',
      city: contact.city || '',
      state: contact.state || '',
      postalCode: contact.zip || '',
      country: contact.countryCode || contact.country || '',
      roles: [],
    };
  }

  private mapNameservers(nameservers: Nameserver[] | null | undefined): string[] {
    if (!nameservers) return [];
    return nameservers
      .map(ns => ns.name?.toLowerCase().trim())
      .filter((name): name is string => !!name);
  }

  private mapStatus(status: unknown): string[] {
    if (!status) return [];
    if (Array.isArray(status)) {
      return status
        .map(s => {
          if (typeof s === 'string') {
            return s.split(/[\s\t]+/)
              .map(part => part.trim().toLowerCase())
              .filter(part => part && !part.startsWith('http') && !part.startsWith('('));
          }
          return [];
        })
        .flat()
        .filter((s): s is string => !!s);
    }
    if (typeof status === 'string') {
      return status.split(/[\s\t]+/)
        .map(s => s.trim().toLowerCase())
        .filter(s => s && !s.startsWith('http') && !s.startsWith('('));
    }
    return [];
  }

  private mapDnssec(parser: ParserBase): DnssecInfo | null {
    const status = parser.status;
    if (!status) return null;

    const statusStr = Array.isArray(status) ? status.join(' ') : String(status);
    const signed = !statusStr.toLowerCase().includes('unsigned') && statusStr.toLowerCase() !== 'no';

    return {
      signed,
      delegationSigned: signed,
      dsData: [],
      keyData: [],
    };
  }
}
