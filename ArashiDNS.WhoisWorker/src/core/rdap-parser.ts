import type { WhoisResponse, ContactCollection, ContactInfo, RegistrarInfo, DomainDates, DnssecInfo, WhoisQueryType } from '../types';

export class RdapParser {
  parse(query: string, queryType: WhoisQueryType, rawJson: string, endpoint: string): WhoisResponse {
    try {
      const root = JSON.parse(rawJson);
      let registrar: RegistrarInfo | null = null;
      const contacts = this.parseContacts(root, reg => { registrar = reg; });

      const response: WhoisResponse = {
        query,
        queryType,
        rawResponse: rawJson,
        domain: this.parseDomain(root, queryType, query),
        isSuccessful: true,
        whoisServer: endpoint,
        port43: this.getString(root, 'port43'),
        statuses: this.parseStatuses(root),
        nameServers: this.parseNameservers(root),
        dates: this.parseDates(root),
        contacts,
        registrar,
        registry: null,
        privacy: null,
        dnssec: this.parseDnssec(root),
        referralChain: [],
        errorMessage: null,
      };

      return response;
    } catch (ex) {
      return {
        query,
        queryType,
        rawResponse: rawJson,
        domain: '',
        isSuccessful: false,
        errorMessage: `Failed to parse RDAP response: ${(ex as Error).message}`,
        whoisServer: endpoint,
        port43: null,
        statuses: [],
        nameServers: [],
        dates: null,
        contacts: { registrant: null, admin: null, tech: null, billing: null },
        registrar: null,
        registry: null,
        privacy: null,
        dnssec: null,
        referralChain: [],
      };
    }
  }

  private parseDomain(root: Record<string, unknown>, queryType: WhoisQueryType, fallback: string): string {
    if (queryType === 'ipv4' || queryType === 'ipv6') {
      return this.parseIpDomain(root, fallback);
    }
    if (queryType === 'asn') {
      return this.parseAsnDomain(root, fallback);
    }
    return (this.getString(root, 'ldhName') || this.getString(root, 'unicodeName') || fallback);
  }

  private parseIpDomain(root: Record<string, unknown>, fallback: string): string {
    const name = this.getString(root, 'name');
    if (name) return name;
    const start = this.getString(root, 'startAddress');
    const end = this.getString(root, 'endAddress');
    if (start && end) return `${start} - ${end}`;
    return fallback;
  }

  private parseAsnDomain(root: Record<string, unknown>, fallback: string): string {
    return (this.getString(root, 'name') || this.getString(root, 'handle') || fallback);
  }

  private parseStatuses(root: Record<string, unknown>): string[] {
    const arr = root['status'];
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((s): s is string => typeof s === 'string')
      .map(s => s.toLowerCase());
  }

  private parseNameservers(root: Record<string, unknown>): string[] {
    const arr = root['nameservers'];
    if (!Array.isArray(arr)) return [];
    return arr
      .map((ns: Record<string, unknown>) => this.getString(ns, 'ldhName') || this.getString(ns, 'unicodeName'))
      .filter((n): n is string => !!n)
      .map(n => n.toLowerCase());
  }

  private parseDates(root: Record<string, unknown>): DomainDates | null {
    const arr = root['events'];
    if (!Array.isArray(arr)) return null;

    const dates: DomainDates = { created: null, updated: null, expires: null };

    for (const evt of arr) {
      const action = this.getString(evt as Record<string, unknown>, 'eventAction');
      const dateStr = this.getString(evt as Record<string, unknown>, 'eventDate');
      if (!action || !dateStr) continue;

      const date = this.parseDate(dateStr);
      if (!date) continue;

      switch (action.toLowerCase()) {
        case 'registration':
          dates.created = date;
          break;
        case 'last changed':
        case 'last update':
          dates.updated = date;
          break;
        case 'expiration':
        case 'registrar expiration':
          dates.expires = date;
          break;
      }
    }

    return dates;
  }

  private parseDate(dateStr: string): string | null {
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return null;
      return d.toISOString().split('T')[0];
    } catch {
      return null;
    }
  }

  private parseDnssec(root: Record<string, unknown>): DnssecInfo | null {
    const secureDns = root['secureDNS'] as Record<string, unknown> | undefined;
    if (!secureDns) return null;

    const dnssec: DnssecInfo = {
      signed: !!secureDns['zoneSigned'],
      delegationSigned: !!secureDns['delegationSigned'],
      dsData: [],
      keyData: [],
    };

    const dsData = secureDns['dsData'];
    if (Array.isArray(dsData)) {
      for (const ds of dsData) {
        dnssec.dsData.push({
          keyTag: (ds as Record<string, unknown>)['keyTag'] as number ?? 0,
          algorithm: (ds as Record<string, unknown>)['algorithm'] as number ?? 0,
          digestType: (ds as Record<string, unknown>)['digestType'] as number ?? 0,
          digest: ((ds as Record<string, unknown>)['digest'] as string) ?? '',
        });
      }
    }

    const keyData = secureDns['keyData'];
    if (Array.isArray(keyData)) {
      for (const key of keyData) {
        dnssec.keyData.push({
          flags: (key as Record<string, unknown>)['flags'] as number ?? 0,
          protocol: (key as Record<string, unknown>)['protocol'] as number ?? 0,
          algorithm: (key as Record<string, unknown>)['algorithm'] as number ?? 0,
          publicKey: ((key as Record<string, unknown>)['publicKey'] as string) ?? '',
        });
      }
    }

    if (!dnssec.signed && !dnssec.delegationSigned && dnssec.dsData.length === 0 && dnssec.keyData.length === 0) {
      return null;
    }

    return dnssec;
  }

  private parseContacts(root: Record<string, unknown>, setRegistrar: (r: RegistrarInfo) => void): ContactCollection {
    const contacts: ContactCollection = { registrant: null, admin: null, tech: null, billing: null };
    const entities = root['entities'];
    if (!Array.isArray(entities)) return contacts;

    const processedHandles = new Set<string>();

    for (const entity of entities) {
      this.processEntity(entity as Record<string, unknown>, contacts, setRegistrar, processedHandles);
    }

    return contacts;
  }

  private processEntity(
    entity: Record<string, unknown>,
    contacts: ContactCollection,
    setRegistrar: (r: RegistrarInfo) => void,
    processedHandles: Set<string>,
  ): void {
    const roles = this.getRoles(entity);
    const handle = this.getString(entity, 'handle') || '';

    if (handle && processedHandles.has(handle)) return;
    if (handle) processedHandles.add(handle);

    if (roles.includes('registrar')) {
      setRegistrar(this.parseRegistrar(entity));
    }

    if (roles.includes('registrant') && !contacts.registrant) {
      contacts.registrant = this.parseContact(entity);
    }
    if (roles.includes('administrative') && !contacts.admin) {
      contacts.admin = this.parseContact(entity);
    }
    if (roles.includes('technical') && !contacts.tech) {
      contacts.tech = this.parseContact(entity);
    }
    if (roles.includes('billing') && !contacts.billing) {
      contacts.billing = this.parseContact(entity);
    }

    const nested = entity['entities'];
    if (Array.isArray(nested)) {
      for (const nestedEntity of nested) {
        this.processEntity(nestedEntity as Record<string, unknown>, contacts, setRegistrar, processedHandles);
      }
    }
  }

  private parseRegistrar(entity: Record<string, unknown>): RegistrarInfo {
    const registrar: RegistrarInfo = { ianaId: '', name: '', website: '', whoisServer: '' };

    const vcard = entity['vcardArray'];
    if (vcard) {
      registrar.name = this.getVcardValue(vcard, 'fn') || this.getVcardValue(vcard, 'org') || '';
    }

    registrar.ianaId = this.getString(entity, 'handle') || '';

    const publicIds = entity['publicIds'];
    if (Array.isArray(publicIds)) {
      for (const pid of publicIds) {
        if (this.getString(pid as Record<string, unknown>, 'type') === 'IANA Registrar ID') {
          registrar.ianaId = this.getString(pid as Record<string, unknown>, 'identifier') || registrar.ianaId;
          break;
        }
      }
    }

    const links = entity['links'];
    if (Array.isArray(links)) {
      for (const link of links) {
        if (this.getString(link as Record<string, unknown>, 'rel') === 'about') {
          registrar.website = this.getString(link as Record<string, unknown>, 'href') || '';
          break;
        }
      }
    }

    return registrar;
  }

  private parseContact(entity: Record<string, unknown>): ContactInfo {
    const contact: ContactInfo = {
      name: '', organization: '', email: '', phone: '',
      street: '', city: '', state: '', postalCode: '', country: '', roles: [],
    };

    const vcard = entity['vcardArray'];
    if (!vcard) return contact;

    const properties = this.getVcardProperties(vcard);
    if (!properties) return contact;

    for (const prop of properties) {
      if (!Array.isArray(prop) || prop.length < 4 || typeof prop[0] !== 'string') continue;

      const fieldType = prop[0].toLowerCase();
      if (fieldType === 'version' || fieldType === 'n') continue;

      const value = prop[3];
      const attributes = prop.length > 1 && typeof prop[1] === 'object' ? prop[1] : null;

      this.applyVcardField(contact, fieldType, value, attributes);
    }

    if (!contact.name && contact.organization) {
      contact.name = contact.organization;
    }

    return contact;
  }

  private applyVcardField(contact: ContactInfo, fieldType: string, value: unknown, attributes: Record<string, unknown> | null): void {
    switch (fieldType) {
      case 'fn':
        contact.name = this.extractString(value) || '';
        break;
      case 'org':
        contact.organization = this.extractString(value) || '';
        break;
      case 'email':
        contact.email = this.extractString(value) || '';
        break;
      case 'contact-uri':
        if (!contact.email) contact.email = this.extractString(value) || '';
        break;
      case 'tel': {
        let phone = this.extractString(value);
        if (phone?.startsWith('tel:')) phone = phone.slice(4);
        if (phone && !contact.phone) contact.phone = phone;
        break;
      }
      case 'adr':
        this.applyAddressField(contact, value, attributes);
        break;
    }
  }

  private applyAddressField(contact: ContactInfo, value: unknown, attributes: Record<string, unknown> | null): void {
    if (attributes && typeof attributes['label'] === 'string') {
      contact.street = attributes['label'];
    } else if (Array.isArray(value)) {
      const streetParts: string[] = [];
      if (value[0]) streetParts.push(this.extractString(value[0]) || '');
      if (value[1]) streetParts.push(this.extractString(value[1]) || '');
      if (value[2]) streetParts.push(this.extractString(value[2]) || '');
      contact.street = streetParts.filter(s => s).join(', ');
      if (value[3]) contact.city = this.extractString(value[3]) || '';
      if (value[4]) contact.state = this.extractString(value[4]) || '';
      if (value[5]) contact.postalCode = this.extractString(value[5]) || '';
      if (value[6]) contact.country = this.extractString(value[6]) || '';
    }

    if (attributes && typeof attributes['cc'] === 'string') {
      contact.country = attributes['cc'] || contact.country;
    }
  }

  private getVcardProperties(vcard: unknown): unknown[] | null {
    if (Array.isArray(vcard) && vcard.length > 1) return vcard[1] as unknown[];
    if (typeof vcard === 'object' && vcard !== null && 'value' in vcard) return (vcard as Record<string, unknown>)['value'] as unknown[];
    return null;
  }

  getVcardValue(vcard: unknown, propertyName: string): string | null {
    const properties = this.getVcardProperties(vcard);
    if (!properties) return null;

    for (const prop of properties) {
      if (!Array.isArray(prop) || prop.length < 4 || typeof prop[0] !== 'string') continue;
      if (prop[0].toLowerCase() === propertyName.toLowerCase()) {
        return this.extractString(prop[3]);
      }
    }

    return null;
  }

  private getRoles(entity: Record<string, unknown>): string[] {
    const arr = entity['roles'];
    if (!Array.isArray(arr)) return [];
    return arr.filter((r): r is string => typeof r === 'string');
  }

  getString(element: Record<string, unknown>, name: string): string | null {
    const prop = element[name];
    if (typeof prop === 'string' && prop.trim()) return prop;
    return null;
  }

  private extractString(element: unknown): string | null {
    if (typeof element === 'string') return element;
    if (Array.isArray(element)) {
      return element
        .filter(e => typeof e === 'string')
        .join(', ') || null;
    }
    return null;
  }

  extractRelatedLink(json: string): string | null {
    try {
      const root = JSON.parse(json);
      const links = root['links'];
      if (!Array.isArray(links)) return null;

      for (const link of links) {
        if (link['rel'] === 'related' && link['href']) {
          if (link['type'] && link['type'].includes('rdap+json')) {
            return link['href'];
          }
          return link['href'];
        }
      }
    } catch { /* ignore */ }
    return null;
  }

  isValidRdap(json: string): boolean {
    try {
      const root = JSON.parse(json);
      if (root['rgv587_flag']) return false;
      if (root['url'] && typeof root['url'] === 'string' && root['url'].includes('punish')) return false;
      if (root['ldhName']) return true;
      if (root['objectClassName']) return true;
      if (root['errorCode']) return true;
      return false;
    } catch {
      return false;
    }
  }
}
