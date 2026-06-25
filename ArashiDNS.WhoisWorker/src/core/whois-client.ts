import { connect } from 'cloudflare:sockets';
import type { WhoisResponse, WhoisQueryType, TraceEntry, ContactInfo, ContactCollection, DomainDates, RegistrarInfo, RegistryInfo, DnssecInfo } from '../types';

const MAX_REFERRALS = 5;
const TCP_TIMEOUT_MS = 15000;

// SLD WHOIS servers (from sld.csv)
const SLD_WHOIS_SERVERS: Record<string, string> = {
  'br.com': 'whois.centralnic.net',
  'cn.com': 'whois.centralnic.net',
  'de.com': 'whois.centralnic.net',
  'eu.com': 'whois.centralnic.net',
  'gb.com': 'whois.centralnic.net',
  'gb.net': 'whois.centralnic.net',
  'gr.com': 'whois.centralnic.net',
  'hu.com': 'whois.centralnic.net',
  'in.net': 'whois.centralnic.net',
  'no.com': 'whois.centralnic.net',
  'qc.com': 'whois.centralnic.net',
  'ru.com': 'whois.centralnic.net',
  'sa.com': 'whois.centralnic.net',
  'se.com': 'whois.centralnic.net',
  'se.net': 'whois.centralnic.net',
  'uk.com': 'whois.centralnic.net',
  'uk.net': 'whois.centralnic.net',
  'us.com': 'whois.centralnic.net',
  'uy.com': 'whois.centralnic.net',
  'za.com': 'whois.centralnic.net',
  'jpn.com': 'whois.centralnic.net',
  'web.com': 'whois.centralnic.net',
  'za.net': 'whois.za.net',
  'eu.org': 'whois.eu.org',
  'za.org': 'whois.za.org',
  'llyw.cymru': 'whois.nic.llyw.cymru',
  'gov.scot': 'whois.nic.gov.scot',
  'gov.wales': 'whois.nic.gov.wales',
  'e164.arpa': 'whois.ripe.net',
  'priv.at': 'whois.nic.priv.at',
  'co.ca': 'whois.co.ca',
  'edu.cn': 'whois.edu.cn',
  'uk.co': 'whois.uk.co',
  'co.pl': 'whois.co.pl',
  'ac.ru': 'whois.free.net',
  'edu.ru': 'whois.informika.ru',
  'com.ru': 'whois.flexireg.net',
  'msk.ru': 'whois.flexireg.net',
  'net.ru': 'whois.nic.net.ru',
  'nov.ru': 'whois.flexireg.net',
  'org.ru': 'whois.nic.net.ru',
  'pp.ru': 'whois.nic.net.ru',
  'spb.ru': 'whois.flexireg.net',
  'msk.su': 'whois.flexireg.net',
  'nov.su': 'whois.flexireg.net',
  'spb.su': 'whois.flexireg.net',
  'biz.ua': 'whois.biz.ua',
  'co.ua': 'whois.co.ua',
  'pp.ua': 'whois.pp.ua',
  'ac.uk': 'whois.nic.ac.uk',
  'gov.uk': 'whois.gov.uk',
  'fed.us': 'whois.nic.gov',
  'ac.za': 'whois.ac.za',
  'co.za': 'whois.registry.net.za',
  'gov.za': 'whois.gov.za',
  'net.za': 'net-whois.registry.net.za',
  'org.za': 'org-whois.registry.net.za',
  'web.za': 'web-whois.registry.net.za',
};

const REFERRAL_REGEX = /(?:ReferralServer|Whois Server|refer|whois):\s*(?:whois:\/\/)?([^\s:\r\n]+)/i;

const DATE_FORMATS = [
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z?/,
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/,
  /^(\d{4})-(\d{2})-(\d{2})$/,
  /^(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/,
  /^(\d{2})-([A-Za-z]{3})-(\d{4})$/,
  /^(\d{2})\.(\d{2})\.(\d{4})$/,
  /^(\d{2})\/(\d{2})\/(\d{4})$/,
  /^(\d{4})\.(\d{2})\.(\d{2})/,
  /^(\d{4})\/(\d{2})\/(\d{2})/,
  /^(\d{4})(\d{2})(\d{2})$/,
  /^([A-Za-z]+)\s+(\d{1,2})\s+(\d{4})/,
];

const MONTH_MAP: Record<string, string> = {
  jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
  jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12',
};

type FieldMapping = [string, string[]];

const DOMAIN_FIELD_MAPPINGS: FieldMapping[] = [
  // Domain
  ['domain', ['Domain Name:', 'Domain name:', 'domain name:', 'domain:', '[Domain Name]', 'Complete Domain Name:', 'Nome de domínio / Domain Name:']],
  ['registry_domain_id', ['Registry Domain ID:', 'Domain ID:', 'ROID:', 'Registry ID:']],
  // Registrar
  ['registrar_name', ['Registrar:', 'Sponsoring Registrar:', 'Registrar Name:', 'Authorized Agency:', 'Sponsoring Registrar Organization:', 'Last Updated by Registrar:', 'Registrar ID:']],
  ['registrar_iana_id', ['Registrar IANA ID:', 'Registrar ID:', 'Sponsoring Registrar IANA ID:']],
  ['registrar_url', ['Registrar URL:', 'Registrar Website:', 'URL:', 'Sponsoring Registrar URL:', 'Sponsoring Registrar Website:', 'Referral URL:', 'Registrar URL (registration services):', 'Registration URL:']],
  ['registrar_whois', ['Registrar WHOIS Server:', 'Whois Server:', 'WHOIS Server:', 'Sponsoring Registrar WHOIS Server:']],
  ['registrar_abuse_email', ['Registrar Abuse Contact Email:', 'Sponsoring Registrar Customer Service Email:']],
  ['registrar_abuse_phone', ['Registrar Abuse Contact Phone:', 'Sponsoring Registrar Phone:', 'Sponsoring Registrar Customer Service Contact:', 'Registrar Contact Information:']],
  // Dates - Creation
  ['created', ['Creation Date:', 'Created:', 'Created Date:', 'Created On:', 'Domain Create Date:', 'Registration Date:', 'Registered on:', 'Registered Date:', 'Registration Time:', 'Record created:', 'Record Created:', 'created:', 'registered:', 'Domain Registration Date:', 'Domain record activated:', 'Domain Name Commencement Date:', '[Registered Date]:', '[Created on]:', 'Data de registo / Creation Date:', 'Record created on:']],
  // Dates - Update
  ['updated', ['Updated Date:', 'Modified:', 'Last Modified:', 'Last Updated:', 'Last Updated On:', 'Domain Last Updated Date:', 'Last Updated Date:', 'Record last updated on:', 'Record last updated:', 'Last Update:', 'last-update:', 'changed:', '[Last Update]:', '[Last Updated]:', 'modified:', 'Domain record last updated:', 'Record changed on:']],
  // Dates - Expiration
  ['expires', ['Registry Expiry Date:', 'Expiration Date:', 'Expires:', 'Expiry Date:', 'Expiry date:', 'Expiry:', 'expire:', 'Registrar Registration Expiration Date:', 'Domain Expiration Date:', 'Expiration Time:', 'Record expires on:', 'Record expires:', 'Expiration:', 'expires:', 'Domain expires:', '[Expires on]:', 'Data de expiração / Expiration Date:', 'Expired:']],
  // Status
  ['status', ['Domain Status:', 'Status:', 'Registration status:', 'Domain status:', 'status:', '[State]:', '[Status]:', 'state:', 'Estado / Status:', 'Re-registration Status:']],
  // Name Servers
  ['nameserver', ['Name Server:', 'Nameserver:', 'nserver:', 'Name servers:', 'Name Servers:', 'Name servers in the listed order:', 'Nameservers:', 'Nserver:', 'DNS:', 'Host Name:', '[Name Server]:', 'Domain nameservers:', 'Domain servers:', 'Domain servers in listed order:', 'Nameserver Information:', 'Primary Server Hostname:', 'Secondary Server Hostname:']],
  // Registrant
  ['registrant_id', ['Registrant ID:', 'Registrant Contact ID:']],
  ['registrant_name', ['Registrant Name:', 'Registrant Contact Name:', 'Registrant:', 'Name:', 'person:', 'contact:', '[Registrant]:', 'Titular / Registrant:', 'holder:', 'holder-c:', 'Organization Using Domain Name:', 'Nombre:']],
  ['registrant_org', ['Registrant Organization:', 'Registrant Contact Organization:', 'Organization:', 'Org Name:', 'Organisation:', 'descr:', 'role:', 'Organization Name:', 'Company English Name:', 'org:']],
  ['registrant_email', ['Registrant Email:', 'Registrant Contact Email:', 'Registrant Email Address:', 'Registrant E-mail:', 'AC E-Mail:', 'Email:', 'E-mail:', 'e-mail:', 'E-Mailbox:', 'Email Address:']],
  ['registrant_street', ['Registrant Street:', 'Registrant Street1:', 'Registrant Street2:', 'Registrant Address:', 'Registrant Address1:', 'Registrant Address2:', 'Registrant Address3:', 'Registrant Contact Street:', 'Address:', 'Street:', 'address:', "Registrant's address:", 'street address:']],
  ['registrant_city', ['Registrant City:', 'Registrant Contact City:', 'City:', 'city:']],
  ['registrant_state', ['Registrant State/Province:', 'Registrant Contact State/Province:', 'StateProv:', 'State:', 'Province:']],
  ['registrant_postal', ['Registrant Postal Code:', 'Registrant Contact Postal Code:', 'Registrant Zip:', 'PostalCode:', 'Zip:', 'Postal Code:', 'Registrant Zip Code:', 'postal code:']],
  ['registrant_country', ['Registrant Country:', 'Registrant Contact Country:', 'Country:', 'Country Code:', 'country:']],
  ['registrant_phone', ['Registrant Phone:', 'Registrant Contact Phone:', 'Phone:', 'phone:', 'Telephone:', 'Registrant Phone Number:', 'TEL:', 'Phone Number:']],
  ['registrant_phone_ext', ['Registrant Phone Ext:', 'Registrant Phone Ext.:']],
  ['registrant_fax', ['Registrant Fax:', 'Registrant FAX:', 'Registrant Fax Ext:', 'Registrant FAX Ext.:', 'Registrant Facsimile Number:', 'Fax:', 'fax-no:', 'FAX:', 'Fax Number:']],
  // Admin Contact
  ['admin_id', ['Admin ID:', 'Administrative Contact ID:']],
  ['admin_name', ['Admin Name:', 'Administrative Contact Name:', 'Admin Contact Name:', 'Admin:', 'Administrative Contact:', '[Administrative Contact]:', 'admin-c:', 'Administrative Name', 'Administrative Contact:']],
  ['admin_org', ['Admin Organization:', 'Administrative Contact Organization:', 'Admin Organisation:', 'Administrative Organization:']],
  ['admin_email', ['Admin Email:', 'Administrative Contact Email:', 'Admin E-mail:', 'Administrative Contact Email:', 'AC E-Mail:', 'Administrative Email:', 'Administrative E-mail:']],
  ['admin_phone', ['Admin Phone:', 'Administrative Contact Phone:', 'Admin Telephone:', 'Administrative Contact Phone Number:', 'AC Phone Number:', 'Administrative Phone:']],
  ['admin_phone_ext', ['Admin Phone Ext:', 'Administrative Phone Ext.:']],
  ['admin_fax', ['Admin Fax:', 'Admin FAX:', 'Admin Fax Ext:', 'Admin FAX Ext.:', 'Administrative Contact Facsimile Number:', 'Administrative FAX:', 'Administrative FAX Ext.:']],
  ['admin_street', ['Admin Street:', 'Admin Street1:', 'Admin Street2:', 'Admin Address:', 'Admin Address1:', 'Admin Address2:', 'Admin Address3:', 'Administrative Contact Address1:', 'Administrative Contact Address2:', 'Administrative Address:', 'Administrative Address2:', 'Administrative Address3:']],
  ['admin_city', ['Admin City:', 'Administrative Contact City:', 'Administrative City:']],
  ['admin_state', ['Admin State/Province:', 'Administrative Contact State/Province:', 'Administrative State/Province:']],
  ['admin_postal', ['Admin Postal Code:', 'Administrative Contact Postal Code:', 'Administrative Postal Code:']],
  ['admin_country', ['Admin Country:', 'Administrative Contact Country:', 'Administrative Contact Country Code:', 'Administrative Country/Economy:']],
  // Tech Contact
  ['tech_id', ['Tech ID:', 'Technical Contact ID:', 'Tech Contact ID:', 'Technical ID:']],
  ['tech_name', ['Tech Name:', 'Technical Contact Name:', 'Tech Contact Name:', 'Technical:', 'Technical Contact:', 'n. [Technical Contact]:', 'tech-c:', 'Technical Name:']],
  ['tech_org', ['Tech Organization:', 'Technical Contact Organization:', 'Tech Organisation:', 'Technical Contact Organization:', 'Responsável Técnico:', 'Technical Organization:']],
  ['tech_email', ['Tech Email:', 'Technical Contact Email:', 'Tech E-mail:', 'Technical Contact Email:', 'Tech Contact Email:', 'Technical E-mail:']],
  ['tech_phone', ['Tech Phone:', 'Technical Contact Phone:', 'Tech Telephone:', 'Technical Contact Phone Number:', 'Technical Phone:']],
  ['tech_phone_ext', ['Tech Phone Ext:', 'Technical Phone Ext.:']],
  ['tech_fax', ['Tech Fax:', 'Tech FAX:', 'Tech Fax Ext:', 'Tech FAX Ext.:', 'Technical Contact Facsimile Number:', 'Technical FAX:', 'Technical FAX Ext.:']],
  ['tech_street', ['Tech Street:', 'Tech Street1:', 'Tech Street2:', 'Tech Address:', 'Tech Address1:', 'Tech Address2:', 'Tech Address3:', 'Technical Contact Address1:', 'Technical Contact Address2:', 'Technical Address:', 'Technical Address2:', 'Technical Address3:']],
  ['tech_city', ['Tech City:', 'Technical Contact City:', 'Technical City:']],
  ['tech_state', ['Tech State/Province:', 'Technical Contact State/Province:', 'Technical State/Province:']],
  ['tech_postal', ['Tech Postal Code:', 'Technical Contact Postal Code:', 'Technical Postal Code:']],
  ['tech_country', ['Tech Country:', 'Technical Contact Country:', 'Technical Contact Country Code:', 'Technical Country/Economy:']],
  // Billing Contact
  ['billing_id', ['Billing ID:', 'Billing Contact ID:']],
  ['billing_name', ['Billing Name:', 'Billing Contact:']],
  ['billing_org', ['Billing Organization:', 'Billing Contact Organization:', 'Entidade Gestora:', 'Billing Organization:']],
  ['billing_email', ['Billing Email:', 'Billing E-mail:', 'Billing Contact Email:', 'Billing E-mail:']],
  ['billing_phone', ['Billing Phone:', 'Billing Contact Phone Number:', 'Billing Phone:']],
  ['billing_phone_ext', ['Billing Phone Ext:', 'Billing Phone Ext.:']],
  ['billing_fax', ['Billing Fax:', 'Billing FAX:', 'Billing Fax Ext:', 'Billing FAX Ext.:', 'Billing Contact Facsimile Number:', 'Billing FAX:', 'Billing FAX Ext.:']],
  ['billing_street', ['Billing Street:', 'Billing Street1:', 'Billing Street2:', 'Billing Address:', 'Billing Address1:', 'Billing Address2:', 'Billing Address3:', 'Billing Contact Address1:']],
  ['billing_city', ['Billing City:', 'Billing Contact City:']],
  ['billing_state', ['Billing State/Province:', 'Billing Contact State/Province:']],
  ['billing_postal', ['Billing Postal Code:', 'Billing Contact Postal Code:']],
  ['billing_country', ['Billing Country:', 'Billing Contact Country:', 'Billing Contact Country Code:']],
  // DNSSEC / Trademark / Other
  ['dnssec', ['DNSSEC:', 'DNSSEC', 'dnssec:']],
  ['trademark_name', ['Trademark Name:']],
  ['trademark_date', ['Trademark Date:']],
  ['trademark_country', ['Trademark Country:']],
  ['trademark_number', ['Trademark Number:']],
  ['remarks', ['Remarks:', 'remarks:']],
];

const IP_FIELD_MAPPINGS: FieldMapping[] = [
  ['network_range', ['NetRange:', 'inetnum:', 'IP Address:']],
  ['network_name', ['NetName:', 'netname:']],
  ['organization', ['OrgName:', 'org-name:', 'org:', 'descr:']],
  ['address', ['Address:', 'address:']],
  ['city', ['City:']],
  ['state', ['StateProv:']],
  ['postal_code', ['PostalCode:']],
  ['country', ['Country:', 'country:']],
  ['abuse_email', ['OrgAbuseEmail:', 'abuse-mailbox:', 'e-mail:']],
  ['abuse_phone', ['OrgAbusePhone:', 'phone:']],
];

// Sort mappings by prefix length descending for longest-match-first
function sortMappings(mappings: FieldMapping[]): [string, string][] {
  const flat: [string, string][] = [];
  for (const [key, prefixes] of mappings) {
    for (const prefix of prefixes) {
      if (prefix) flat.push([key, prefix]);
    }
  }
  return flat.sort((a, b) => b[1].length - a[1].length);
}

const SORTED_DOMAIN_MAPPINGS = sortMappings(DOMAIN_FIELD_MAPPINGS);
const SORTED_IP_MAPPINGS = sortMappings(IP_FIELD_MAPPINGS);

function extractFields(rawResponse: string, sortedMappings: [string, string][]): Map<string, string[]> {
  const fields = new Map<string, string[]>();
  const lines = rawResponse.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#')) continue;

    const wordCount = trimmed.split(/\s+/).length;
    if (wordCount > 10) continue;

    for (const [key, prefix] of sortedMappings) {
      if (trimmed.toLowerCase().startsWith(prefix.toLowerCase())) {
        const value = trimmed.slice(prefix.length).trim();
        if (value) {
          if (!fields.has(key)) fields.set(key, []);
          fields.get(key)!.push(value);
        }
        break;
      }
    }
  }

  return fields;
}

function getFieldValue(fields: Map<string, string[]>, key: string): string {
  const values = fields.get(key);
  return values && values.length > 0 ? values[0] : '';
}

function getFieldValues(fields: Map<string, string[]>, key: string): string[] {
  return fields.get(key) || [];
}

function cleanFieldValue(value: string): string {
  if (!value) return '';
  value = value.trim();
  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.slice(1, -1).trim();
  }
  return value;
}

function parseWhoisDate(dateStr: string): string | null {
  if (!dateStr) return null;
  dateStr = dateStr.split('(')[0].trim();
  dateStr = dateStr.replace(/\s*(JST|UTC|GMT|KST)\s*$/i, '').trim();

  // ISO format
  const isoMatch = dateStr.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (isoMatch) {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // dd-MMM-yyyy (with optional time)
  const dmyMatch = dateStr.match(/^(\d{2})-([A-Za-z]{3})-(\d{4})/);
  if (dmyMatch) {
    const month = MONTH_MAP[dmyMatch[2].toLowerCase()];
    if (month) {
      const d = new Date(`${dmyMatch[3]}-${month}-${dmyMatch[1]}`);
      if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
    }
  }

  // dd.MM.yyyy
  const dotMatch = dateStr.match(/^(\d{2})\.(\d{2})\.(\d{4})/);
  if (dotMatch) {
    const d = new Date(`${dotMatch[3]}-${dotMatch[2]}-${dotMatch[1]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // dd/MM/yyyy
  const slashMatch = dateStr.match(/^(\d{2})\/(\d{2})\/(\d{4})/);
  if (slashMatch) {
    const d = new Date(`${slashMatch[3]}-${slashMatch[2]}-${slashMatch[1]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // MM/dd/yyyy
  const usMatch = dateStr.match(/^(\d{2})\/(\d{2})\/(\d{4})/);
  if (usMatch) {
    const d = new Date(`${usMatch[3]}-${usMatch[1]}-${usMatch[2]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // yyyy.MM.dd
  const ydotMatch = dateStr.match(/^(\d{4})\.(\d{2})\.(\d{2})/);
  if (ydotMatch) {
    const d = new Date(`${ydotMatch[1]}-${ydotMatch[2]}-${ydotMatch[3]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // Korean: yyyy. MM. dd.
  const korMatch = dateStr.match(/^(\d{4})\.\s*(\d{2})\.\s*(\d{2})/);
  if (korMatch) {
    const d = new Date(`${korMatch[1]}-${korMatch[2]}-${korMatch[3]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // Month name format: "June 30 2010" or "June  30 2010"
  const monthNameMatch = dateStr.match(/^([A-Za-z]+)\s+(\d{1,2})\s+(\d{4})/);
  if (monthNameMatch) {
    const d = new Date(`${monthNameMatch[1]} ${monthNameMatch[2]}, ${monthNameMatch[3]}`);
    if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  }

  // Fallback
  const d = new Date(dateStr);
  if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];

  return null;
}

function parseStatuses(statusValues: string[]): string[] {
  const result: string[] = [];
  for (const val of statusValues) {
    const parts = val.split(/[\s\t]+/);
    for (const part of parts) {
      const s = part.trim().toLowerCase();
      if (s && !s.startsWith('http') && !s.startsWith('(') && !result.includes(s)) {
        result.push(s);
      }
    }
  }
  return result;
}

function parseContact(fields: Map<string, string[]>, prefix: string): ContactInfo | null {
  const name = cleanFieldValue(getFieldValue(fields, `${prefix}_name`));
  const org = cleanFieldValue(getFieldValue(fields, `${prefix}_org`));
  const email = cleanFieldValue(getFieldValue(fields, `${prefix}_email`));
  const street = cleanFieldValue(getFieldValue(fields, `${prefix}_street`));
  const city = cleanFieldValue(getFieldValue(fields, `${prefix}_city`));
  const state = cleanFieldValue(getFieldValue(fields, `${prefix}_state`));
  const postal = cleanFieldValue(getFieldValue(fields, `${prefix}_postal`));
  const country = cleanFieldValue(getFieldValue(fields, `${prefix}_country`));
  const phone = cleanFieldValue(getFieldValue(fields, `${prefix}_phone`));

  if (!name && !org && !email) return null;

  return { name, organization: org, email, phone, street, city, state, postalCode: postal, country, roles: [] };
}

function parseDnssec(fields: Map<string, string[]>): DnssecInfo | null {
  const val = cleanFieldValue(getFieldValue(fields, 'dnssec'));
  if (!val) return null;
  const signed = !val.toLowerCase().includes('unsigned') && val.toLowerCase() !== 'no';
  return { signed, delegationSigned: signed, dsData: [], keyData: [] };
}

function formatQuery(server: string, query: string, queryType: WhoisQueryType): string {
  const lower = server.toLowerCase();
  if (lower.includes('verisign-grs.com')) return `domain ${query}`;
  if (lower.includes('arin.net')) {
    if (queryType === 'ipv4' || queryType === 'ipv6') return `n + ${query}`;
    return query;
  }
  return query;
}

function extractReferral(response: string): string | null {
  const match = response.match(REFERRAL_REGEX);
  return match ? match[1] : null;
}

function extractTld(domain: string): string {
  const parts = domain.replace(/\.$/, '').split('.');
  return parts.length > 0 ? parts[parts.length - 1].toLowerCase() : '';
}

// Section-based WHOIS parsing (for .kg, .cn, etc.)
function parseSectionBasedWhois(raw: string): Partial<WhoisResponse> {
  const lines = raw.split('\n');
  const contacts: ContactCollection = { registrant: null, admin: null, tech: null, billing: null };
  let currentContact: ContactInfo | null = null;
  let currentRole: string = '';
  const nameServers: string[] = [];
  let inNsSection = false;
  let domain = '';
  const dates: DomainDates = { created: null, updated: null, expires: null };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#')) continue;

    // Domain: "Domain AC.KG (ACTIVE)"
    if (trimmed.toLowerCase().startsWith('domain ') && !trimmed.toLowerCase().includes('status')) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        domain = parts[1].replace(/\.$/, '').toLowerCase();
        if (domain.includes('(')) domain = domain.split('(')[0].trim();
      }
    }

    // Contact sections
    const t = trimmed.toLowerCase();
    if (t.endsWith('contact:') || t.endsWith('contact')) {
      currentContact = { name: '', organization: '', email: '', phone: '', street: '', city: '', state: '', postalCode: '', country: '', roles: [] };
      if (t.includes('admin')) { contacts.admin = currentContact; currentRole = 'admin'; }
      else if (t.includes('tech')) { contacts.tech = currentContact; currentRole = 'tech'; }
      else if (t.includes('bill')) { contacts.billing = currentContact; currentRole = 'billing'; }
      else { contacts.registrant = currentContact; currentRole = 'registrant'; }
      continue;
    }

    // Contact fields
    if (currentContact) {
      if (trimmed.toLowerCase().startsWith('name:')) currentContact.name = trimmed.slice(5).trim();
      else if (trimmed.toLowerCase().startsWith('address:')) currentContact.street = trimmed.slice(8).trim();
      else if (trimmed.toLowerCase().startsWith('email:')) currentContact.email = trimmed.slice(6).trim();
      else if (trimmed.toLowerCase().startsWith('phone:')) currentContact.phone = trimmed.slice(6).trim();
    }

    // Dates
    if (trimmed.toLowerCase().startsWith('record created:')) {
      dates.created = parseWhoisDate(trimmed.slice(15).trim());
    } else if (trimmed.toLowerCase().startsWith('record last updated')) {
      const idx = trimmed.indexOf(':');
      dates.updated = parseWhoisDate(idx >= 0 ? trimmed.slice(idx + 1).trim() : trimmed);
    } else if (trimmed.toLowerCase().startsWith('record expires')) {
      const idx = trimmed.indexOf(':');
      dates.expires = parseWhoisDate(idx >= 0 ? trimmed.slice(idx + 1).trim() : trimmed);
    }

    // Nameservers
    if (trimmed.toLowerCase().includes('name servers') || trimmed.toLowerCase().includes('nameservers')) {
      inNsSection = true;
      continue;
    }
    if (inNsSection && trimmed) {
      if (trimmed.toLowerCase().startsWith('ns') || trimmed.match(/\.(com|net|org)$/i)) {
        nameServers.push(trimmed.toLowerCase());
      } else {
        inNsSection = false;
      }
    }
  }

  return { domain, contacts, nameServers, dates };
}

export class WhoisTcpClient {
  async query(query: string, queryType: WhoisQueryType): Promise<{ response: WhoisResponse; trace: TraceEntry[] }> {
    const traces: TraceEntry[] = [];
    const referralChain: string[] = [];
    let currentServer = this.getWhoisServer(query, queryType);
    let lastRawResponse: string | null = null;

    for (let i = 0; i < MAX_REFERRALS; i++) {
      if (!currentServer) break;
      referralChain.push(currentServer);

      const trace: TraceEntry = { protocol: 'WHOIS', endpoint: currentServer, formatter: '', success: false };
      traces.push(trace);

      try {
        const formattedQuery = formatQuery(currentServer, query, queryType);
        const rawResponse = await this.tcpQuery(currentServer, formattedQuery);
        lastRawResponse = rawResponse;
        trace.success = true;

        const referralServer = extractReferral(rawResponse);
        if (!referralServer || referralChain.includes(referralServer)) break;

        currentServer = referralServer;
      } catch (ex) {
        trace.error = (ex as Error).message;
        if (i === 0) {
          return { response: this.errorResponse(query, queryType, currentServer, referralChain, (ex as Error).message), trace: traces };
        }
        break;
      }
    }

    if (!lastRawResponse) {
      return { response: this.errorResponse(query, queryType, currentServer || '', referralChain, 'No response received'), trace: traces };
    }

    const response = this.parseResponse(query, queryType, lastRawResponse, referralChain);
    return { response, trace: traces };
  }

  private getWhoisServer(query: string, queryType: WhoisQueryType): string {
    if (queryType === 'domain') {
      const domain = query.toLowerCase().replace(/\.$/, '');
      // Check SLD first (e.g. google.co.uk -> co.uk)
      const parts = domain.split('.');
      for (let i = 1; i < parts.length; i++) {
        const sld = parts.slice(i).join('.');
        if (SLD_WHOIS_SERVERS[sld]) return SLD_WHOIS_SERVERS[sld];
      }
      // Fallback to TLD
      const tld = extractTld(query);
      return `${tld}.whois-servers.net`;
    }
    if (queryType === 'ipv4' || queryType === 'ipv6') return 'whois.arin.net';
    if (queryType === 'asn') return 'whois.arin.net';
    return 'whois.iana.org';
  }

  private async tcpQuery(host: string, query: string): Promise<string> {
    const socket = connect({ hostname: host, port: 43 });
    const writer = socket.writable.getWriter();
    const encoder = new TextEncoder();
    await writer.write(encoder.encode(query + '\r\n'));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const chunks: Uint8Array[] = [];
    const decoder = new TextDecoder('utf-8');

    let result = '';
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.length > 0) {
          chunks.push(value);
        }
      }
    } catch { /* stream ended */ }

    try { reader.releaseLock(); } catch {}

    // Combine all chunks
    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
    if (totalLen === 0) {
      try { await socket.close(); } catch {}
      return '';
    }

    const bytes = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }

    try { await socket.close(); } catch {}

    // Try UTF-8, fallback to Latin1
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (!text.includes('\uFFFD')) return text;
    } catch {}
    return new TextDecoder('latin1').decode(bytes);
  }

  private parseResponse(query: string, queryType: WhoisQueryType, rawResponse: string, referralChain: string[]): WhoisResponse {
    const base: WhoisResponse = {
      query, queryType, domain: '', isSuccessful: true,
      whoisServer: referralChain[0] || '', port43: referralChain[referralChain.length - 1] || '',
      rawResponse, referralChain, errorMessage: null,
      statuses: [], nameServers: [], dates: null,
      contacts: { registrant: null, admin: null, tech: null, billing: null },
      registrar: null, registry: null, privacy: null, dnssec: null,
    };

    if (queryType === 'ipv4' || queryType === 'ipv6' || queryType === 'asn') {
      const fields = extractFields(rawResponse, SORTED_IP_MAPPINGS);
      base.domain = cleanFieldValue(getFieldValue(fields, 'network_range')) || query;
      base.registry = {
        name: cleanFieldValue(getFieldValue(fields, 'organization')),
        website: '', whoisServer: referralChain[0] || '',
      };
      const org = cleanFieldValue(getFieldValue(fields, 'organization'));
      const email = cleanFieldValue(getFieldValue(fields, 'abuse_email'));
      const country = cleanFieldValue(getFieldValue(fields, 'country'));
      if (org || email) {
        base.contacts.registrant = {
          name: '', organization: org, email, phone: cleanFieldValue(getFieldValue(fields, 'abuse_phone')),
          street: cleanFieldValue(getFieldValue(fields, 'address')),
          city: cleanFieldValue(getFieldValue(fields, 'city')),
          state: cleanFieldValue(getFieldValue(fields, 'state')),
          postalCode: cleanFieldValue(getFieldValue(fields, 'postal_code')),
          country, roles: ['registrant'],
        };
      }
      return base;
    }

    // Domain parsing
    const fields = extractFields(rawResponse, SORTED_DOMAIN_MAPPINGS);
    base.domain = cleanFieldValue(getFieldValue(fields, 'domain')) || query.toUpperCase();

    base.dates = {
      created: parseWhoisDate(getFieldValue(fields, 'created')),
      updated: parseWhoisDate(getFieldValue(fields, 'updated')),
      expires: parseWhoisDate(getFieldValue(fields, 'expires')),
    };

    base.nameServers = getFieldValues(fields, 'nameserver').map(v => cleanFieldValue(v).toLowerCase()).filter(Boolean);
    base.statuses = parseStatuses(getFieldValue(fields, 'status') ? [getFieldValue(fields, 'status')] : getFieldValues(fields, 'status'));
    base.dnssec = parseDnssec(fields);

    const regName = cleanFieldValue(getFieldValue(fields, 'registrar_name'));
    if (regName) {
      base.registrar = {
        name: regName,
        ianaId: cleanFieldValue(getFieldValue(fields, 'registrar_iana_id')),
        website: cleanFieldValue(getFieldValue(fields, 'registrar_url')),
        whoisServer: cleanFieldValue(getFieldValue(fields, 'registrar_whois')),
      };
    }

    base.contacts.registrant = parseContact(fields, 'registrant');
    base.contacts.admin = parseContact(fields, 'admin');
    base.contacts.tech = parseContact(fields, 'tech');
    base.contacts.billing = parseContact(fields, 'billing');

    // Section-based fallback
    if (!base.domain || (!base.registrar?.name && !base.dates?.expires)) {
      const section = parseSectionBasedWhois(rawResponse);
      if (section.domain && base.domain === query.toUpperCase()) base.domain = section.domain;
      if (!base.dates?.expires && section.dates?.expires) base.dates = section.dates;
      if (!base.registrar?.name && section.registrar) base.registrar = section.registrar;
      if (base.nameServers.length === 0 && section.nameServers && section.nameServers.length > 0) base.nameServers = section.nameServers;
      if (!base.contacts.registrant && section.contacts?.registrant) base.contacts.registrant = section.contacts.registrant;
      if (!base.contacts.admin && section.contacts?.admin) base.contacts.admin = section.contacts.admin;
      if (!base.contacts.tech && section.contacts?.tech) base.contacts.tech = section.contacts.tech;
      if (!base.contacts.billing && section.contacts?.billing) base.contacts.billing = section.contacts.billing;
    }

    // Set roles
    if (base.contacts.registrant) base.contacts.registrant.roles = ['registrant'];
    if (base.contacts.admin) base.contacts.admin.roles = ['admin'];
    if (base.contacts.tech) base.contacts.tech.roles = ['tech'];
    if (base.contacts.billing) base.contacts.billing.roles = ['billing'];

    return base;
  }

  private errorResponse(query: string, queryType: WhoisQueryType, server: string, referralChain: string[], error: string): WhoisResponse {
    return {
      query, queryType, domain: '', isSuccessful: false, errorMessage: error,
      whoisServer: server, port43: null, statuses: [], nameServers: [], dates: null,
      contacts: { registrant: null, admin: null, tech: null, billing: null },
      registrar: null, registry: null, privacy: null, dnssec: null, rawResponse: null, referralChain,
    };
  }
}
