import type { WhoisResponse, ContactCollection, ContactInfo, RegistrarInfo, DomainDates, DnssecInfo, WhoisQueryType } from '../types';

interface FieldPattern {
  pattern: RegExp;
  group: number;
  server: string;
}

function p(pattern: string, group = 1, server = 'generic'): FieldPattern {
  return { pattern: new RegExp(pattern, 'i'), group, server };
}

const FIELD_PATTERNS: Record<string, FieldPattern[]> = {
  // Domain
  domain: [
    p('Domain Name:\\s*(.+)'), p('Domain name:\\s*(.+)'), p('domain:\\s*(.+)'),
    p('domain name:\\s*(.+)'), p('\\[Domain Name\\]\\s*(.+)'), p('Complete Domain Name:\\s*(.+)'),
    p('domain_name:\\s*(.+)'), p('Domain:\\s*(.+)'),
  ],
  registry_domain_id: [
    p('Registry Domain ID:\\s*(.+)'), p('Domain ID:\\s*(.+)'),
    p('ROID:\\s*(.+)'), p('Registry ID:\\s*(.+)'),
  ],

  // Registrar
  registrar_name: [
    p('Registrar:\\s*(.+)'), p('Sponsoring Registrar:\\s*(.+)'), p('Registrar Name:\\s*(.+)'),
    p('Authorized Agency:\\s*(.+)'), p('Sponsoring Registrar Organization:\\s*(.+)'),
    p('Last Updated by Registrar:\\s*(.+)'), p('Registrar ID:\\s*(.+)'),
    p('registrar:\\s*(.+)'), p('\\uB4F1\\uB85D\\uB300\\uD589\\uC790:\\s*(.+)'), // 등록대행자:
    p('registrar_name:\\s*(.+)'),
  ],
  registrar_iana_id: [
    p('Registrar IANA ID:\\s*(.+)'), p('Registrar ID:\\s*(.+)'),
    p('Sponsoring Registrar IANA ID:\\s*(.+)'),
  ],
  registrar_url: [
    p('Registrar URL:\\s*(.+)'), p('Registrar Website:\\s*(.+)'), p('URL:\\s*(.+)'),
    p('Sponsoring Registrar URL:\\s*(.+)'), p('Sponsoring Registrar Website:\\s*(.+)'),
    p('Referral URL:\\s*(.+)'), p('Registrar URL \\(registration services\\):\\s*(.+)'),
    p('Registration URL:\\s*(.+)'),
  ],
  registrar_whois: [
    p('Registrar WHOIS Server:\\s*(.+)'), p('Whois Server:\\s*(.+)'),
    p('WHOIS Server:\\s*(.+)'), p('Sponsoring Registrar WHOIS Server:\\s*(.+)'),
  ],
  registrar_abuse_email: [
    p('Registrar Abuse Contact Email:\\s*(.+)'),
    p('Sponsoring Registrar Customer Service Email:\\s*(.+)'),
  ],
  registrar_abuse_phone: [
    p('Registrar Abuse Contact Phone:\\s*(.+)'),
    p('Sponsoring Registrar Phone:\\s*(.+)'),
    p('Sponsoring Registrar Customer Service Contact:\\s*(.+)'),
    p('Registrar Contact Information:\\s*(.+)'),
  ],

  // Dates
  created: [
    p('Creation Date:\\s*(.+)'), p('Created:\\s*(.+)'), p('Created Date:\\s*(.+)'),
    p('Created On:\\s*(.+)'), p('Domain Create Date:\\s*(.+)'), p('Registration Date:\\s*(.+)'),
    p('Registered on:\\s*(.+)'), p('Registered Date:\\s*(.+)'), p('Registration Time:\\s*(.+)'),
    p('Record created:\\s*(.+)'), p('Record Created:\\s*(.+)'), p('created:\\s*(.+)'),
    p('registered:\\s*(.+)'), p('Domain Registration Date:\\s*(.+)'),
    p('Domain record activated:\\s*(.+)'), p('Domain Name Commencement Date:\\s*(.+)'),
    p('\\[Registered Date\\]:\\s*(.+)'), p('\\[Created on\\]:\\s*(.+)'),
    p('Record created on:\\s*(.+)'),
    p('\\[\\u767B\\u9304\\u5E74\\u6708\\u65E5\\]\\s*(.+)'), // [登録年月日]
    p('\\uB4F1\\uB85D\\uC77C:\\s*(.+)'), // 등록일:
    p('Date registered:\\s*(.+)'), p('Registered:\\s*(.+)'),
  ],
  updated: [
    p('Updated Date:\\s*(.+)'), p('Modified:\\s*(.+)'), p('Last Modified:\\s*(.+)'),
    p('Last Updated:\\s*(.+)'), p('Last Updated On:\\s*(.+)'),
    p('Domain Last Updated Date:\\s*(.+)'), p('Last Updated Date:\\s*(.+)'),
    p('Record last updated on:\\s*(.+)'), p('Record last updated:\\s*(.+)'),
    p('Last Update:\\s*(.+)'), p('last-update:\\s*(.+)'), p('changed:\\s*(.+)'),
    p('\\[Last Update\\]:\\s*(.+)'), p('\\[Last Updated\\]:\\s*(.+)'),
    p('modified:\\s*(.+)'), p('Domain record last updated:\\s*(.+)'),
    p('Record changed on:\\s*(.+)'),
    p('\\[\\u6700\\u7EC8\\u66F4\\u65B0\\]\\s*(.+)'), // [最終更新]
    p('\\uCD5C\\uADFC \\uC815\\uBCF4 \\uBCC0\\uACBD\\uC77C:\\s*(.+)'), // 최근 정보 변경일
    p('Update Date:\\s*(.+)'), p('Modification date:\\s*(.+)'),
  ],
  expires: [
    p('Registry Expiry Date:\\s*(.+)'), p('Expiration Date:\\s*(.+)'),
    p('Expires:\\s*(.+)'), p('Expiry Date:\\s*(.+)'), p('Expiry date:\\s*(.+)'),
    p('Expiry:\\s*(.+)'), p('expire:\\s*(.+)'),
    p('Registrar Registration Expiration Date:\\s*(.+)'),
    p('Domain Expiration Date:\\s*(.+)'), p('Expiration Time:\\s*(.+)'),
    p('Record expires on:\\s*(.+)'), p('Record expires:\\s*(.+)'),
    p('Expiration:\\s*(.+)'), p('expires:\\s*(.+)'), p('Domain expires:\\s*(.+)'),
    p('\\[Expires on\\]:\\s*(.+)'),
    p('\\[\\u6709\\u6548\\u671F\\u9650\\]\\s*(.+)'), // [有効期限]
    p('Expired:\\s*(.+)'),
    p('\\uC0AC\\uC6A9 \\uC885\\uB8CC\\uC77C:\\s*(.+)'), // 사용 종료일
    p('Expire Date:\\s*(.+)'), p('renewal date:\\s*(.+)'),
  ],

  // Status
  status: [
    p('Domain Status:\\s*(.+)'), p('Status:\\s*(.+)'), p('Registration status:\\s*(.+)'),
    p('Domain status:\\s*(.+)'), p('status:\\s*(.+)'),
    p('\\[State\\]:\\s*(.+)'), p('\\[Status\\]:\\s*(.+)'), p('state:\\s*(.+)'),
    p('Re-registration Status:\\s*(.+)'),
    p('\\[\\u72B6\\u614B\\]\\s*(.+)'), // [状態]
    p('\\[\\u30ED\\u30C3\\u30AF\\u72B6\\u614B\\]\\s*(.+)'), // [ロック状態]
    p('\\uB4F1\\uB85D\\uC815\\uBCF4 \\uBCF4\\uD638:\\s*(.+)'), // 등록정보 보호
  ],

  // Nameservers
  nameserver: [
    p('Name Server:\\s*(.+)'), p('Nameserver:\\s*(.+)'), p('nserver:\\s*(.+)'),
    p('Name servers:\\s*(.+)'), p('Name Servers:\\s*(.+)'),
    p('Name servers in the listed order:\\s*(.+)'), p('Nameservers:\\s*(.+)'),
    p('Nserver:\\s*(.+)'), p('DNS:\\s*(.+)'), p('Host Name:\\s*(.+)'),
    p('\\[Name Server\\]\\s*(.+)'),
    p('Domain nameservers:\\s*(.+)'), p('Domain servers:\\s*(.+)'),
    p('Domain servers in listed order:\\s*(.+)'), p('Nameserver Information:\\s*(.+)'),
    p('Primary Server Hostname:\\s*(.+)'), p('Secondary Server Hostname:\\s*(.+)'),
    p('Hostname:\\s*(.+)'),
  ],

  // Registrant
  registrant_id: [
    p('Registrant ID:\\s*(.+)'), p('Registrant Contact ID:\\s*(.+)'),
    p('Registry Registrant ID:\\s*(.+)'), p('owner-contact:\\s*(.+)'),
    p('holder-c:\\s*(.+)'),
  ],
  registrant_name: [
    p('Registrant Name:\\s*(.+)'), p('Registrant Contact Name:\\s*(.+)'),
    p('Registrant:\\s*(.+)'), p('Name:\\s*(.+)'), p('person:\\s*(.+)'),
    p('contact:\\s*(.+)'), p('owner-name:\\s*(.+)'),
    p('\\[Registrant\\]:\\s*(.+)'), p('\\[Registrant\\]\\s*(.+)'),
    p('Titular / Registrant:\\s*(.+)'), p('holder:\\s*(.+)'),
    p('Organization Using Domain Name:\\s*(.+)'), p('Nombre:\\s*(.+)'),
    p('\\[\\u767B\\u9304\\u8005\\u540D\\]\\s*(.+)'), // [登録者名]
    p('\\[\\u540D\\u524D\\]\\s*(.+)'), // [名前]
    p('\\[Name\\]\\s*(.+)'),
    p('\\uB4F1\\uB85D\\uC778:\\s*(.+)'), // 등록인:
  ],
  registrant_org: [
    p('Registrant Organization:\\s*(.+)'), p('Registrant Contact Organization:\\s*(.+)'),
    p('owner-organization:\\s*(.+)'), p('Organization:\\s*(.+)'),
    p('Org Name:\\s*(.+)'), p('Organisation:\\s*(.+)'), p('descr:\\s*(.+)'),
    p('role:\\s*(.+)'), p('Organization Name:\\s*(.+)'),
    p('Company English Name:\\s*(.+)'), p('org:\\s*(.+)'),
  ],
  registrant_email: [
    p('Registrant Email:\\s*(.+)'), p('Registrant Contact Email:\\s*(.+)'),
    p('Registrant Email Address:\\s*(.+)'), p('Registrant E-mail:\\s*(.+)'),
    p('owner-email:\\s*(.+)'), p('AC E-Mail:\\s*(.+)'),
    p('Email:\\s*(.+)'), p('E-mail:\\s*(.+)'), p('e-mail:\\s*(.+)'),
    p('E-Mailbox:\\s*(.+)'), p('Email Address:\\s*(.+)'),
    p('\\[Email\\]\\s*(.+)'),
  ],
  registrant_street: [
    p('Registrant Street:\\s*(.+)'), p('Registrant Street1:\\s*(.+)'),
    p('Registrant Street2:\\s*(.+)'), p('Registrant Address:\\s*(.+)'),
    p('Registrant Address1:\\s*(.+)'), p('Registrant Address2:\\s*(.+)'),
    p('Registrant Address3:\\s*(.+)'), p('Registrant Contact Street:\\s*(.+)'),
    p('owner-street:\\s*(.+)'), p('Address:\\s*(.+)'), p('Street:\\s*(.+)'),
    p('address:\\s*(.+)'), p("Registrant's address:\\s*(.+)"),
    p('street address:\\s*(.+)'),
    p('\\[\\u4F4F\\u6240\\]\\s*(.+)'), // [住所]
    p('\\[Postal Address\\]\\s*(.+)'),
    p('\\uB4F1\\uB85D\\uC778 \\uC8FC\\uC18C:\\s*(.+)'), // 등록인 주소
  ],
  registrant_city: [
    p('Registrant City:\\s*(.+)'), p('Registrant Contact City:\\s*(.+)'),
    p('owner-city:\\s*(.+)'), p('City:\\s*(.+)'), p('city:\\s*(.+)'),
  ],
  registrant_state: [
    p('Registrant State/Province:\\s*(.+)'), p('Registrant Contact State/Province:\\s*(.+)'),
    p('StateProv:\\s*(.+)'), p('State:\\s*(.+)'), p('Province:\\s*(.+)'),
  ],
  registrant_postal: [
    p('Registrant Postal Code:\\s*(.+)'), p('Registrant Contact Postal Code:\\s*(.+)'),
    p('Registrant Zip:\\s*(.+)'), p('owner-zip:\\s*(.+)'),
    p('PostalCode:\\s*(.+)'), p('Zip:\\s*(.+)'), p('Postal Code:\\s*(.+)'),
    p('Registrant Zip Code:\\s*(.+)'), p('postal code:\\s*(.+)'),
    p('\\[\\u90F5\\u4FBF\\u756A\\u53F7\\]\\s*(.+)'), // [郵便番号]
    p('\\uB4F1\\uB85D\\uC778 \\uC6B0\\uD3B8\\uBC88\\uD638:\\s*(.+)'), // 등록인 우편번호
  ],
  registrant_country: [
    p('Registrant Country:\\s*(.+)'), p('Registrant Contact Country:\\s*(.+)'),
    p('owner-country:\\s*(.+)'), p('Country:\\s*(.+)'), p('Country Code:\\s*(.+)'),
    p('country:\\s*(.+)'), p('Registrant Country/Economy:\\s*(.+)'),
  ],
  registrant_phone: [
    p('Registrant Phone:\\s*(.+)'), p('Registrant Contact Phone:\\s*(.+)'),
    p('owner-phone:\\s*(.+)'), p('Phone:\\s*(.+)'), p('phone:\\s*(.+)'),
    p('Telephone:\\s*(.+)'), p('Registrant Phone Number:\\s*(.+)'),
    p('TEL:\\s*(.+)'), p('Phone Number:\\s*(.+)'),
    p('\\[\\u96FB\\u8A71\\u756A\\u53F7\\]\\s*(.+)'), // [電話番号]
  ],
  registrant_phone_ext: [p('Registrant Phone Ext:\\s*(.+)'), p('Registrant Phone Ext\\.:\\s*(.+)')],
  registrant_fax: [
    p('Registrant Fax:\\s*(.+)'), p('Registrant FAX:\\s*(.+)'),
    p('Registrant Fax Ext:\\s*(.+)'), p('Registrant FAX Ext\\.:\\s*(.+)'),
    p('Registrant Facsimile Number:\\s*(.+)'), p('owner-fax:\\s*(.+)'),
    p('Fax:\\s*(.+)'), p('fax-no:\\s*(.+)'), p('FAX:\\s*(.+)'),
    p('Fax Number:\\s*(.+)'),
    p('\\[FAX\\u756A\\u53F7\\]\\s*(.+)'), // [FAX番号]
  ],

  // Admin
  admin_id: [p('Admin ID:\\s*(.+)'), p('Administrative Contact ID:\\s*(.+)'), p('admin-c:\\s*(.+)')],
  admin_name: [
    p('Admin Name:\\s*(.+)'), p('Administrative Contact Name:\\s*(.+)'),
    p('Admin Contact Name:\\s*(.+)'), p('Admin:\\s*(.+)'),
    p('Administrative Contact:\\s*(.+)'),
    p('\\[Administrative Contact\\]\\s*(.+)'), p('admin-c:\\s*(.+)'),
    p('Administrative Name:\\s*(.+)'),
    p('Administrative Contact\\(AC\\):\\s*(.+)'),
    p('\\uCC44\\uAC00\\uC790:\\s*(.+)'), // 책임자:
  ],
  admin_org: [
    p('Admin Organization:\\s*(.+)'), p('Administrative Contact Organization:\\s*(.+)'),
    p('Admin Organisation:\\s*(.+)'), p('Administrative Organization:\\s*(.+)'),
  ],
  admin_email: [
    p('Admin Email:\\s*(.+)'), p('Administrative Contact Email:\\s*(.+)'),
    p('Admin E-mail:\\s*(.+)'), p('AC E-Mail:\\s*(.+)'),
    p('Administrative Email:\\s*(.+)'), p('Administrative E-mail:\\s*(.+)'),
    p('\\uCC44\\uAC00\\uC790 \\uC804\\uC790\\uC6B0\\uD3B8:\\s*(.+)'), // 책임자 전자우편:
  ],
  admin_phone: [
    p('Admin Phone:\\s*(.+)'), p('Administrative Contact Phone:\\s*(.+)'),
    p('Admin Telephone:\\s*(.+)'), p('Administrative Contact Phone Number:\\s*(.+)'),
    p('AC Phone Number:\\s*(.+)'), p('Administrative Phone:\\s*(.+)'),
    p('\\uCC44\\uAC00\\uC790 \\uC804\\uD654\\uBC88\\uD638:\\s*(.+)'), // 책임자 전화번호:
  ],
  admin_street: [
    p('Admin Street:\\s*(.+)'), p('Admin Street1:\\s*(.+)'), p('Admin Street2:\\s*(.+)'),
    p('Admin Address:\\s*(.+)'), p('Admin Address1:\\s*(.+)'), p('Admin Address2:\\s*(.+)'),
    p('Admin Address3:\\s*(.+)'), p('Administrative Contact Address1:\\s*(.+)'),
    p('Administrative Contact Address2:\\s*(.+)'), p('Administrative Address:\\s*(.+)'),
  ],
  admin_city: [p('Admin City:\\s*(.+)'), p('Administrative Contact City:\\s*(.+)'), p('Administrative City:\\s*(.+)')],
  admin_state: [p('Admin State/Province:\\s*(.+)'), p('Administrative Contact State/Province:\\s*(.+)'), p('Administrative State/Province:\\s*(.+)')],
  admin_postal: [p('Admin Postal Code:\\s*(.+)'), p('Administrative Contact Postal Code:\\s*(.+)'), p('Administrative Postal Code:\\s*(.+)')],
  admin_country: [
    p('Admin Country:\\s*(.+)'), p('Administrative Contact Country:\\s*(.+)'),
    p('Administrative Contact Country Code:\\s*(.+)'), p('Administrative Country/Economy:\\s*(.+)'),
  ],

  // Tech
  tech_id: [
    p('Tech ID:\\s*(.+)'), p('Technical Contact ID:\\s*(.+)'),
    p('Tech Contact ID:\\s*(.+)'), p('Technical ID:\\s*(.+)'), p('tech-c:\\s*(.+)'),
  ],
  tech_name: [
    p('Tech Name:\\s*(.+)'), p('Technical Contact Name:\\s*(.+)'),
    p('Tech Contact Name:\\s*(.+)'), p('Technical:\\s*(.+)'),
    p('Technical Contact:\\s*(.+)'),
    p('\\[Technical Contact\\]\\s*(.+)'), p('tech-c:\\s*(.+)'),
    p('Technical Name:\\s*(.+)'),
  ],
  tech_org: [
    p('Tech Organization:\\s*(.+)'), p('Technical Contact Organization:\\s*(.+)'),
    p('Tech Organisation:\\s*(.+)'), p('Technical Contact Organization:\\s*(.+)'),
    p('Technical Organization:\\s*(.+)'),
  ],
  tech_email: [
    p('Tech Email:\\s*(.+)'), p('Technical Contact Email:\\s*(.+)'),
    p('Tech E-mail:\\s*(.+)'), p('Technical Contact Email:\\s*(.+)'),
    p('Tech Contact Email:\\s*(.+)'), p('Technical E-mail:\\s*(.+)'),
  ],
  tech_phone: [
    p('Tech Phone:\\s*(.+)'), p('Technical Contact Phone:\\s*(.+)'),
    p('Tech Telephone:\\s*(.+)'), p('Technical Contact Phone Number:\\s*(.+)'),
    p('Technical Phone:\\s*(.+)'),
  ],
  tech_street: [
    p('Tech Street:\\s*(.+)'), p('Tech Street1:\\s*(.+)'), p('Tech Street2:\\s*(.+)'),
    p('Tech Address:\\s*(.+)'), p('Tech Address1:\\s*(.+)'), p('Tech Address2:\\s*(.+)'),
    p('Tech Address3:\\s*(.+)'), p('Technical Contact Address1:\\s*(.+)'),
    p('Technical Contact Address2:\\s*(.+)'), p('Technical Address:\\s*(.+)'),
  ],
  tech_city: [p('Tech City:\\s*(.+)'), p('Technical Contact City:\\s*(.+)'), p('Technical City:\\s*(.+)')],
  tech_state: [p('Tech State/Province:\\s*(.+)'), p('Technical Contact State/Province:\\s*(.+)'), p('Technical State/Province:\\s*(.+)')],
  tech_postal: [p('Tech Postal Code:\\s*(.+)'), p('Technical Contact Postal Code:\\s*(.+)'), p('Technical Postal Code:\\s*(.+)')],
  tech_country: [
    p('Tech Country:\\s*(.+)'), p('Technical Contact Country:\\s*(.+)'),
    p('Technical Contact Country Code:\\s*(.+)'), p('Technical Country/Economy:\\s*(.+)'),
  ],

  // Billing
  billing_id: [p('Billing ID:\\s*(.+)'), p('Billing Contact ID:\\s*(.+)')],
  billing_name: [p('Billing Name:\\s*(.+)'), p('Billing Contact:\\s*(.+)')],
  billing_org: [
    p('Billing Organization:\\s*(.+)'), p('Billing Contact Organization:\\s*(.+)'),
    p('Entidade Gestora:\\s*(.+)'),
  ],
  billing_email: [
    p('Billing Email:\\s*(.+)'), p('Billing E-mail:\\s*(.+)'),
    p('Billing Contact Email:\\s*(.+)'),
  ],
  billing_phone: [
    p('Billing Phone:\\s*(.+)'), p('Billing Contact Phone Number:\\s*(.+)'),
  ],
  billing_street: [
    p('Billing Street:\\s*(.+)'), p('Billing Street1:\\s*(.+)'), p('Billing Street2:\\s*(.+)'),
    p('Billing Address:\\s*(.+)'), p('Billing Address1:\\s*(.+)'), p('Billing Address2:\\s*(.+)'),
    p('Billing Address3:\\s*(.+)'), p('Billing Contact Address1:\\s*(.+)'),
    p('Billing Contact Address2:\\s*(.+)'),
  ],
  billing_city: [p('Billing City:\\s*(.+)'), p('Billing Contact City:\\s*(.+)')],
  billing_state: [p('Billing State/Province:\\s*(.+)'), p('Billing Contact State/Province:\\s*(.+)')],
  billing_postal: [p('Billing Postal Code:\\s*(.+)'), p('Billing Contact Postal Code:\\s*(.+)')],
  billing_country: [
    p('Billing Country:\\s*(.+)'), p('Billing Contact Country:\\s*(.+)'),
    p('Billing Contact Country Code:\\s*(.+)'), p('Billing Country/Economy:\\s*(.+)'),
  ],

  // DNSSEC / Trademark / Other
  dnssec: [p('DNSSEC:\\s*(.+)'), p('dnssec:\\s*(.+)'), p('\\[Signing Key\\]\\s*(.+)')],
  trademark_name: [p('Trademark Name:\\s*(.+)')],
  trademark_date: [p('Trademark Date:\\s*(.+)')],
  trademark_country: [p('Trademark Country:\\s*(.+)')],
  trademark_number: [p('Trademark Number:\\s*(.+)')],
  remarks: [p('Remarks:\\s*(.+)'), p('remarks:\\s*(.+)')],
};

// Sort by pattern length descending for longest-match-first
const SORTED_PATTERNS: [string, FieldPattern][] = [];
for (const [key, patterns] of Object.entries(FIELD_PATTERNS)) {
  for (const pat of patterns) {
    SORTED_PATTERNS.push([key, pat]);
  }
}
SORTED_PATTERNS.sort((a, b) => b[1].pattern.source.length - a[1].pattern.source.length);

function preprocessWhois(raw: string): string {
  const lines = raw.split('\n');
  const result: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty lines
    if (!trimmed) { i++; continue; }

    // Check if this line is a section label ending with ':' (no value after it)
    // e.g. "Registrar:" or "Relevant dates:"
    if (trimmed.endsWith(':') && trimmed.length > 1) {
      const nextLine = i + 1 < lines.length ? lines[i + 1] : null;
      if (nextLine) {
        const nextTrimmed = nextLine.trim();
        const nextIndent = nextLine.length - nextLine.trimStart().length;
        const curIndent = line.length - line.trimStart().length;

        // Next line is indented more and not empty
        if (nextTrimmed && nextIndent > curIndent) {
          // If next line is also a label (ends with ':'), this is a section header
          // Don't merge - let the sub-fields be parsed individually
          if (nextTrimmed.endsWith(':') && nextTrimmed.length > 1) {
            // Section header like "Relevant dates:" followed by "Registered on: ..."
            // Skip the header, process sub-fields below
            i++;
            continue;
          }

          // Merge: "Key: Value"
          const key = trimmed.slice(0, -1).trim();
          result.push(`${key}: ${nextTrimmed}`);
          i += 2;

          // Handle multi-value fields (e.g. multiple Name Server lines under same section)
          while (i < lines.length) {
            const contLine = lines[i];
            const contTrimmed = contLine.trim();
            const contIndent = contLine.length - contLine.trimStart().length;
            if (!contTrimmed || contIndent <= curIndent) break;
            // If it looks like a sub-field (has colon), don't merge
            if (contTrimmed.includes(':') && contTrimmed.split(':')[0].trim().length > 1) break;
            // Continuation value
            if (contTrimmed) result.push(`${key}: ${contTrimmed}`);
            i++;
          }
          continue;
        }
      }
    }

    result.push(trimmed);
    i++;
  }

  return result.join('\n');
}

function extractFields(rawResponse: string): Map<string, string[]> {
  const processed = preprocessWhois(rawResponse);
  const fields = new Map<string, string[]>();
  const lines = processed.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#')) continue;

    const wordCount = trimmed.split(/\s+/).length;
    if (wordCount > 10) continue;

    for (const [key, fieldPattern] of SORTED_PATTERNS) {
      const match = trimmed.match(fieldPattern.pattern);
      if (match && match.length > 1) {
        const value = match[1].trim();
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

function parseDate(dateStr: string): string | null {
  if (!dateStr) return null;
  dateStr = dateStr.split('(')[0].trim();
  dateStr = dateStr.replace(/\s*(JST|UTC|GMT|KST)\s*$/i, '').trim();

  const d = new Date(dateStr);
  if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];

  // dd-MMM-yyyy
  const dmyMatch = dateStr.match(/^(\d{2})-([A-Za-z]{3})-(\d{4})/);
  if (dmyMatch) {
    const months: Record<string, string> = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' };
    const month = months[dmyMatch[2].toLowerCase()];
    if (month) {
      const d2 = new Date(`${dmyMatch[3]}-${month}-${dmyMatch[1]}`);
      if (!isNaN(d2.getTime())) return d2.toISOString().split('T')[0];
    }
  }

  return null;
}

function parseStatuses(values: string[]): string[] {
  const result: string[] = [];
  for (const val of values) {
    for (const part of val.split(/[\s\t]+/)) {
      const s = part.trim().toLowerCase();
      if (s && !s.startsWith('http') && !s.startsWith('(') && !result.includes(s)) {
        result.push(s);
      }
    }
  }
  return result;
}

function parseContact(fields: Map<string, string[]>, prefix: string): ContactInfo | null {
  const name = getFieldValue(fields, `${prefix}_name`);
  const org = getFieldValue(fields, `${prefix}_org`);
  const email = getFieldValue(fields, `${prefix}_email`);
  const street = getFieldValue(fields, `${prefix}_street`);
  const city = getFieldValue(fields, `${prefix}_city`);
  const state = getFieldValue(fields, `${prefix}_state`);
  const postal = getFieldValue(fields, `${prefix}_postal`);
  const country = getFieldValue(fields, `${prefix}_country`);
  const phone = getFieldValue(fields, `${prefix}_phone`);

  if (!name && !org && !email) return null;
  return { name, organization: org, email, phone, street, city, state, postalCode: postal, country, roles: [] };
}

function parseRegistrar(fields: Map<string, string[]>): RegistrarInfo | null {
  let name = getFieldValue(fields, 'registrar_name');
  // Clean registrar name - remove URL in parentheses
  if (name) {
    const parenIndex = name.indexOf('(');
    if (parenIndex > 0) name = name.slice(0, parenIndex).trim();
  }

  if (!name) return null;
  return {
    name,
    ianaId: getFieldValue(fields, 'registrar_iana_id'),
    website: getFieldValue(fields, 'registrar_url'),
    whoisServer: getFieldValue(fields, 'registrar_whois'),
  };
}

function parseDnssec(fields: Map<string, string[]>): DnssecInfo | null {
  const val = getFieldValue(fields, 'dnssec');
  if (!val) return null;
  const signed = !val.toLowerCase().includes('unsigned') && val.toLowerCase() !== 'no';
  return { signed, delegationSigned: signed, dsData: [], keyData: [] };
}

export class RegexParser {
  parse(rawResponse: string, query: string, queryType: WhoisQueryType): WhoisResponse | null {
    if (!rawResponse) return null;

    const fields = extractFields(rawResponse);
    if (fields.size === 0) return null;

    const domain = getFieldValue(fields, 'domain').toLowerCase() || query;
    const registrar = parseRegistrar(fields);

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
      statuses: parseStatuses(getFieldValues(fields, 'status')),
      nameServers: getFieldValues(fields, 'nameserver').map(n => n.toLowerCase().trim()).filter(Boolean),
      dates: {
        created: parseDate(getFieldValue(fields, 'created')),
        updated: parseDate(getFieldValue(fields, 'updated')),
        expires: parseDate(getFieldValue(fields, 'expires')),
      },
      contacts: {
        registrant: parseContact(fields, 'registrant'),
        admin: parseContact(fields, 'admin'),
        tech: parseContact(fields, 'tech'),
        billing: parseContact(fields, 'billing'),
      },
      registrar,
      registry: null,
      privacy: null,
      dnssec: parseDnssec(fields),
    };
  }
}
