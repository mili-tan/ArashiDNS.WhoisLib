import type { WhoisResponse, PrivacyInfo } from '../types';

const PRIVACY_KEYWORDS = [
  'redacted for privacy', 'redacted for gdpr', 'data protected',
  'data not available', 'whoisguard', 'domains by proxy',
  'contact privacy', 'withheld for privacy', 'perfect privacy',
  'registration private', 'privacyprotect', 'privacydotlink',
  'privacy service', 'whoisprivacy', 'identity protection service',
  'super privacy service', 'dynadot privacy', 'not disclosed',
  'personal data is not published', 'please query the rdds',
];

const PRIVACY_EMAIL_DOMAINS = [
  '@domainsbyproxy.com', '@whoisguard.com', '@contactprivacy.com',
  '@withheldforprivacy.com', '@privacyprotect.com', '@privacydotlink.com',
  '@proxy.domain.com', '@privacy', '@redacted', '@protect',
];

const PRIVACY_PROVIDERS: Record<string, string> = {
  'domains by proxy': 'Domains By Proxy (GoDaddy)',
  'domainsbyproxy': 'Domains By Proxy (GoDaddy)',
  'registration private': 'Domains By Proxy (GoDaddy)',
  'whoisguard': 'WhoisGuard (Namecheap)',
  'contact privacy': 'Contact Privacy (Google)',
  'contactprivacy': 'Contact Privacy (Google)',
  'withheld for privacy': 'Withheld for Privacy (Namecheap)',
  'withheldforprivacy': 'Withheld for Privacy (Namecheap)',
  'perfect privacy': 'Perfect Privacy (Network Solutions)',
  'privacyprotect': 'Privacy Protect',
  'privacydotlink': 'PrivacyDotLink',
  'super privacy service': 'Dynadot Privacy',
  'dynadot privacy': 'Dynadot Privacy',
  'redacted for privacy': 'GDPR Redaction',
  'redacted for gdpr': 'GDPR Redaction',
  'identity protection service': 'Identity Protection Service',
};

export function detectPrivacy(response: WhoisResponse): PrivacyInfo {
  const rawResponse = (response.rawResponse || '').toLowerCase();
  const indicators: string[] = [];

  for (const keyword of PRIVACY_KEYWORDS) {
    if (rawResponse.includes(keyword)) {
      indicators.push(keyword);
    }
  }

  const registrantEmail = response.contacts?.registrant?.email || '';
  for (const domain of PRIVACY_EMAIL_DOMAINS) {
    if (registrantEmail.toLowerCase().includes(domain)) {
      indicators.push(`Email domain: ${domain}`);
    }
  }

  const redactedCount = (rawResponse.match(/redacted/g) || []).length;
  if (redactedCount >= 3) {
    indicators.push(`Multiple redacted fields (${redactedCount})`);
  }

  if (response.contacts?.registrant) {
    const r = response.contacts.registrant;
    const hasAnyData = !!r.name || !!r.organization || (!!r.email && !r.email.toLowerCase().includes('redacted'));
    if (!hasAnyData) {
      indicators.push('No registrant data provided');
    }
  }

  const isPrivate = indicators.length > 0;
  let provider = detectProvider(rawResponse);

  if (isPrivate && !provider) {
    if (indicators.some(i => i.includes('redacted'))) provider = 'Redacted';
    else if (indicators.some(i => i.includes('No registrant data'))) provider = 'Registrar does not provide information';
    else provider = 'Unknown privacy service';
  }

  return { isPrivate, provider };
}

function detectProvider(rawResponse: string): string | null {
  for (const [key, value] of Object.entries(PRIVACY_PROVIDERS)) {
    if (rawResponse.includes(key)) return value;
  }
  return null;
}
