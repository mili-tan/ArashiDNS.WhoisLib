export interface GeoInfo {
  country: string | null;
  countryCode: string | null;
  state: string | null;
  city: string | null;
  street: string | null;
}

const COUNTRY_CODES: Record<string, string> = {
  AF: 'Afghanistan', AL: 'Albania', DZ: 'Algeria', AD: 'Andorra',
  AO: 'Angola', AG: 'Antigua and Barbuda', AR: 'Argentina', AM: 'Armenia',
  AU: 'Australia', AT: 'Austria', AZ: 'Azerbaijan', BS: 'Bahamas',
  BH: 'Bahrain', BD: 'Bangladesh', BB: 'Barbados', BY: 'Belarus',
  BE: 'Belgium', BZ: 'Belize', BJ: 'Benin', BT: 'Bhutan',
  BO: 'Bolivia', BA: 'Bosnia and Herzegovina', BW: 'Botswana', BR: 'Brazil',
  BN: 'Brunei', BG: 'Bulgaria', BF: 'Burkina Faso', BI: 'Burundi',
  KH: 'Cambodia', CM: 'Cameroon', CA: 'Canada', CV: 'Cape Verde',
  CF: 'Central African Republic', TD: 'Chad', CL: 'Chile', CN: 'China',
  CO: 'Colombia', KM: 'Comoros', CG: 'Congo', CD: 'Congo (DRC)',
  CR: 'Costa Rica', CI: "Cote d'Ivoire", HR: 'Croatia', CU: 'Cuba',
  CY: 'Cyprus', CZ: 'Czech Republic', DK: 'Denmark', DJ: 'Djibouti',
  DM: 'Dominica', DO: 'Dominican Republic', EC: 'Ecuador', EG: 'Egypt',
  SV: 'El Salvador', GQ: 'Equatorial Guinea', ER: 'Eritrea', EE: 'Estonia',
  ET: 'Ethiopia', FJ: 'Fiji', FI: 'Finland', FR: 'France',
  GA: 'Gabon', GM: 'Gambia', GE: 'Georgia', DE: 'Germany',
  GH: 'Ghana', GR: 'Greece', GD: 'Grenada', GT: 'Guatemala',
  GN: 'Guinea', GW: 'Guinea-Bissau', GY: 'Guyana', HT: 'Haiti',
  HN: 'Honduras', HK: 'Hong Kong', HU: 'Hungary', IS: 'Iceland',
  IN: 'India', ID: 'Indonesia', IR: 'Iran', IQ: 'Iraq',
  IE: 'Ireland', IL: 'Israel', IT: 'Italy', JM: 'Jamaica',
  JP: 'Japan', JO: 'Jordan', KZ: 'Kazakhstan', KE: 'Kenya',
  KI: 'Kiribati', KP: 'North Korea', KR: 'South Korea', KW: 'Kuwait',
  KG: 'Kyrgyzstan', LA: 'Laos', LV: 'Latvia', LB: 'Lebanon',
  LS: 'Lesotho', LR: 'Liberia', LY: 'Libya', LI: 'Liechtenstein',
  LT: 'Lithuania', LU: 'Luxembourg', MO: 'Macao', MK: 'North Macedonia',
  MG: 'Madagascar', MW: 'Malawi', MY: 'Malaysia', MV: 'Maldives',
  ML: 'Mali', MT: 'Malta', MH: 'Marshall Islands', MR: 'Mauritania',
  MU: 'Mauritius', MX: 'Mexico', FM: 'Micronesia', MD: 'Moldova',
  MC: 'Monaco', MN: 'Mongolia', ME: 'Montenegro', MA: 'Morocco',
  MZ: 'Mozambique', MM: 'Myanmar', NA: 'Namibia', NR: 'Nauru',
  NP: 'Nepal', NL: 'Netherlands', NZ: 'New Zealand', NI: 'Nicaragua',
  NE: 'Niger', NG: 'Nigeria', NO: 'Norway', OM: 'Oman',
  PK: 'Pakistan', PW: 'Palau', PA: 'Panama', PG: 'Papua New Guinea',
  PY: 'Paraguay', PE: 'Peru', PH: 'Philippines', PL: 'Poland',
  PT: 'Portugal', QA: 'Qatar', RO: 'Romania', RU: 'Russia',
  RW: 'Rwanda', KN: 'Saint Kitts and Nevis', LC: 'Saint Lucia',
  VC: 'Saint Vincent and the Grenadines', WS: 'Samoa', SM: 'San Marino',
  ST: 'Sao Tome and Principe', SA: 'Saudi Arabia', SN: 'Senegal',
  RS: 'Serbia', SC: 'Seychelles', SL: 'Sierra Leone', SG: 'Singapore',
  SK: 'Slovakia', SI: 'Slovenia', SB: 'Solomon Islands', SO: 'Somalia',
  ZA: 'South Africa', SS: 'South Sudan', ES: 'Spain', LK: 'Sri Lanka',
  SD: 'Sudan', SR: 'Suriname', SE: 'Sweden', CH: 'Switzerland',
  SY: 'Syria', TW: 'Taiwan', TJ: 'Tajikistan', TZ: 'Tanzania',
  TH: 'Thailand', TL: 'Timor-Leste', TG: 'Togo', TO: 'Tonga',
  TT: 'Trinidad and Tobago', TN: 'Tunisia', TR: 'Turkey', TM: 'Turkmenistan',
  TV: 'Tuvalu', UG: 'Uganda', UA: 'Ukraine', AE: 'United Arab Emirates',
  GB: 'United Kingdom', UK: 'United Kingdom', US: 'United States',
  UY: 'Uruguay', UZ: 'Uzbekistan', VU: 'Vanuatu', VE: 'Venezuela',
  VN: 'Vietnam', YE: 'Yemen', ZM: 'Zambia', ZW: 'Zimbabwe',
  XK: 'Kosovo', PS: 'Palestine', EU: 'European Union',
  AP: 'Asia/Pacific Region',
};

const COUNTRY_ALIASES: Record<string, string> = {
  'USA': 'US', 'U.S.A.': 'US', 'U.S.': 'US',
  'UNITED STATES': 'US', 'UNITED STATES OF AMERICA': 'US',
  'UK': 'GB', 'UNITED KINGDOM': 'GB', 'GREAT BRITAIN': 'GB', 'ENGLAND': 'GB',
  'CHINA': 'CN', 'PRC': 'CN', 'PEOPLES REPUBLIC OF CHINA': 'CN',
  'JAPAN': 'JP', 'KOREA': 'KR', 'SOUTH KOREA': 'KR', 'REPUBLIC OF KOREA': 'KR',
  'NORTH KOREA': 'KP', 'GERMANY': 'DE', 'DEUTSCHLAND': 'DE',
  'FRANCE': 'FR', 'FRENCH REPUBLIC': 'FR', 'ITALY': 'IT', 'ITALIA': 'IT',
  'SPAIN': 'ES', 'ESPANA': 'ES', 'BRAZIL': 'BR', 'BRASIL': 'BR',
  'RUSSIA': 'RU', 'RUSSIAN FEDERATION': 'RU', 'INDIA': 'IN',
  'AUSTRALIA': 'AU', 'CANADA': 'CA', 'MEXICO': 'MX',
  'ARGENTINA': 'AR', 'COLOMBIA': 'CO', 'CHILE': 'CL', 'PERU': 'PE',
  'VENEZUELA': 'VE', 'TURKEY': 'TR', 'TURKIYE': 'TR',
  'SAUDI ARABIA': 'SA', 'UNITED ARAB EMIRATES': 'AE', 'UAE': 'AE',
  'SINGAPORE': 'SG', 'MALAYSIA': 'MY', 'THAILAND': 'TH',
  'VIETNAM': 'VN', 'VIET NAM': 'VN', 'INDONESIA': 'ID',
  'PHILIPPINES': 'PH', 'TAIWAN': 'TW', 'TAIPEI': 'TW',
  'HONG KONG': 'HK', 'MACAO': 'MO', 'MACAU': 'MO',
  'NEW ZEALAND': 'NZ', 'NZ': 'NZ', 'SWEDEN': 'SE', 'NORWAY': 'NO',
  'DENMARK': 'DK', 'FINLAND': 'FI', 'NETHERLANDS': 'NL', 'HOLLAND': 'NL',
  'BELGIUM': 'BE', 'SWITZERLAND': 'CH', 'SUISSE': 'CH', 'SCHWEIZ': 'CH',
  'AUSTRIA': 'AT', 'OSTERREICH': 'AT', 'POLAND': 'PL', 'POLSKA': 'PL',
  'CZECH REPUBLIC': 'CZ', 'CZECHIA': 'CZ', 'HUNGARY': 'HU',
  'ROMANIA': 'RO', 'BULGARIA': 'BG', 'GREECE': 'GR', 'PORTUGAL': 'PT',
  'IRELAND': 'IE', 'EIRE': 'IE', 'ISRAEL': 'IL', 'EGYPT': 'EG',
  'SOUTH AFRICA': 'ZA', 'NIGERIA': 'NG', 'KENYA': 'KE',
  'UKRAINE': 'UA', 'BELARUS': 'BY', 'LITHUANIA': 'LT',
  'LATVIA': 'LV', 'ESTONIA': 'EE', 'CROATIA': 'HR', 'SERBIA': 'RS',
  'SLOVENIA': 'SI', 'SLOVAKIA': 'SK', 'ICELAND': 'IS',
  'VATICAN': 'VA', 'HOLY SEE': 'VA',
};

// Build reverse map: full name -> code
const COUNTRY_NAME_TO_CODE: Record<string, string> = {};
for (const [code, name] of Object.entries(COUNTRY_CODES)) {
  COUNTRY_NAME_TO_CODE[name.toUpperCase()] = code;
}

export function identifyCountryCode(input: string | null): string | null {
  if (!input) return null;
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Direct 2-letter code
  if (trimmed.length === 2 && COUNTRY_CODES[trimmed.toUpperCase()]) {
    return trimmed.toUpperCase();
  }

  // Check aliases
  const upper = trimmed.toUpperCase();
  if (COUNTRY_ALIASES[upper]) return COUNTRY_ALIASES[upper];

  // Check country name -> code
  if (COUNTRY_NAME_TO_CODE[upper]) return COUNTRY_NAME_TO_CODE[upper];

  // Check if input contains a country name
  for (const [code, name] of Object.entries(COUNTRY_CODES)) {
    if (name.toUpperCase() === upper) return code;
  }

  for (const [alias, code] of Object.entries(COUNTRY_ALIASES)) {
    if (alias === upper) return code;
  }

  return null;
}

export function getCountryName(code: string): string | null {
  return COUNTRY_CODES[code.toUpperCase()] ?? null;
}

export function normalizeGeo(country: string | null, state?: string | null, city?: string | null, street?: string | null): GeoInfo {
  const info: GeoInfo = { country, state: state ?? null, city: city ?? null, street: street ?? null };

  if (country) {
    const code = identifyCountryCode(country);
    if (code) {
      info.countryCode = code;
      const fullName = COUNTRY_CODES[code];
      if (fullName) info.country = fullName;
    }
  }

  return info;
}

export function extractCountryFromAddress(address: string | null): string | null {
  if (!address) return null;
  const parts = address.split(/[,;]/).map(p => p.trim()).filter(Boolean);
  if (parts.length === 0) return null;

  const lastPart = parts[parts.length - 1];
  const code = identifyCountryCode(lastPart);
  if (code) return code;

  for (const [code2, name] of Object.entries(COUNTRY_CODES)) {
    if (lastPart.toUpperCase().includes(name.toUpperCase())) return code2;
  }

  return null;
}
