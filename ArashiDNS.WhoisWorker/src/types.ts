export type WhoisQueryType = 'domain' | 'ipv4' | 'ipv6' | 'asn';

export interface RegistryInfo {
  name: string;
  website: string;
  whoisServer: string;
  rdapEndpoint?: string;
  type?: string;
  manager?: string;
  sponsoringOrganisation?: string;
  registrationDate?: string;
  lastUpdated?: string;
  adminContact?: { name?: string; email?: string; voice?: string; fax?: string };
  techContact?: { name?: string; email?: string; voice?: string; fax?: string };
}

export interface RegistrarInfo {
  ianaId: string;
  name: string;
  website: string;
  whoisServer: string;
  rdapUrl?: string;
  status?: string;
  country?: string;
  contact?: { name?: string; phone?: string; email?: string };
}

export interface ContactInfo {
  name: string;
  organization: string;
  email: string;
  phone: string;
  street: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  roles: string[];
}

export interface PrivacyInfo {
  isPrivate: boolean;
  provider: string | null;
}

export interface DomainDates {
  created: string | null;
  updated: string | null;
  expires: string | null;
}

export interface DsRecord {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
}

export interface DnssecKey {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: string;
}

export interface DnssecInfo {
  signed: boolean;
  delegationSigned: boolean;
  dsData: DsRecord[];
  keyData: DnssecKey[];
}

export interface FormattedResult {
  domain: string;
  registry: RegistryInfo | null;
  registrar: RegistrarInfo | null;
  privacy: PrivacyInfo | null;
  contacts: ContactInfo[];
  dates: DomainDates | null;
  nameServers: string[];
  status: string[];
  dnssec: DnssecInfo | null;
  rawResponse?: string;
  trace?: TraceEntry[];
}

export interface TraceEntry {
  protocol: string;
  endpoint: string;
  formatter: string;
  success: boolean;
  error?: string;
}

export interface WhoisResponse {
  query: string;
  domain: string;
  queryType: WhoisQueryType;
  registry: RegistryInfo | null;
  registrar: RegistrarInfo | null;
  privacy: PrivacyInfo | null;
  contacts: ContactCollection;
  dates: DomainDates | null;
  nameServers: string[];
  statuses: string[];
  dnssec: DnssecInfo | null;
  whoisServer: string;
  port43: string | null;
  rawResponse: string | null;
  referralChain: string[];
  isSuccessful: boolean;
  errorMessage: string | null;
}

export interface ContactCollection {
  registrant: ContactInfo | null;
  admin: ContactInfo | null;
  tech: ContactInfo | null;
  billing: ContactInfo | null;
}

export interface RegistrarEntry {
  id: string;
  name: string;
  status: string;
  rdapBaseUrl: string;
}

export interface TldInfo {
  registryName: string;
  website: string;
  whoisServer: string;
  rdapEndpoint: string;
}

export interface Env {
  A_WHOIS_CACHE_KV: KVNamespace;
  API_KEY?: string;
  DEEPSEEK_API_KEY?: string;
  DEEPSEEK_API_ENDPOINT?: string;
  DEEPSEEK_MODEL?: string;
  DEEPSEEK_ENABLE_THINKING?: string;
  DEEPSEEK_REASONING_EFFORT?: string;
  RATE_LIMIT_RPM?: string;
}
