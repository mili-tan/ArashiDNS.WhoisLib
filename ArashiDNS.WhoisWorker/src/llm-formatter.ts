import type { FormattedResult, Env } from './types';

const SYSTEM_PROMPT = `You are a WHOIS data parser assistant. Your task is to parse raw WHOIS/RDAP response data and output structured JSON.

Rules:
1. Merge identical contact information (Registrant/Admin/Tech/Billing) and add a 'roles' array field
2. Detect if WHOIS privacy protection is being used
3. Identify Registry (NIC) and Registrar information with their official websites
4. Simplify output by removing redundant fields
5. Return empty strings for missing fields, never null
6. Dates should be in ISO 8601 format (yyyy-MM-dd)
7. Status values should be lowercase with no URL prefixes
8. Name servers should be lowercase
9. Extract DNSSEC information if available (signed, delegationSigned, dsData, keyData)`;

const JSON_FORMAT_PROMPT = `Parse the following WHOIS/RDAP data into the specified JSON format.

Output JSON schema:
{
  "domain": "string",
  "registry": {
    "name": "string",
    "website": "string",
    "whoisServer": "string"
  },
  "registrar": {
    "name": "string",
    "ianaId": "string",
    "website": "string",
    "whoisServer": "string"
  },
  "privacy": {
    "isPrivate": boolean,
    "provider": "string"
  },
  "contacts": [
    {
      "name": "string",
      "organization": "string",
      "email": "string",
      "phone": "string",
      "street": "string",
      "city": "string",
      "state": "string",
      "postalCode": "string",
      "country": "string",
      "roles": ["registrant", "admin", "tech", "billing"]
    }
  ],
  "dates": {
    "created": "yyyy-MM-dd",
    "updated": "yyyy-MM-dd",
    "expires": "yyyy-MM-dd"
  },
  "nameServers": ["string"],
  "status": ["string"],
  "dnssec": {
    "signed": boolean,
    "delegationSigned": boolean,
    "dsRecords": [{ "keyTag": number, "algorithm": number, "digestType": number, "digest": "string" }]
  }
}

WHOIS/RDAP Raw Data:
{raw}

Output JSON only, no explanations.`;

export class LlmFormatter {
  private apiEndpoint: string;
  private apiKey: string;
  private model: string;
  private enableThinking: boolean;
  private reasoningEffort: string;

  constructor(env: Env) {
    this.apiEndpoint = env.DEEPSEEK_API_ENDPOINT || 'https://api.deepseek.com/chat/completions';
    this.apiKey = env.DEEPSEEK_API_KEY || '';
    this.model = env.DEEPSEEK_MODEL || 'deepseek-v4-flash';
    this.enableThinking = env.DEEPSEEK_ENABLE_THINKING === 'true';
    this.reasoningEffort = env.DEEPSEEK_REASONING_EFFORT || 'high';
  }

  get isEnabled(): boolean {
    return !!this.apiKey;
  }

  async format(rawResponse: string): Promise<FormattedResult | null> {
    if (!this.isEnabled) return null;

    try {
      const prompt = JSON_FORMAT_PROMPT.replace('{raw}', rawResponse);

      const body: Record<string, unknown> = {
        model: this.model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: prompt },
        ],
        max_tokens: 4096,
        stream: false,
      };

      // Thinking mode: DeepSeek requires thinking param, no temperature
      if (this.enableThinking) {
        body['thinking'] = { type: 'enabled' };
        body['reasoning_effort'] = this.reasoningEffort;
      } else {
        body['temperature'] = 0.1;
      }

      const resp = await fetch(this.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
      });

      if (!resp.ok) return null;

      const data = await resp.json() as {
        choices?: { message?: { content?: string } }[];
      };

      const content = data.choices?.[0]?.message?.content;
      if (!content) return null;

      // Extract JSON from response (handle markdown code blocks)
      let jsonStr = content.trim();
      const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (jsonMatch) jsonStr = jsonMatch[1].trim();

      const parsed = JSON.parse(jsonStr) as FormattedResult;
      return this.normalizeResult(parsed);
    } catch {
      return null;
    }
  }

  private normalizeResult(result: FormattedResult): FormattedResult {
    return {
      domain: result.domain || '',
      registry: result.registry || null,
      registrar: result.registrar || null,
      privacy: result.privacy || null,
      contacts: Array.isArray(result.contacts) ? result.contacts.map(c => ({
        name: c.name || '',
        organization: c.organization || '',
        email: c.email || '',
        phone: c.phone || '',
        street: c.street || '',
        city: c.city || '',
        state: c.state || '',
        postalCode: c.postalCode || '',
        country: c.country || '',
        roles: Array.isArray(c.roles) ? c.roles : [],
      })) : [],
      dates: result.dates || null,
      nameServers: Array.isArray(result.nameServers) ? result.nameServers : [],
      status: Array.isArray(result.status) ? result.status : [],
      dnssec: result.dnssec || null,
    };
  }
}
