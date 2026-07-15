export type AvailabilityStatus = 'unknown' | 'not_registered' | 'registered' | 'reserved' | 'throttled' | 'error';

export interface AvailabilityResult {
  status: AvailabilityStatus;
  isAvailable: boolean;
  isThrottled: boolean;
  isReserved: boolean;
  errorMessage?: string;
}

const NOT_REGISTERED_PATTERNS = [
  /No match for\s+"/i,
  /No match for\s+domain/i,
  /^NOT FOUND/im,
  /^No Data Found/im,
  /Domain not found/i,
  /Status:\s*free\b/i,
  /Domain Status:\s*available\b/i,
  /^Status:\s*available$/im,
  /No such domain/i,
  /The queried object does not exist/i,
  /Domain not registered/i,
  /is free/i,
  /NOT EXIST/i,
  /No match for/i,
  /No records matching/i,
  /DOMAIN NOT FOUND/i,
  /^Not found$/im,
  /AVAILABLE FOR REGISTRATION/i,
  /No entries found/i,
  /^AVAILABLE$/im,
  /is available for registration/i,
  /queried domain name is not registered/i,
  /has not been registered/i,
  /no matching record/i,
  /is free for registration/i,
];

const REGISTERED_PATTERNS = [
  /Domain Name:/i,
  /Domain name:/i,
  /domain:/i,
  /Registry Domain ID:/i,
  /Registrar:/i,
  /Creation Date:/i,
  /Created:/i,
  /Registration Date:/i,
  /Registry Expiry Date:/i,
  /Expiration Date:/i,
  /Updated Date:/i,
  /Last Updated:/i,
  /Name Server:/i,
  /Nameserver:/i,
  /nserver:/i,
  /Domain Status:/i,
  /Status:/i,
];

const THROTTLED_PATTERNS = [
  /exceeded/i,
  /rate limit/i,
  /try again later/i,
  /too many requests/i,
  /query limit/i,
  /throttl/i,
  /abuse/i,
  /Please try again/i,
];

const RESERVED_PATTERNS = [
  /reserved/i,
  /reserved by/i,
  /reserved domain/i,
  /premium domain/i,
  /restricted/i,
];

export function detectAvailability(rawResponse: string | null): AvailabilityResult {
  if (!rawResponse) {
    return { status: 'unknown', isAvailable: false, isThrottled: false, isReserved: false, errorMessage: 'Empty response' };
  }

  if (THROTTLED_PATTERNS.some(p => p.test(rawResponse))) {
    return { status: 'throttled', isAvailable: false, isThrottled: true, isReserved: false };
  }

  if (RESERVED_PATTERNS.some(p => p.test(rawResponse))) {
    return { status: 'reserved', isAvailable: false, isThrottled: false, isReserved: true };
  }

  const isNotRegistered = NOT_REGISTERED_PATTERNS.some(p => p.test(rawResponse));
  if (isNotRegistered) {
    const hasRegisteredSignals = REGISTERED_PATTERNS.some(p => p.test(rawResponse));
    if (!hasRegisteredSignals) {
      return { status: 'not_registered', isAvailable: true, isThrottled: false, isReserved: false };
    }
  }

  const registeredCount = REGISTERED_PATTERNS.filter(p => p.test(rawResponse)).length;
  if (registeredCount >= 2) {
    return { status: 'registered', isAvailable: false, isThrottled: false, isReserved: false };
  }

  return { status: 'unknown', isAvailable: false, isThrottled: false, isReserved: false };
}

export function detectAvailabilityFromRdap(rawJson: string | null): AvailabilityResult {
  if (!rawJson) {
    return { status: 'unknown', isAvailable: false, isThrottled: false, isReserved: false, errorMessage: 'Empty RDAP response' };
  }

  try {
    const root = JSON.parse(rawJson);

    if (root.errorCode) {
      const code = root.errorCode;
      if (code === 404 || code === 410) {
        return { status: 'not_registered', isAvailable: true, isThrottled: false, isReserved: false };
      }
      if (code === 429) {
        return { status: 'throttled', isAvailable: false, isThrottled: true, isReserved: false };
      }
    }

    if (root.ldhName || root.unicodeName) {
      return { status: 'registered', isAvailable: false, isThrottled: false, isReserved: false };
    }
  } catch {
    // Not valid JSON
  }

  return { status: 'unknown', isAvailable: false, isThrottled: false, isReserved: false };
}
