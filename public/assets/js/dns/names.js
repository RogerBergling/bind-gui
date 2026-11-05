/* DNS name handling, validation and address canonicalisation. */

export function stripTrailingDot(name) {
  const text = String(name ?? '');
  return text.endsWith('.') ? text.slice(0, -1) : text;
}

export function ensureTrailingDot(name) {
  const text = String(name ?? '');
  if (!text || text === '.') return '.';
  return text.endsWith('.') ? text : `${text}.`;
}

export function isAbsoluteName(name) {
  return String(name ?? '').endsWith('.') && name !== '.';
}

export function normalizeName(name, origin = '.') {
  const raw = String(name ?? '').trim();
  if (!raw || raw === '@') return ensureTrailingDot(origin);
  if (raw === '.') return '.';
  const absolute = raw.endsWith('.');
  const base = origin && origin !== '.' ? stripTrailingDot(String(origin).toLowerCase()) : '';
  const value = raw.toLowerCase();
  if (absolute) return ensureTrailingDot(value);
  if (!base) return ensureTrailingDot(value);
  return ensureTrailingDot(`${value}.${base}`);
}

export function toFqdn(name, origin = '.') {
  return normalizeName(name, origin);
}

export function canonicalName(name, origin = '.') {
  return normalizeName(name, origin).toLowerCase();
}

export function labelsOf(name) {
  const normalized = stripTrailingDot(String(name ?? '').toLowerCase());
  if (!normalized) return [];
  return normalized.split('.');
}

export function isSubdomain(name, parent) {
  const child = ensureTrailingDot(String(name ?? '').toLowerCase());
  const zone = ensureTrailingDot(String(parent ?? '').toLowerCase());
  if (zone === '.') return true;
  return child === zone || child.endsWith(`.${zone}`);
}

export function isStrictSubdomain(name, parent) {
  const child = ensureTrailingDot(String(name ?? '').toLowerCase());
  const zone = ensureTrailingDot(String(parent ?? '').toLowerCase());
  return child !== zone && isSubdomain(child, zone);
}

export function parentName(name) {
  const normalized = ensureTrailingDot(String(name ?? '').toLowerCase());
  if (normalized === '.') return '.';
  const labels = labelsOf(normalized);
  return labels.length <= 1 ? '.' : ensureTrailingDot(labels.slice(1).join('.'));
}

export function isWildcard(name) {
  return labelsOf(name)[0] === '*';
}

export function wildcardBase(name) {
  const labels = labelsOf(name);
  return isWildcard(name) ? ensureTrailingDot(labels.slice(1).join('.')) : normalizeName(name);
}

export function validateDomainName(name, options = {}) {
  const {
    allowWildcard = true,
    allowUnderscore = true,
    requireAbsolute = false,
    allowRoot = true,
  } = options;
  const value = String(name ?? '');
  const errors = [];
  const warnings = [];
  if (!value) {
    errors.push('The name is empty.');
    return { valid: false, errors, warnings, name: value };
  }
  if (value === '.') {
    if (!allowRoot) errors.push('The root name is not allowed here.');
    return { valid: errors.length === 0, errors, warnings, name: '.' };
  }
  if (requireAbsolute && !value.endsWith('.')) {
    warnings.push('The name is relative; BIND resolves it against the current $ORIGIN.');
  }
  const normalized = ensureTrailingDot(value.toLowerCase());
  if (normalized.length > 255) errors.push('The full name is longer than the 255-octet DNS limit.');
  const labels = labelsOf(normalized);
  if (labels.length === 0) errors.push('The name has no labels.');
  labels.forEach((label, index) => {
    if (!label) {
      errors.push('The name contains an empty label (two consecutive dots).');
      return;
    }
    if (label.length > 63) errors.push(`Label “${label}” is longer than 63 octets.`);
    if (label === '*') {
      if (!allowWildcard) errors.push('Wildcards are not allowed in this context.');
      else if (index !== 0) errors.push('A wildcard is only valid as the left-most label.');
      return;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      warnings.push(`Label “${label}” starts or ends with a hyphen.`);
    }
    if (/[^a-z0-9_-]/i.test(label)) {
      if (/[^\x00-\x7f]/.test(label)) warnings.push(`Label “${label}” is not ASCII; use an IDNA A-label (xn--…) for DNS.`);
      else warnings.push(`Label “${label}” contains an unusual character.`);
    }
    if (label.includes('_') && !allowUnderscore) {
      errors.push(`Label “${label}” contains an underscore, which is not valid in a hostname.`);
    }
  });
  if (normalized.includes('..')) errors.push('The name contains two consecutive dots.');
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    name: normalized,
    labels,
  };
}

function decodeLabel(label) {
  return label.replace(/\\(\d{3})/g, (_, digits) => String.fromCharCode(Number(digits)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\(.)/g, '$1');
}

export function nameToWire(name) {
  const normalized = ensureTrailingDot(String(name ?? '').toLowerCase());
  if (normalized === '.') return new Uint8Array([0]);
  const encoder = new TextEncoder();
  const labels = labelsOf(normalized).map(decodeLabel);
  const chunks = [];
  for (const label of labels) {
    const bytes = encoder.encode(label);
    if (bytes.length > 63) throw new Error(`Label too long: ${label}`);
    chunks.push(Uint8Array.of(bytes.length), bytes);
  }
  chunks.push(Uint8Array.of(0));
  const total = chunks.reduce((length, chunk) => length + chunk.length, 0);
  const wire = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    wire.set(chunk, offset);
    offset += chunk.length;
  }
  return wire;
}

/* ------------------------------------------------------------------ */
/* IP addresses                                                        */
/* ------------------------------------------------------------------ */

export function isValidIPv4(value) {
  const text = String(value ?? '').trim();
  const parts = text.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

export function canonicalIPv4(value) {
  if (!isValidIPv4(value)) return null;
  return String(value).trim().split('.').map((part) => String(Number(part))).join('.');
}

export function parseIPv6(value) {
  let text = String(value ?? '').trim().toLowerCase();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  if (!text || !text.includes(':')) return null;
  let ipv4Tail = null;
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    const tail = text.slice(lastColon + 1);
    if (!isValidIPv4(tail)) return null;
    const octets = tail.split('.').map(Number);
    ipv4Tail = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    text = `${text.slice(0, lastColon + 1)}0:0`;
  }
  if ((text.match(/::/g) || []).length > 1) return null;
  const [headText, tailText] = text.split('::');
  const head = headText ? headText.split(':') : [];
  const tail = tailText !== undefined && tailText !== '' ? tailText.split(':') : [];
  const all = [...head, ...tail];
  if (all.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  const missing = 8 - all.length;
  if (text.includes('::')) {
    if (missing < 0) return null;
    const groups = [...head, ...Array(missing).fill('0'), ...tail].map((group) => Number.parseInt(group || '0', 16));
    if (ipv4Tail) {
      groups[6] = ipv4Tail[0];
      groups[7] = ipv4Tail[1];
    }
    return groups.length === 8 ? groups : null;
  }
  if (all.length !== 8) return null;
  const groups = all.map((group) => Number.parseInt(group, 16));
  if (ipv4Tail) {
    groups[6] = ipv4Tail[0];
    groups[7] = ipv4Tail[1];
  }
  return groups;
}

export function isValidIPv6(value) {
  return parseIPv6(value) !== null;
}

export function formatIPv6(groups) {
  const hex = groups.map((group) => group.toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < hex.length; index += 1) {
    if (hex[index] !== '0') continue;
    let end = index;
    while (end < hex.length && hex[end] === '0') end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end - 1;
  }
  if (bestLength > 1) {
    const before = hex.slice(0, bestStart).join(':');
    const after = hex.slice(bestStart + bestLength).join(':');
    return `${before}::${after}`;
  }
  return hex.join(':');
}

export function canonicalIPv6(value) {
  const groups = parseIPv6(value);
  return groups ? formatIPv6(groups) : null;
}

export function canonicalIp(value) {
  return canonicalIPv4(value) ?? canonicalIPv6(value) ?? String(value ?? '').trim();
}

export function reverseIpName(value) {
  const ipv4 = canonicalIPv4(value);
  if (ipv4) return ensureTrailingDot(`${ipv4.split('.').reverse().join('.')}.in-addr.arpa`);
  const groups = parseIPv6(value);
  if (!groups) return null;
  const full = groups.map((group) => group.toString(16).padStart(4, '0')).join('');
  return ensureTrailingDot(`${full.split('').reverse().join('.')}.ip6.arpa`);
}

export function isReverseName(name) {
  const normalized = ensureTrailingDot(String(name ?? '').toLowerCase());
  return normalized.endsWith('.in-addr.arpa.') || normalized.endsWith('.ip6.arpa.');
}
