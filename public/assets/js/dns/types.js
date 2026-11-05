/* DNS type, class, RCODE and DNSSEC algorithm registries used by the app. */

export const DNS_TYPES = [
  ['A', 1],
  ['NS', 2],
  ['MD', 3],
  ['MF', 4],
  ['CNAME', 5],
  ['SOA', 6],
  ['MB', 7],
  ['MG', 8],
  ['MR', 9],
  ['NULL', 10],
  ['WKS', 11],
  ['PTR', 12],
  ['HINFO', 13],
  ['MINFO', 14],
  ['MX', 15],
  ['TXT', 16],
  ['RP', 17],
  ['AFSDB', 18],
  ['X25', 19],
  ['ISDN', 20],
  ['RT', 21],
  ['NSAP', 22],
  ['NSAP-PTR', 23],
  ['SIG', 24],
  ['KEY', 25],
  ['PX', 26],
  ['GPOS', 27],
  ['AAAA', 28],
  ['LOC', 29],
  ['NXT', 30],
  ['EID', 31],
  ['NIMLOC', 32],
  ['SRV', 33],
  ['ATMA', 34],
  ['NAPTR', 35],
  ['KX', 36],
  ['CERT', 37],
  ['A6', 38],
  ['DNAME', 39],
  ['SINK', 40],
  ['OPT', 41],
  ['APL', 42],
  ['DS', 43],
  ['SSHFP', 44],
  ['IPSECKEY', 45],
  ['RRSIG', 46],
  ['NSEC', 47],
  ['DNSKEY', 48],
  ['DHCID', 49],
  ['NSEC3', 50],
  ['NSEC3PARAM', 51],
  ['TLSA', 52],
  ['SMIMEA', 53],
  ['HIP', 55],
  ['NINFO', 56],
  ['RKEY', 57],
  ['TALINK', 58],
  ['CDS', 59],
  ['CDNSKEY', 60],
  ['OPENPGPKEY', 61],
  ['CSYNC', 62],
  ['ZONEMD', 63],
  ['SVCB', 64],
  ['HTTPS', 65],
  ['SPF', 99],
  ['UINFO', 100],
  ['UID', 101],
  ['GID', 102],
  ['UNSPEC', 103],
  ['NID', 104],
  ['L32', 105],
  ['L64', 106],
  ['LP', 107],
  ['EUI48', 108],
  ['EUI64', 109],
  ['TKEY', 249],
  ['TSIG', 250],
  ['IXFR', 251],
  ['AXFR', 252],
  ['MAILB', 253],
  ['MAILA', 254],
  ['ANY', 255],
  ['URI', 256],
  ['CAA', 257],
  ['AVC', 258],
  ['DOA', 259],
  ['AMTRELAY', 260],
  ['RESINFO', 261],
  ['WALLET', 262],
  ['CLA', 263],
  ['IPN', 264],
];

export const TYPE_BY_NAME = new Map(DNS_TYPES);
export const TYPE_BY_CODE = new Map(DNS_TYPES.map(([name, code]) => [code, name]));

export const QUERY_TYPES = [
  'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR',
  'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'SSHFP',
  'SVCB', 'HTTPS', 'NAPTR', 'DNAME', 'URI', 'SPF', 'ANY',
];

export const DNS_CLASSES = ['IN', 'CH', 'HS', 'NONE', 'ANY'];

export const RCODES = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
  6: 'YXDOMAIN',
  7: 'YXRRSET',
  8: 'NXRRSET',
  9: 'NOTAUTH',
  10: 'NOTZONE',
  11: 'DSOTYPENI',
  16: 'BADVERS/BADSIG',
  17: 'BADKEY',
  18: 'BADTIME',
  19: 'BADMODE',
  20: 'BADNAME',
  21: 'BADALG',
  22: 'BADTRUNC',
  23: 'BADCOOKIE',
};

export const DNSSEC_ALGORITHMS = {
  1: { name: 'RSAMD5', status: 'deprecated', bits: '1024–4096', note: 'Obsolete and must not be used.' },
  3: { name: 'DSA', status: 'deprecated', bits: '512–1024', note: 'Obsolete; do not deploy.' },
  5: { name: 'RSASHA1', status: 'weak', bits: '1024–4096', note: 'Legacy; migrate to ECDSA or Ed25519.' },
  6: { name: 'DSA-NSEC3-SHA1', status: 'deprecated', bits: '512–1024', note: 'Obsolete; do not deploy.' },
  7: { name: 'RSASHA1-NSEC3-SHA1', status: 'weak', bits: '1024–4096', note: 'Legacy; migrate to ECDSA or Ed25519.' },
  8: { name: 'RSASHA256', status: 'good', bits: '2048–4096', note: 'Widely supported; use at least 2048-bit keys.' },
  10: { name: 'RSASHA512', status: 'good', bits: '2048–4096', note: 'Supported, but larger signatures than ECDSA.' },
  12: { name: 'ECC-GOST', status: 'limited', bits: '—', note: 'Limited deployment; not universally supported.' },
  13: { name: 'ECDSAP256SHA256', status: 'recommended', bits: '256', note: 'Excellent default: short keys and signatures.' },
  14: { name: 'ECDSAP384SHA384', status: 'recommended', bits: '384', note: 'Strong ECDSA option with wider support gaps than P-256.' },
  15: { name: 'ED25519', status: 'recommended', bits: '256', note: 'Compact and fast; check resolver and tooling support.' },
  16: { name: 'ED448', status: 'limited', bits: '456', note: 'Strong but limited support.' },
  17: { name: 'SM2SM3', status: 'limited', bits: '256', note: 'Regional algorithm; limited deployment.' },
};

export const DS_DIGESTS = {
  1: { name: 'SHA-1', status: 'weak', note: 'Legacy digest; migrate to SHA-256.' },
  2: { name: 'SHA-256', status: 'recommended', note: 'The normal choice for DS records.' },
  3: { name: 'GOST R 34.11-94', status: 'limited', note: 'Limited deployment.' },
  4: { name: 'SHA-384', status: 'good', note: 'Stronger digest; use when the policy requires it.' },
};

export const DNSSEC_KEY_FLAGS = {
  256: 'Zone Signing Key (ZSK)',
  257: 'Key Signing Key (KSK), SEP bit set',
};

export const RECORD_GROUPS = {
  address: ['A', 'AAAA'],
  alias: ['CNAME', 'DNAME'],
  mail: ['MX', 'SPF', 'DKIM', 'DMARC'],
  service: ['SRV', 'SVCB', 'HTTPS', 'NAPTR', 'URI'],
  security: ['CAA', 'TLSA', 'SMIMEA', 'SSHFP', 'IPSECKEY', 'OPENPGPKEY'],
  dnssec: ['DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY', 'ZONEMD'],
  infrastructure: ['SOA', 'NS', 'PTR', 'HINFO', 'RP', 'LOC'],
};

export function typeCode(type) {
  const name = String(type ?? '').toUpperCase();
  if (TYPE_BY_NAME.has(name)) return TYPE_BY_NAME.get(name);
  const generic = name.match(/^TYPE(\d+)$/);
  if (generic) return Number(generic[1]);
  return null;
}

export function typeName(code) {
  const number = Number(code);
  return TYPE_BY_CODE.get(number) || `TYPE${number}`;
}

export function normalizeType(type) {
  const name = String(type ?? '').toUpperCase();
  const code = typeCode(name);
  return code === null ? name : typeName(code);
}

export function rcodeName(code) {
  return RCODES[Number(code)] || `RCODE${code}`;
}

export function algorithmInfo(code) {
  return DNSSEC_ALGORITHMS[Number(code)] || {
    name: `ALG${code}`,
    status: 'unknown',
    bits: '—',
    note: 'Unknown or newer algorithm; check current IANA and resolver support.',
  };
}

export function digestInfo(code) {
  return DS_DIGESTS[Number(code)] || {
    name: `DIGEST${code}`,
    status: 'unknown',
    note: 'Unknown digest type; check the IANA DS digest registry.',
  };
}

export function keyFlagLabel(flags) {
  const value = Number(flags);
  if (value === 257) return 'KSK / SEP';
  if (value === 256) return 'ZSK';
  if (value & 1) return `flags ${value} (SEP)`;
  return `flags ${value}`;
}

export function isDnssecType(type) {
  return RECORD_GROUPS.dnssec.includes(String(type).toUpperCase());
}
