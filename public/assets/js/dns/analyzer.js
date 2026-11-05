/* Explainable BIND configuration and zone analyzer. */

import { base64ToBytes } from '../utils.js';
import {
  canonicalIPv4,
  canonicalIPv6,
  ensureTrailingDot,
  isReverseName,
  isSubdomain,
  normalizeName,
  parentName,
} from './names.js';
import { normalizeRdataForCompare, parseTTL } from './syntax.js';
import { algorithmInfo, digestInfo, keyFlagLabel } from './types.js';
import {
  dnskeyTag,
  matchDsToDnskeys,
  parseDnskeyRdata,
  parseDsRdata,
  parseRrsigRdata,
  rrsigHealth,
  zoneDnssecInventory,
  zoneUsesManagedSigning,
} from './dnssec.js';
import {
  globalAclValues,
  optionEnabled,
  optionEntry,
  optionValues,
  zoneAclValues,
  zoneOption,
} from './workspace.js';

const SEVERITY_ORDER = { error: 0, warning: 1, recommendation: 2, info: 3 };

function slug(value) {
  return String(value ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}


function expandAcl(values, model, seen = new Set()) {
  const output = [];
  for (const raw of values || []) {
    const value = String(raw ?? '').trim();
    if (!value) continue;
    const negated = value.startsWith('!');
    const clean = negated ? value.slice(1) : value;
    const acl = (model?.acls || []).find((item) => item.name === clean);
    if (acl && !seen.has(clean)) {
      const nested = expandAcl(acl.values, model, new Set([...seen, clean]));
      output.push(...(negated ? nested.map((item) => `!${item}`) : nested));
    } else {
      output.push(value);
    }
  }
  return output;
}

function containsAny(values) {
  return values.some((value) => String(value).toLowerCase() === 'any');
}

function containsNone(values) {
  return values.some((value) => String(value).toLowerCase() === 'none');
}

function valuesOf(entry) {
  if (!entry) return [];
  const list = [...(entry.args || [])];
  const walk = (items) => {
    for (const item of items || []) {
      if (item.keyword) list.push(item.keyword, ...(item.args || []));
      if (item.body?.length) walk(item.body);
    }
  };
  walk(entry.body);
  return list;
}

function boolValue(entry) {
  const value = String(entry?.args?.[0] ?? '').toLowerCase();
  if (['yes', 'true', 'on'].includes(value)) return true;
  if (['no', 'false', 'off'].includes(value)) return false;
  return null;
}

function recordsAt(zone, owner, type = null) {
  return (zone?.parsed?.records || []).filter((record) => record.owner === owner && (!type || record.type === type));
}

function allRecords(zone) {
  return zone?.parsed?.records || [];
}

function zoneFile(zone) {
  return zone?.filePath || zone?.file || null;
}

function findingId(...parts) {
  return parts.map((part) => slug(part)).filter(Boolean).join(':');
}

function reverseNameToIp(name) {
  const normalized = ensureTrailingDot(String(name || '').toLowerCase());
  if (normalized.endsWith('.in-addr.arpa.')) {
    const labels = normalized.slice(0, -'.in-addr.arpa.'.length).split('.').filter(Boolean).reverse();
    const candidate = labels.join('.');
    return canonicalIPv4(candidate);
  }
  if (normalized.endsWith('.ip6.arpa.')) {
    const nibbles = normalized.slice(0, -'.ip6.arpa.'.length).split('.').filter(Boolean).reverse();
    if (nibbles.length !== 32) return null;
    const groups = [];
    for (let index = 0; index < 32; index += 4) groups.push(nibbles.slice(index, index + 4).join(''));
    return canonicalIPv6(groups.join(':'));
  }
  return null;
}

function rsabits(publicKey) {
  try {
    const bytes = base64ToBytes(publicKey);
    if (!bytes.length) return null;
    let offset = 0;
    let exponentLength;
    if (bytes[0] === 0) {
      if (bytes.length < 3) return null;
      exponentLength = (bytes[1] << 8) | bytes[2];
      offset = 3;
    } else {
      exponentLength = bytes[0];
      offset = 1;
    }
    offset += exponentLength;
    if (offset >= bytes.length) return null;
    let modulus = bytes.subarray(offset);
    while (modulus.length && modulus[0] === 0) modulus = modulus.subarray(1);
    if (!modulus.length) return null;
    const first = modulus[0];
    let topBits = 0;
    let value = first;
    while (value) {
      topBits += 1;
      value >>= 1;
    }
    return (modulus.length - 1) * 8 + topBits;
  } catch {
    return null;
  }
}

export async function analyzeWorkspace(workspace, model) {
  const findings = [];
  const seen = new Set();
  const add = (severity, category, id, title, message, options = {}) => {
    const stable = id || findingId(title, options.file, options.line, options.zone);
    if (seen.has(stable)) return;
    seen.add(stable);
    findings.push({
      id: stable,
      severity,
      category,
      title,
      message,
      why: options.why || '',
      recommendation: options.recommendation || '',
      file: options.file || null,
      line: options.line || null,
      zone: options.zone || null,
      learn: options.learn || 'hardening',
      refs: options.refs || [],
      details: options.details || [],
      scope: options.scope || null,
    });
  };

  if (!model) {
    add('error', 'Structure', 'no-model', 'No BIND model could be built', 'The workspace is empty or unreadable.', {
      recommendation: 'Import named.conf or a zone file to begin.',
      learn: 'bind-architecture',
    });
    return finalize(findings);
  }

  const hasOptionsBlock = (model.named?.statements || []).some((statement) => statement.keyword === 'options');

  /* ---------------------------------------------------------------- */
  /* Parse and structure errors                                       */
  /* ---------------------------------------------------------------- */

  for (const error of model.parseErrors || []) {
    add('error', 'Syntax', findingId('parse', error.file, error.line, error.message), 'named.conf syntax error', error.message, {
      file: error.file,
      line: error.line,
      why: 'BIND must parse the complete configuration before it can start or reload. A syntax error stops the whole server from loading the new configuration.',
      recommendation: 'Fix the reported line, run named-checkconf, and inspect the surrounding block delimiters and semicolons.',
      learn: 'named-conf',
    });
  }

  for (const error of model.errors || []) {
    add('error', 'Structure', findingId('structure', error.file, error.line, error.message), 'Configuration reference problem', error.message, {
      file: error.file,
      line: error.line,
      why: 'An unresolved include or zone file means the configuration on disk is incomplete. BIND would fail to load the zone or the entire configuration.',
      recommendation: 'Import the missing file, correct the path, or place it where the include/directory directive expects it.',
      learn: 'bind-architecture',
    });
  }

  for (const warning of model.warnings || []) {
    add('warning', 'Structure', findingId('structure-warning', warning.file, warning.line, warning.message), 'Configuration note', warning.message, {
      file: warning.file,
      line: warning.line,
      recommendation: 'Review the include structure and confirm that every file is loaded exactly once in the intended context.',
      learn: 'named-conf',
    });
  }

  if (!model.hasNamed) {
    add('recommendation', 'Structure', 'no-named-conf', 'No named.conf was detected', 'The workspace contains zone data but no named.conf or include tree.', {
      why: 'A zone file alone does not tell BIND which zone name it serves, who may transfer it, or whether it is signed. named.conf supplies that context.',
      recommendation: 'Add the named.conf and included files that reference these zones so the analysis can check delegation, policy and DNSSEC.',
      learn: 'bind-architecture',
    });
  }

  if (!model.zones?.length) {
    add('warning', 'Structure', 'no-zones', 'No zones were found', 'No zone declarations or standalone zone files were detected in this workspace.', {
      recommendation: 'Add the zone statements and the files they reference.',
      learn: 'zone-files',
    });
  }

  if (!hasOptionsBlock) {
    add('warning', 'Structure', 'no-options-block', 'The options block is missing', 'No global options block was found in the parsed named.conf tree.', {
      why: 'The options block controls listening interfaces, recursion, transfers, DNSSEC validation, file paths and logging defaults. Relying on every default is rarely intentional.',
      recommendation: 'Add an options block and make the security-relevant defaults explicit.',
      learn: 'named-conf',
    });
  }

  const optionsDirectory = optionValues(model, 'directory')[0];
  if (!optionsDirectory) {
    add('recommendation', 'Operations', 'directory-missing', 'Set an explicit directory', 'The global directory option is not set.', {
      why: 'BIND resolves many relative file paths against its working directory. An implicit working directory makes includes, journals and zone files depend on how the service was started.',
      recommendation: 'Set directory to the configuration data directory (commonly /var/cache/bind or /etc/bind) and make every file path intentional.',
      learn: 'bind-architecture',
    });
  }

  if (!optionEntry(model, 'listen-on') && !optionEntry(model, 'listen-on-v6')) {
    add('warning', 'Network exposure', 'listen-on-missing', 'BIND is listening on default interfaces', 'Neither listen-on nor listen-on-v6 is configured.', {
      why: 'Without an explicit listen-on statement, BIND may listen on all available interfaces. On a multi-homed host this can expose a service on an unintended network.',
      recommendation: 'Declare the exact addresses and ports BIND should use, for example listen-on port 53 { 127.0.0.1; 192.0.2.53; };.',
      learn: 'hardening',
    });
  }

  const duplicateZones = new Map();
  for (const zone of model.zones || []) {
    const key = `${zone.view || '(default)'}|${zone.class}|${zone.name}`;
    if (!duplicateZones.has(key)) duplicateZones.set(key, []);
    duplicateZones.get(key).push(zone);
  }
  for (const [key, zones] of duplicateZones) {
    if (zones.length < 2) continue;
    add('error', 'Structure', findingId('duplicate-zone', key), 'Duplicate zone declaration', `${zones.length} zone statements declare ${zones[0].name} in the same view and class.`, {
      file: zones[1].file,
      line: zones[1].line,
      zone: zones[0].name,
      why: 'A zone name must be unique within a view and class. BIND rejects duplicate definitions and may refuse to load the configuration.',
      recommendation: 'Keep one authoritative declaration, or place the second copy in a different view with explicit match-clients.',
      learn: 'views-rpz',
    });
  }

  /* ---------------------------------------------------------------- */
  /* Global security options                                          */
  /* ---------------------------------------------------------------- */

  const recursionEntry = optionEntry(model, 'recursion');
  const recursion = recursionEntry ? boolValue(recursionEntry) : null;
  const allowRecursion = expandAcl(globalAclValues(model, 'allow-recursion'), model);
  const allowQueryCache = expandAcl(globalAclValues(model, 'allow-query-cache'), model);
  const allowQuery = expandAcl(globalAclValues(model, 'allow-query'), model);

  if (recursion === true) {
    if (!optionEntry(model, 'allow-recursion')) {
      add('warning', 'Recursion', 'recursion-missing-acl', 'Recursive service has no explicit allow-recursion policy', 'recursion is enabled but allow-recursion is not set.', {
        file: recursionEntry.file,
        line: recursionEntry.line,
        why: 'A recursive resolver that answers arbitrary clients is an open resolver. It can be abused for amplification, cache poisoning attempts and reflection attacks, and it may leak internal names.',
        recommendation: 'Restrict recursion explicitly, for example allow-recursion { localhost; localnets; }; and verify with an external query from outside your network.',
        learn: 'recursion-security',
      });
    } else if (containsAny(allowRecursion)) {
      add('error', 'Security', 'open-recursion', 'Open recursion is enabled', 'allow-recursion includes “any”, so any reachable client can use this server as a recursive resolver.', {
        file: recursionEntry.file,
        line: recursionEntry.line,
        why: 'Open resolvers are routinely abused for DNS amplification and reflection. They also expose the cache and can be used to probe internal names.',
        recommendation: 'Replace “any” with the smallest useful ACL: localhost, localnets, a management subnet, or a named ACL. If this server is authoritative-only, set recursion no.',
        learn: 'recursion-security',
      });
    }
    if (optionEntry(model, 'allow-query-cache') && containsAny(allowQueryCache)) {
      add('error', 'Security', 'open-cache', 'The DNS cache is open to every client', 'allow-query-cache includes “any”.', {
        file: optionEntry(model, 'allow-query-cache').file,
        line: optionEntry(model, 'allow-query-cache').line,
        why: 'The cache is a privileged data path. Allowing arbitrary clients to query it can reveal internal names and increases the impact of cache-related attacks.',
        recommendation: 'Restrict allow-query-cache to the same clients that are allowed recursion, or to none for a pure authoritative server.',
        learn: 'recursion-security',
      });
    } else if (!optionEntry(model, 'allow-query-cache')) {
      add('recommendation', 'Security', 'cache-acl-missing', 'Set an explicit cache ACL', 'recursion is enabled but allow-query-cache is not configured.', {
        recommendation: 'Set allow-query-cache to the same clients as allow-recursion, or to none for a pure authoritative server.',
        learn: 'recursion-security',
      });
    }
    if (!optionEntry(model, 'max-cache-size')) {
      add('recommendation', 'Performance', 'max-cache-size-missing', 'No cache size limit is set', 'recursion is enabled but max-cache-size is not configured.', {
        why: 'A resolver cache with no explicit limit can consume large amounts of memory under load or attack.',
        recommendation: 'Set max-cache-size to a measured value appropriate for the host, and monitor cache usage.',
        learn: 'operations',
      });
    }
    if (!optionEntry(model, 'max-recursion-queries') || !optionEntry(model, 'max-recursion-depth')) {
      add('recommendation', 'Security', 'recursion-limits-missing', 'Recursion work limits are not tuned', 'max-recursion-queries and/or max-recursion-depth are not set.', {
        why: 'Limits reduce the resource cost of hostile delegation chains and accidental loops.',
        recommendation: 'Set conservative limits and adjust after measuring legitimate traffic.',
        learn: 'recursion-security',
      });
    }
  } else if (recursion === null) {
    add('warning', 'Recursion', 'recursion-not-explicit', 'Recursion is not explicitly configured', 'No recursion statement was found in the global options.', {
      recommendation: 'Set recursion no on an authoritative-only server, or set recursion yes with explicit allow-recursion and cache limits on a resolver.',
      learn: 'recursion-security',
    });
  }

  if (recursion === true && optionEntry(model, 'allow-query') && containsAny(allowQuery)) {
    add('warning', 'Recursion', 'allow-query-any', 'allow-query is unrestricted', 'allow-query includes “any”.', {
      why: 'allowing every client to query authoritative data is sometimes intended for a public authoritative server. Combined with recursion, it can expose more surface than intended.',
      recommendation: 'Separate authoritative and recursive roles, or restrict allow-query and allow-recursion independently.',
      learn: 'recursion-security',
    });
  }

  const versionEntry = optionEntry(model, 'version');
  if (!versionEntry) {
    add('recommendation', 'Information disclosure', 'version-hidden', 'Hide the BIND version', 'The version option is not set.', {
      why: 'BIND answers version.bind by default. Exposing the exact version helps an attacker match known vulnerabilities to your server.',
      recommendation: 'Set version none; (or a harmless string) in options. This is defense in depth, not a substitute for patching.',
      learn: 'hardening',
    });
  } else if (!['none', 'not currently available', ''].includes(String(versionEntry.args?.[0] ?? '').toLowerCase())) {
    add('recommendation', 'Information disclosure', 'version-string', 'The version string is still useful to attackers', `version is set to “${versionEntry.args?.[0] || ''}”.`, {
      file: versionEntry.file,
      line: versionEntry.line,
      recommendation: 'Use version none; and keep the real version in your internal inventory.',
      learn: 'hardening',
    });
  }

  const validationEntry = optionEntry(model, 'dnssec-validation');
  const validation = String(validationEntry?.args?.[0] ?? '').toLowerCase();
  if (!validationEntry) {
    add('recommendation', 'DNSSEC', 'dnssec-validation-missing', 'Make DNSSEC validation explicit', 'dnssec-validation is not set.', {
      why: 'Modern BIND defaults to automatic validation, but an explicit setting documents intent and prevents a future default change from going unnoticed.',
      recommendation: 'Use dnssec-validation auto; on a validating resolver and keep the root trust anchor managed by BIND.',
      learn: 'dnssec-chain',
    });
  } else if (validation === 'no') {
    add(recursion === true ? 'error' : 'warning', 'DNSSEC', 'dnssec-validation-off', 'DNSSEC validation is disabled', 'dnssec-validation no is configured.', {
      file: validationEntry.file,
      line: validationEntry.line,
      why: 'A resolver that does not validate DNSSEC can return forged or corrupted data. On an authoritative-only server validation is not used for local zone data, but disabled validation is still a risky template to copy.',
      recommendation: 'Use dnssec-validation auto; unless you have a documented reason and compensating controls.',
      learn: 'dnssec-chain',
    });
  } else if (validation === 'yes') {
    add('recommendation', 'DNSSEC', 'dnssec-validation-manual', 'Manual validation requires managed trust anchors', 'dnssec-validation yes is set.', {
      file: validationEntry.file,
      line: validationEntry.line,
      why: 'With “yes”, the resolver relies on static trust anchors. If they are stale, validation fails or silently weakens.',
      recommendation: 'Prefer dnssec-validation auto; or automate trust-anchor updates and monitor anchor expiry.',
      learn: 'dnssec-chain',
    });
  }

  for (const obsolete of ['dnssec-enable', 'dnssec-lookaside', 'dnssec-secure-to-insecure']) {
    const entry = optionEntry(model, obsolete);
    if (entry) {
      add('warning', 'DNSSEC', findingId('obsolete', obsolete), `Obsolete directive: ${obsolete}`, `${obsolete} is no longer the right way to express this policy.`, {
        file: entry.file,
        line: entry.line,
        why: 'Obsolete directives are removed or ignored in current BIND branches. Keeping them makes the configuration look intentional when it is not.',
        recommendation: 'Remove the directive and use dnssec-validation, dnssec-policy and trust-anchors instead. Verify against your BIND version.',
        learn: 'dnssec-operations',
      });
    }
  }

  if (optionEntry(model, 'trusted-keys')) {
    add('warning', 'DNSSEC', 'trusted-keys-legacy', 'trusted-keys is legacy', 'A trusted-keys block was found.', {
      file: optionEntry(model, 'trusted-keys').file,
      line: optionEntry(model, 'trusted-keys').line,
      recommendation: 'Migrate to trust-anchors with managed keys or a DNSSEC policy; trusted-keys is static and easy to leave stale.',
      learn: 'dnssec-operations',
    });
  }

  if (optionEntry(model, 'allow-new-zones') && boolValue(optionEntry(model, 'allow-new-zones')) === true) {
    add('warning', 'Security', 'allow-new-zones', 'allow-new-zones is enabled', 'New zones can be added at runtime through the controls channel.', {
      file: optionEntry(model, 'allow-new-zones').file,
      line: optionEntry(model, 'allow-new-zones').line,
      why: 'This is a powerful management path. It must be protected by a key and a restricted controls channel.',
      recommendation: 'Restrict controls to localhost or a management network, require TSIG, and monitor zone additions.',
      learn: 'hardening',
    });
  }

  const controls = model.controls || [];
  if (!controls.length) {
    add('recommendation', 'Operations', 'controls-missing', 'No controls channel is configured', 'The controls statement is absent.', {
      why: 'rndc needs a protected controls channel. Without explicit configuration it may use a default local channel and key file whose permissions are easy to overlook.',
      recommendation: 'Configure controls on localhost or a management network with an explicit key and restrictive allow list.',
      learn: 'operations',
    });
  } else {
    for (const control of controls) {
      const text = JSON.stringify(control.statement);
      if (text.includes('"any"') || /\bany\b/.test(text)) {
        add('warning', 'Security', findingId('controls-open', control.file, control.line), 'The controls channel may be too open', 'The controls block contains “any”.', {
          file: control.file,
          line: control.line,
          recommendation: 'Limit the controls channel to localhost or a management subnet and require TSIG keys.',
          learn: 'hardening',
        });
      }
    }
  }

  for (const channel of model.statisticsChannels || []) {
    const text = JSON.stringify(channel.statement);
    const hasAllow = /"allow"|allow\b/.test(text);
    if (!hasAllow || /\bany\b/.test(text)) {
      add('warning', 'Operations', findingId('statistics-open', channel.file, channel.line), 'Statistics channel may be exposed', 'The statistics-channels block has no obvious allow restriction.', {
        file: channel.file,
        line: channel.line,
        why: 'The statistics endpoint reveals zone names, query volumes and server internals. It should not be reachable by arbitrary clients.',
        recommendation: 'Bind statistics-channels to localhost or a management address and add allow { 127.0.0.1; };.',
        learn: 'operations',
      });
    }
  }

  /* ---------------------------------------------------------------- */
  /* Transfers, updates, logging, policy                              */
  /* ---------------------------------------------------------------- */

  const globalTransferEntry = optionEntry(model, 'allow-transfer');
  const globalTransfer = expandAcl(globalAclValues(model, 'allow-transfer'), model);
  if (globalTransferEntry && containsAny(globalTransfer)) {
    add('error', 'Transfers', 'transfer-any-global', 'Zone transfers are open to everyone', 'The global allow-transfer ACL includes “any”.', {
      file: globalTransferEntry.file,
      line: globalTransferEntry.line,
      why: 'An unrestricted AXFR/IXFR exposes the complete zone, including internal names and service discovery data. It can also be abused for amplification.',
      recommendation: 'Set allow-transfer { none; }; globally and allow only the secondary server addresses, protected by TSIG where possible.',
      learn: 'transfers-tsig',
    });
  }

  for (const zone of model.zones || []) {
    const zoneTransferEntry = zoneOption(zone, 'allow-transfer');
    const effectiveTransfer = zoneTransferEntry ? expandAcl(zoneAclValues(zone, 'allow-transfer'), model) : globalTransfer;
    if (containsAny(effectiveTransfer)) {
      add('error', 'Transfers', findingId('transfer-any', zone.view, zone.name), `Zone ${zone.name} can be transferred by anyone`, 'The effective allow-transfer policy includes “any”.', {
        file: zoneTransferEntry?.file || zone.file,
        line: zoneTransferEntry?.line || zone.line,
        zone: zone.name,
        recommendation: 'Restrict transfers to the exact secondary addresses, and use TSIG keys so source-address spoofing is not enough.',
        learn: 'transfers-tsig',
      });
    } else if (!zoneTransferEntry && !globalTransferEntry) {
      add('recommendation', 'Transfers', findingId('transfer-unset', zone.name), 'Set an explicit transfer policy', `Zone ${zone.name} has no explicit allow-transfer policy.`, {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        why: 'Leaving transfers implicit means the answer depends on the BIND version and defaults. An explicit policy is auditable.',
        recommendation: 'Set allow-transfer { none; }; for hidden primaries and an address/TSIG ACL for zones that need secondaries.',
        learn: 'transfers-tsig',
      });
    }

    const updateEntry = zoneOption(zone, 'allow-update');
    const updateValues = updateEntry ? expandAcl(zoneAclValues(zone, 'allow-update'), model) : [];
    if (updateEntry && containsAny(updateValues)) {
      add('error', 'Dynamic updates', findingId('allow-update-any', zone.name), `Zone ${zone.name} accepts unauthenticated updates`, 'allow-update includes “any”.', {
        file: updateEntry.file,
        line: updateEntry.line,
        zone: zone.name,
        why: 'Anyone who can reach the server could rewrite records, hijack names or poison the zone.',
        recommendation: 'Remove allow-update { any; }; use update-policy with TSIG keys and the narrowest possible name/type permissions.',
        learn: 'advanced-bind',
      });
    } else if (updateEntry && !containsNone(updateValues) && !zoneOption(zone, 'update-policy') && !updateEntry.args?.some((arg) => String(arg).toLowerCase().includes('key'))) {
      add('warning', 'Dynamic updates', findingId('allow-update-no-key', zone.name), `Zone ${zone.name} uses address-based updates`, 'allow-update is configured without an obvious TSIG key or update-policy.', {
        file: updateEntry.file,
        line: updateEntry.line,
        zone: zone.name,
        recommendation: 'Prefer update-policy with a named TSIG key. Address-based update ACLs are weaker and easy to misconfigure.',
        learn: 'advanced-bind',
      });
    }
    if (updateEntry && !zoneOption(zone, 'journal')) {
      add('recommendation', 'Dynamic updates', findingId('journal-missing', zone.name), `Zone ${zone.name} has no explicit journal`, 'Dynamic updates are enabled but no journal file is set.', {
        file: updateEntry.file,
        line: updateEntry.line,
        zone: zone.name,
        why: 'The journal stores incremental changes and is essential for IXFR and crash recovery. An implicit journal path can surprise operators.',
        recommendation: 'Set an explicit journal path beside the zone, or ensure the global directory is correct and monitored.',
        learn: 'advanced-bind',
      });
    }

    const type = String(zone.type || '').toLowerCase();
    const mastersEntry = zoneOption(zone, 'masters') || zoneOption(zone, 'primaries');
    if ((type === 'secondary' || type === 'slave') && !mastersEntry && !zoneOption(zone, 'in-view')) {
      add('error', 'Structure', findingId('secondary-no-primary', zone.name), `Secondary zone ${zone.name} has no primaries`, 'A secondary/slave zone needs at least one masters/primaries list.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Add masters/primaries with the primary server addresses, or correct the zone type.',
        learn: 'transfers-tsig',
      });
    }
    if ((type === 'primary' || type === 'master') && !zone.fileOption && !zoneOption(zone, 'in-view')) {
      add('error', 'Structure', findingId('primary-no-file', zone.name), `Primary zone ${zone.name} has no file`, 'A primary/master zone must point to a zone file.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Add a file directive and import the zone file into this workspace.',
        learn: 'zone-files',
      });
    }
    if (!zone.type && !zone.inView) {
      add('error', 'Structure', findingId('zone-no-type', zone.name), `Zone ${zone.name} has no type`, 'Every zone statement needs a type.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Add type primary; for a local authoritative zone, or type secondary; with masters for a replica.',
        learn: 'named-conf',
      });
    }
    if (type === 'forward' && !zoneOption(zone, 'forwarders')) {
      add('warning', 'Structure', findingId('forward-no-forwarders', zone.name), `Forward zone ${zone.name} has no forwarders`, 'A forward zone should specify forwarders and usually forward only.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Add forwarders and forward only/first as appropriate.',
        learn: 'recursion-security',
      });
    }
    if (zoneOption(zone, 'notify') && boolValue(zoneOption(zone, 'notify')) === false && zoneOption(zone, 'also-notify')) {
      add('warning', 'Operations', findingId('also-notify-disabled', zone.name), `also-notify is inert for ${zone.name}`, 'notify is disabled but also-notify is present.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Enable notify yes or remove also-notify so the intent is clear.',
        learn: 'transfers-tsig',
      });
    }
    if (zoneOption(zone, 'dnssec-policy') && !(model.policies || []).some((policy) => policy.name === zoneOption(zone, 'dnssec-policy').args?.[0])) {
      add('warning', 'DNSSEC', findingId('policy-missing', zone.name), `DNSSEC policy for ${zone.name} is not defined`, `The zone references policy “${zoneOption(zone, 'dnssec-policy').args?.[0] || ''}” but no matching dnssec-policy block was found.`, {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Define the policy or correct the policy name. named-checkconf rejects an unknown policy.',
        learn: 'dnssec-operations',
      });
    }
    if (zoneOption(zone, 'inline-signing') && boolValue(zoneOption(zone, 'inline-signing')) === true && !zoneOption(zone, 'dnssec-policy')) {
      add('warning', 'DNSSEC', findingId('inline-signing-no-policy', zone.name), `Inline signing has no DNSSEC policy for ${zone.name}`, 'inline-signing yes is set without a dnssec-policy.', {
        file: zone.file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Use dnssec-policy so key lifetimes, algorithms and rollover are managed by BIND.',
        learn: 'dnssec-operations',
      });
    }
  }

  if (!(model.channels || []).length) {
    add('recommendation', 'Operations', 'logging-missing', 'No logging channels are configured', 'No logging block or channel was found.', {
      why: 'Without deliberate logging, important events (zone transfers, DNSSEC failures, update attempts) may only go to the service manager or be lost on restart.',
      recommendation: 'Define a channel and categories for default, security, queries (only when needed), xfer-out and dnssec.',
      learn: 'operations',
    });
  }
  for (const channel of model.channels || []) {
    const fileEntry = channel.options.get('file')?.[0];
    const fileArgs = (fileEntry?.args || []).map((arg) => String(arg).toLowerCase());
    const size = channel.options.get('size') || (fileArgs.includes('size') ? channel.options.get('file') : null);
    const versions = channel.options.get('versions') || (fileArgs.includes('versions') ? channel.options.get('file') : null);
    if (fileEntry && (!size || !versions)) {
      add('recommendation', 'Operations', findingId('channel-unbounded', channel.name), `Log channel ${channel.name} may grow without bound`, 'A file channel has no explicit size/versions rotation policy.', {
        file: channel.file,
        line: channel.line,
        why: 'Unbounded log files can fill the filesystem and take BIND down. Rotation limits are part of availability.',
        recommendation: 'Set size and versions, or use a syslog channel managed by the host logging stack.',
        learn: 'operations',
      });
    }
    const severity = String(channel.options.get('severity')?.[0]?.args?.[0] || '').toLowerCase();
    if (severity === 'debug' || severity === 'dynamic') {
      add('warning', 'Operations', findingId('channel-debug', channel.name), `Log channel ${channel.name} may be very verbose`, `Severity is ${severity}.`, {
        file: channel.file,
        line: channel.line,
        recommendation: 'Use debug logging temporarily and scope it to the category you are investigating.',
        learn: 'operations',
      });
    }
  }
  if (optionEntry(model, 'querylog') && boolValue(optionEntry(model, 'querylog')) === true) {
    add('warning', 'Privacy', 'querylog-on', 'Query logging is enabled globally', 'querylog yes writes every query to the log.', {
      file: optionEntry(model, 'querylog').file,
      line: optionEntry(model, 'querylog').line,
      why: 'Query logs contain sensitive names and can grow quickly. They are a diagnostic tool, not a permanent default.',
      recommendation: 'Enable query logging only while investigating, and protect/rotate the resulting logs.',
      learn: 'operations',
    });
  }

  if (!optionEntry(model, 'minimal-responses') || boolValue(optionEntry(model, 'minimal-responses')) === false) {
    add('recommendation', 'Security', 'minimal-responses', 'Consider minimal-responses yes', 'minimal-responses is not enabled.', {
      why: 'Minimal responses omit unnecessary authority and additional records. This reduces response size and makes some cache-poisoning techniques harder.',
      recommendation: 'Set minimal-responses yes; unless a legacy client or a specific delegation requirement needs the extra data.',
      learn: 'hardening',
    });
  }
  if ((model.zones || []).some((zone) => ['primary', 'master', 'secondary', 'slave'].includes(String(zone.type || '').toLowerCase())) && !optionEntry(model, 'rate-limit')) {
    add('recommendation', 'Security', 'rate-limit', 'Consider response rate limiting', 'No rate-limit policy is configured for authoritative service.', {
      why: 'Response Rate Limiting (RRL) reduces the amplification value of a public authoritative server during a flood or reflection attack.',
      recommendation: 'Measure normal traffic first, then add rate-limit settings for responses-per-second, errors-per-second and slip.',
      learn: 'hardening',
    });
  }
  if (recursion === true && !(model.responsePolicies || []).length) {
    add('recommendation', 'Security', 'rpz', 'Consider a Response Policy Zone', 'No response-policy is configured.', {
      why: 'RPZ is a local, DNS-native policy layer for blocking or rewriting known-bad names before clients receive them. It is optional, but a strong control for recursive resolvers.',
      recommendation: 'If this is a recursive resolver, evaluate a maintained RPZ feed and test it in observe-only mode first.',
      learn: 'views-rpz',
    });
  }

  for (const policy of model.policies || []) {
    const used = (model.zones || []).some((zone) => zoneOption(zone, 'dnssec-policy')?.args?.[0] === policy.name);
    if (!used) {
      add('info', 'DNSSEC', findingId('policy-unused', policy.name), `DNSSEC policy ${policy.name} is unused`, 'The policy is defined but no zone references it.', {
        file: policy.file,
        line: policy.line,
        recommendation: 'Remove it if it is stale, or attach it to the intended zones.',
        learn: 'dnssec-operations',
      });
    }
  }
  for (const responsePolicy of model.responsePolicies || []) {
    for (const zoneStatement of (responsePolicy.statement.body || []).filter((statement) => statement.keyword === 'zone')) {
      const rpzName = normalizeName(zoneStatement.args?.[0] || '');
      if (!rpzName || rpzName === '.') continue;
      if (!(model.zones || []).some((zone) => zone.name === rpzName)) {
        add('warning', 'Security', findingId('rpz-zone-missing', rpzName), `RPZ zone ${rpzName} is not loaded`, 'response-policy references an RPZ zone that is not declared in this workspace.', {
          file: responsePolicy.file,
          line: responsePolicy.line,
          recommendation: 'Import or declare the RPZ zone, or remove the stale response-policy entry. A missing RPZ can fail open or fail closed depending on configuration.',
          learn: 'views-rpz',
        });
      }
    }
  }
  const managedSigning = (model.zones || []).some((zone) => zoneOption(zone, 'dnssec-policy') || boolValue(zoneOption(zone, 'inline-signing')) === true);
  if (managedSigning && !optionEntry(model, 'key-directory')) {
    add('recommendation', 'DNSSEC', 'key-directory-missing', 'Set an explicit key directory', 'A zone uses DNSSEC policy/inline signing but no global key-directory is configured.', {
      why: 'BIND writes private keys and signing state to this directory. The default may be the working directory, which is easy to lose or expose.',
      recommendation: 'Set key-directory to a protected, persistent path writable only by the BIND user.',
      learn: 'dnssec-operations',
    });
  }

  if ((model.views || []).length) {
    for (const view of model.views) {
      const viewRecursion = view.recursion ? boolValue(view.recursion) : null;
      const viewAllow = expandAcl(view.allowRecursion ? valuesOf(view.allowRecursion) : [], model);
      if (viewRecursion === true && containsAny(viewAllow)) {
        add('error', 'Security', findingId('view-open-recursion', view.name), `View ${view.name} has open recursion`, 'recursion is enabled and allow-recursion includes “any” in this view.', {
          file: view.file,
          line: view.line,
          recommendation: 'Restrict recursion per view. A split-horizon view still needs an explicit client policy.',
          learn: 'views-rpz',
        });
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /* Zone data checks                                                 */
  /* ---------------------------------------------------------------- */

  const zonesByName = new Map((model.zones || []).map((zone) => [zone.name, zone]));
  const forwardAddresses = new Map();
  for (const zone of model.zones || []) {
    for (const record of allRecords(zone)) {
      if (record.type !== 'A' && record.type !== 'AAAA') continue;
      const address = record.type === 'A' ? canonicalIPv4(record.data?.address) : canonicalIPv6(record.data?.address);
      if (!address) continue;
      if (!forwardAddresses.has(record.owner)) forwardAddresses.set(record.owner, new Set());
      forwardAddresses.get(record.owner).add(address);
    }
  }

  for (const zone of model.zones || []) {
    const parsed = zone.parsed;
    if (!parsed) continue;
    const file = zoneFile(zone);
    const records = allRecords(zone);
    const apex = zone.name;
    const zoneType = String(zone.type || '').toLowerCase();
    const specialZone = ['forward', 'hint', 'stub', 'redirect'].includes(zoneType);

    for (const error of parsed.errors || []) {
      add('error', 'Zone syntax', findingId('zone-parse', zone.name, error.file, error.line, error.message), `Zone ${zone.name}: ${error.message}`, error.message, {
        file: error.file || file,
        line: error.line,
        zone: zone.name,
        recommendation: 'Fix the master-file syntax, then run named-checkzone on the exact file.',
        learn: 'zone-files',
      });
    }
    for (const warning of parsed.warnings || []) {
      add('warning', 'Zone data', findingId('zone-warning', zone.name, warning.file, warning.line, warning.message), `Zone ${zone.name}: ${warning.message}`, warning.message, {
        file: warning.file || file,
        line: warning.line,
        zone: zone.name,
        recommendation: 'Review the record and make the intended value explicit.',
        learn: 'zone-files',
      });
    }

    const soa = records.filter((record) => record.type === 'SOA');
    const apexSoa = soa.filter((record) => record.owner === apex);
    if (!specialZone && !soa.length) {
      add('error', 'Zone data', findingId('zone-no-soa', zone.name), `Zone ${zone.name} has no SOA`, 'A zone must start with exactly one SOA record at its apex.', {
        file,
        line: zone.line,
        zone: zone.name,
        why: 'The SOA identifies the primary server, the responsible mailbox, the serial and the negative-caching timers. Without it BIND cannot load the zone as authoritative.',
        recommendation: 'Add one SOA at the apex and increment its serial on every publish.',
        learn: 'soa-ns-ttl',
      });
    } else if (!specialZone && apexSoa.length > 1) {
      add('error', 'Zone data', findingId('zone-soa-duplicate', zone.name), `Zone ${zone.name} has multiple SOA records`, `${apexSoa.length} SOA records are present at the apex.`, {
        file,
        line: apexSoa[1].line,
        zone: zone.name,
        recommendation: 'Keep exactly one SOA at the apex.',
        learn: 'soa-ns-ttl',
      });
    } else if (!specialZone && soa.length && !apexSoa.length) {
      add('error', 'Zone data', findingId('zone-soa-wrong-owner', zone.name), `Zone ${zone.name} has SOA at the wrong owner`, `The SOA owner is ${soa[0].owner}, not ${apex}.`, {
        file,
        line: soa[0].line,
        zone: zone.name,
        recommendation: 'Move the SOA to the zone apex.',
        learn: 'soa-ns-ttl',
      });
    }

    const apexNS = records.filter((record) => record.type === 'NS' && record.owner === apex);
    if (!specialZone && !apexNS.length) {
      add('error', 'Zone data', findingId('zone-no-ns', zone.name), `Zone ${zone.name} has no apex NS records`, 'Every authoritative zone needs at least one NS at its apex.', {
        file,
        line: zone.line,
        zone: zone.name,
        why: 'The apex NS RRset defines the zone’s authoritative name servers. Without it the zone is not a usable delegation.',
        recommendation: 'Add at least two apex NS records pointing at resolvable name servers, and make sure the parent delegation matches.',
        learn: 'soa-ns-ttl',
      });
    } else if (!specialZone && apexNS.length === 1) {
      add('recommendation', 'Resilience', findingId('zone-one-ns', zone.name), `Zone ${zone.name} has only one apex NS`, 'A single name server is a single point of failure.', {
        file,
        line: apexNS[0].line,
        zone: zone.name,
        recommendation: 'Publish at least two apex NS records on independent infrastructure where practical.',
        learn: 'soa-ns-ttl',
      });
    }

    if (apexSoa.length === 1) {
      const data = apexSoa[0].data || {};
      if (!data.serial) {
        add('warning', 'Zone data', findingId('zone-serial-zero', zone.name), `Zone ${zone.name} has serial 0`, 'SOA serial is 0.', {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Use a monotonic serial (often YYYYMMDDnn) and increment it for every publish.',
          learn: 'soa-ns-ttl',
        });
      }
      const { refresh, retry, expire, minimum, mname, rname } = data;
      if (refresh !== null && refresh < 1200) {
        add('warning', 'Zone data', findingId('soa-refresh-low', zone.name), `Zone ${zone.name} refreshes very often`, `SOA refresh is ${refresh} seconds.`, {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Typical refresh values are 1h–12h. Very low values increase primary load and transfer churn.',
          learn: 'soa-ns-ttl',
        });
      }
      if (retry !== null && refresh !== null && retry > refresh) {
        add('warning', 'Zone data', findingId('soa-retry', zone.name), `Zone ${zone.name} retry is longer than refresh`, `retry=${retry}s, refresh=${refresh}s.`, {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Retry should normally be shorter than refresh so a secondary retries before the next refresh cycle.',
          learn: 'soa-ns-ttl',
        });
      }
      if (expire !== null && expire < 604800) {
        add('warning', 'Zone data', findingId('soa-expire', zone.name), `Zone ${zone.name} expires quickly`, `SOA expire is ${expire} seconds (less than 7 days).`, {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'A short expire can make a secondary stop answering during a primary outage. Typical values are 1–4 weeks.',
          learn: 'soa-ns-ttl',
        });
      }
      if (minimum !== null && minimum > 86400) {
        add('recommendation', 'Zone data', findingId('soa-minimum', zone.name), `Zone ${zone.name} has a large negative-caching TTL`, `SOA minimum is ${minimum} seconds.`, {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Negative answers can be cached for this long. 300–3600 seconds is common; choose deliberately.',
          learn: 'soa-ns-ttl',
        });
      }
      if (String(rname || '').includes('@')) {
        add('warning', 'Zone data', findingId('soa-rname-at', zone.name), `Zone ${zone.name} SOA RNAME contains “@”`, 'The RNAME field is a DNS name, not an email address.', {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Use hostmaster.example.com. (with a trailing dot) instead of hostmaster@example.com.',
          learn: 'soa-ns-ttl',
        });
      }
      if (mname && !apexNS.some((record) => record.data?.target === mname)) {
        add('recommendation', 'Zone data', findingId('soa-mname', zone.name), `Zone ${zone.name} SOA MNAME is not an apex NS`, `MNAME is ${mname}.`, {
          file: apexSoa[0].file,
          line: apexSoa[0].line,
          zone: zone.name,
          recommendation: 'Point MNAME at an authoritative primary name server that also appears in the apex NS RRset.',
          learn: 'soa-ns-ttl',
        });
      }
    }

    if (!records.length) {
      add('warning', 'Zone data', findingId('zone-empty', zone.name), `Zone ${zone.name} is empty`, 'The zone file contains no records.', {
        file,
        line: zone.line,
        zone: zone.name,
        recommendation: 'Add the SOA, NS and intended records, or remove the zone declaration.',
        learn: 'zone-files',
      });
    }

    const ttlMissing = records.filter((record) => record.ttl === null || record.ttl === undefined);
    if (ttlMissing.length) {
      add('warning', 'Zone data', findingId('zone-ttl-missing', zone.name), `Zone ${zone.name} has records without a TTL`, `${ttlMissing.length} record(s) have no explicit TTL and no $TTL default.`, {
        file: ttlMissing[0].file,
        line: ttlMissing[0].line,
        zone: zone.name,
        why: 'Without $TTL or a per-record TTL, BIND must fall back to legacy behavior and may warn. TTLs become hard to reason about.',
        recommendation: 'Add a $TTL directive near the top of the zone and override it only where needed.',
        learn: 'soa-ns-ttl',
      });
    }
    const explicitTtls = records.map((record) => record.ttl).filter((ttl) => Number.isFinite(ttl));
    if (explicitTtls.length) {
      const min = Math.min(...explicitTtls);
      const max = Math.max(...explicitTtls);
      if (max > 604800) {
        add('recommendation', 'Zone data', findingId('zone-ttl-large', zone.name), `Zone ${zone.name} has a TTL longer than 7 days`, `The largest TTL is ${max} seconds.`, {
          file: records.find((record) => record.ttl === max)?.file,
          line: records.find((record) => record.ttl === max)?.line,
          zone: zone.name,
          recommendation: 'Long TTLs slow down corrections. Use them only for very stable data and plan key/DNS changes accordingly.',
          learn: 'soa-ns-ttl',
        });
      }
      if (min === 0) {
        add('warning', 'Zone data', findingId('zone-ttl-zero', zone.name), `Zone ${zone.name} has a zero TTL`, 'TTL 0 disables caching for that RRset.', {
          file: records.find((record) => record.ttl === 0)?.file,
          line: records.find((record) => record.ttl === 0)?.line,
          zone: zone.name,
          recommendation: 'Use TTL 0 only for rapidly changing records such as dynamic load balancers.',
          learn: 'soa-ns-ttl',
        });
      }
      if (min > 0 && max / min > 10) {
        add('info', 'Zone data', findingId('zone-ttl-variance', zone.name), `Zone ${zone.name} mixes very different TTLs`, `TTLs range from ${min} to ${max} seconds.`, {
          file,
          line: zone.line,
          zone: zone.name,
          recommendation: 'Large TTL differences are valid, but document the reason. It complicates change and rollback timing.',
          learn: 'soa-ns-ttl',
        });
      }
    }

    const ownerTypes = new Map();
    for (const record of records) {
      if (!ownerTypes.has(record.owner)) ownerTypes.set(record.owner, new Set());
      ownerTypes.get(record.owner).add(record.type);
      if (!record.inZone) {
        add('error', 'Zone data', findingId('out-of-zone', zone.name, record.owner, record.line), `Out-of-zone record in ${zone.name}`, `${record.owner} ${record.type} is outside the zone origin.`, {
          file: record.file,
          line: record.line,
          zone: zone.name,
          why: 'BIND ignores master-file data outside the zone origin, so the record silently does not exist.',
          recommendation: 'Move the record to the correct zone or correct the owner name/trailing dot.',
          learn: 'zone-files',
        });
      }
      if (record.class !== 'IN') {
        add('warning', 'Zone data', findingId('class-non-in', zone.name, record.line), `Non-IN class in ${zone.name}`, `${record.owner} ${record.type} has class ${record.class}.`, {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Most BIND zones are class IN. Confirm that a non-IN class is intentional and supported by your tooling.',
          learn: 'zone-files',
        });
      }
    }

    const duplicateRecordKeys = new Map();
    for (const record of records) {
      if (record.type === 'RRSIG') continue;
      const key = `${record.owner}|${record.type}|${normalizeRdataForCompare(record.type, record.rdata)}`;
      if (!duplicateRecordKeys.has(key)) duplicateRecordKeys.set(key, []);
      duplicateRecordKeys.get(key).push(record);
    }
    for (const [key, list] of duplicateRecordKeys) {
      if (list.length < 2) continue;
      add('warning', 'Zone data', findingId('duplicate-record', zone.name, key), `Duplicate record in ${zone.name}`, `${list[0].owner} ${list[0].type} appears ${list.length} times with the same RDATA.`, {
        file: list[1].file,
        line: list[1].line,
        zone: zone.name,
        recommendation: 'Remove the duplicate or make the intended difference explicit. Duplicates are usually a merge or generation mistake.',
        learn: 'zone-files',
      });
    }

    for (const [owner, types] of ownerTypes) {
      const applicationTypes = new Set(Array.from(types).filter((type) => !['RRSIG', 'NSEC', 'SIG'].includes(type)));
      if (applicationTypes.has('CNAME') && applicationTypes.size > 1) {
        add('error', 'Zone data', findingId('cname-other-data', zone.name, owner), `CNAME coexists with other data at ${owner}`, `Types at this owner: ${Array.from(applicationTypes).join(', ')}.`, {
          file: records.find((record) => record.owner === owner)?.file,
          line: records.find((record) => record.owner === owner)?.line,
          zone: zone.name,
          why: 'A CNAME must be the only data at a name. BIND may load the zone but the data is inconsistent and resolution breaks unpredictably.',
          recommendation: 'Move the other records to the canonical target, or replace the CNAME with the intended record type.',
          learn: 'records',
        });
      }
      if (owner === apex && types.has('CNAME')) {
        add('error', 'Zone data', findingId('cname-apex', zone.name), `Zone ${zone.name} has a CNAME at its apex`, 'The zone apex cannot be a CNAME.', {
          file: records.find((record) => record.owner === owner && record.type === 'CNAME')?.file,
          line: records.find((record) => record.owner === owner && record.type === 'CNAME')?.line,
          zone: zone.name,
          why: 'The apex already owns SOA and NS records. A CNAME would conflict with mandatory zone data and break the delegation.',
          recommendation: 'Use A/AAAA records at the apex, or use a provider-specific ALIAS/ANAME feature outside DNS.',
          learn: 'records',
        });
      }
      if (types.has('DNAME') && types.has('CNAME')) {
        add('error', 'Zone data', findingId('dname-cname', zone.name, owner), `DNAME and CNAME coexist at ${owner}`, 'A DNAME redirects everything below the owner; a CNAME at the same owner conflicts.', {
          file: records.find((record) => record.owner === owner)?.file,
          line: records.find((record) => record.owner === owner)?.line,
          zone: zone.name,
          recommendation: 'Remove one of the two records and test the intended redirection.',
          learn: 'records',
        });
      }
    }

    const cnameRecords = records.filter((record) => record.type === 'CNAME');
    for (const record of cnameRecords) {
      const target = record.data?.target;
      if (!target) continue;
      if (target === record.owner) {
        add('error', 'Zone data', findingId('cname-self', zone.name, record.owner), `CNAME loop at ${record.owner}`, 'A CNAME points to itself.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Point the alias at a real target or remove it.',
          learn: 'records',
        });
        continue;
      }
      const targetRecords = recordsAt(zone, target);
      if (targetRecords.some((candidate) => candidate.type === 'CNAME')) {
        add('warning', 'Zone data', findingId('cname-chain', zone.name, record.owner), `CNAME chain at ${record.owner}`, `The target ${target} is itself a CNAME.`, {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Point directly at the final canonical name to reduce lookup latency and simplify operations.',
          learn: 'records',
        });
      } else if (isSubdomain(target, apex) && !targetRecords.some((candidate) => candidate.type === 'A' || candidate.type === 'AAAA')) {
        add('warning', 'Zone data', findingId('cname-target-missing', zone.name, record.owner), `CNAME target ${target} has no address in this zone`, 'The target is in-zone but has no A or AAAA record.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Add the target address, or point the alias at a name that exists.',
          learn: 'records',
        });
      }
    }

    const mxRecords = records.filter((record) => record.type === 'MX');
    for (const record of mxRecords) {
      const target = record.data?.exchange;
      if (!target) continue;
      if (recordsAt(zone, target, 'CNAME').length) {
        add('error', 'Zone data', findingId('mx-target-cname', zone.name, record.owner), `MX target ${target} is a CNAME`, 'Mail exchangers must not be aliases.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          why: 'RFC 2181 forbids an MX target from being a CNAME. Some mail systems fail or create mail loops.',
          recommendation: 'Point MX at a hostname with A/AAAA records. Use a separate alias name only for web traffic.',
          learn: 'records',
        });
      } else if (isSubdomain(target, apex) && !recordsAt(zone, target, 'A').length && !recordsAt(zone, target, 'AAAA').length) {
        add('warning', 'Zone data', findingId('mx-target-missing', zone.name, record.owner), `MX target ${target} has no address in this zone`, 'The mail exchanger target has no A/AAAA record in this zone.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Add the target address, or point MX at a name that resolves.',
          learn: 'records',
        });
      }
    }
    const nullMx = mxRecords.filter((record) => record.data?.preference === 0 && record.data?.exchange === '.');
    if (nullMx.length && mxRecords.length > nullMx.length) {
      add('warning', 'Zone data', findingId('null-mx-mixed', zone.name), `Zone ${zone.name} mixes a null MX with real MX records`, 'A null MX (“0 .”) must be the only MX for a domain.', {
        file: nullMx[0].file,
        line: nullMx[0].line,
        zone: zone.name,
        recommendation: 'Use a null MX only for domains that must not receive mail; remove it if the domain has real mail exchangers.',
        learn: 'records',
      });
    }

    for (const record of records.filter((candidate) => candidate.type === 'SRV')) {
      const target = record.data?.target;
      if (!target || target === '.') continue;
      if (recordsAt(zone, target, 'CNAME').length) {
        add('error', 'Zone data', findingId('srv-target-cname', zone.name, record.owner), `SRV target ${target} is a CNAME`, 'SRV targets must not be aliases.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Point SRV at a hostname with A/AAAA records.',
          learn: 'records',
        });
      } else if (isSubdomain(target, apex) && !recordsAt(zone, target, 'A').length && !recordsAt(zone, target, 'AAAA').length) {
        add('warning', 'Zone data', findingId('srv-target-missing', zone.name, record.owner), `SRV target ${target} has no address in this zone`, 'The service target has no A/AAAA record in this zone.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Add the target address or correct the target name.',
          learn: 'records',
        });
      }
    }

    for (const record of apexNS) {
      const target = record.data?.target;
      if (!target) continue;
      if (recordsAt(zone, target, 'CNAME').length) {
        add('error', 'Zone data', findingId('ns-target-cname', zone.name, target), `NS target ${target} is a CNAME`, 'Name server names must not be aliases.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          recommendation: 'Point NS at a hostname with A/AAAA glue or an out-of-zone address.',
          learn: 'soa-ns-ttl',
        });
      } else if (isSubdomain(target, apex) && !recordsAt(zone, target, 'A').length && !recordsAt(zone, target, 'AAAA').length) {
        add('error', 'Zone data', findingId('ns-target-missing', zone.name, target), `NS target ${target} has no address in this zone`, 'An in-zone name server needs glue A/AAAA records in this same zone.', {
          file: record.file,
          line: record.line,
          zone: zone.name,
          why: 'In-bailiwick name server names require glue in the parent/authoritative zone so resolvers can reach them without a circular dependency.',
          recommendation: 'Add A/AAAA glue for the name server, or move the NS target out of the zone.',
          learn: 'delegation',
        });
      }
    }

    // Delegations: child NS cuts, glue, DS and cross-zone consistency.
    const childCuts = new Map();
    for (const record of records) {
      if (record.type !== 'NS' || record.owner === apex) continue;
      if (!childCuts.has(record.owner)) childCuts.set(record.owner, []);
      childCuts.get(record.owner).push(record);
    }
    for (const [childName, childNS] of childCuts) {
      const childZone = zonesByName.get(childName);
      const dsRecords = recordsAt(zone, childName, 'DS');
      const cnameAtCut = recordsAt(zone, childName, 'CNAME');
      if (cnameAtCut.length) {
        add('error', 'Delegation', findingId('cname-at-cut', zone.name, childName), `CNAME at delegation point ${childName}`, 'A delegation point cannot also be a CNAME.', {
          file: cnameAtCut[0].file,
          line: cnameAtCut[0].line,
          zone: zone.name,
          recommendation: 'Remove the CNAME or move the delegation to a different name.',
          learn: 'delegation',
        });
      }
      for (const ns of childNS) {
        const target = ns.data?.target;
        if (!target) continue;
        if (isSubdomain(target, childName)) {
          const glue = recordsAt(zone, target).filter((record) => record.type === 'A' || record.type === 'AAAA');
          if (!glue.length) {
            add('error', 'Delegation', findingId('glue-missing', zone.name, childName, target), `Missing glue for ${target}`, `The delegation ${childName} uses in-bailiwick name server ${target} but the parent zone has no A/AAAA glue.`, {
              file: ns.file,
              line: ns.line,
              zone: zone.name,
              why: 'Resolvers cannot resolve the name server name through the child if the glue is missing from the parent.',
              recommendation: 'Add A/AAAA glue records for every in-bailiwick name server, and keep them synchronized with the child zone.',
              learn: 'delegation',
            });
          }
        } else if (isSubdomain(target, apex)) {
          const address = recordsAt(zone, target).filter((record) => record.type === 'A' || record.type === 'AAAA');
          if (!address.length) {
            add('warning', 'Delegation', findingId('ns-address-missing', zone.name, target), `Name server ${target} has no address in the parent zone`, 'The delegation target is inside this zone but has no A/AAAA record.', {
              file: ns.file,
              line: ns.line,
              zone: zone.name,
              recommendation: 'Add the address records or point the delegation at a reachable name server.',
              learn: 'delegation',
            });
          }
        }
        if (recordsAt(zone, target, 'CNAME').length) {
          add('error', 'Delegation', findingId('ns-cname', zone.name, target), `Delegation NS target ${target} is a CNAME`, 'NS targets must not be aliases.', {
            file: ns.file,
            line: ns.line,
            zone: zone.name,
            recommendation: 'Use an address record for the name server.',
            learn: 'delegation',
          });
        }
      }
      if (childZone?.parsed) {
        const childApexNS = childZone.parsed.records.filter((record) => record.owner === childName && record.type === 'NS');
        const parentNSSet = new Set(childNS.map((record) => record.data?.target));
        const childNSSet = new Set(childApexNS.map((record) => record.data?.target));
        if (parentNSSet.size && childNSSet.size && [...parentNSSet].sort().join('|') !== [...childNSSet].sort().join('|')) {
          add('warning', 'Delegation', findingId('ns-mismatch', zone.name, childName), `Parent and child NS sets differ for ${childName}`, 'The delegation NS RRset and the child apex NS RRset are not identical.', {
            file: childNS[0]?.file || zone.file,
            line: childNS[0]?.line || zone.line,
            zone: childName,
            recommendation: 'Keep the parent delegation and child apex NS sets in sync. Grep both files in the same change.',
            learn: 'delegation',
          });
        }
        const childKeys = childZone.parsed.records.filter((record) => record.owner === childName && record.type === 'DNSKEY');
        if (dsRecords.length && childKeys.length) {
          const match = await matchDsToDnskeys(childName, dsRecords, childKeys);
          if (match.status === 'match') {
            add('info', 'DNSSEC', findingId('ds-match', childName), `DS matches the child DNSKEY for ${childName}`, 'The imported parent DS and child DNSKEY agree.', {
              zone: childName,
              recommendation: 'This is a positive check. Keep the DS and DNSKEY rollover plan synchronized.',
              learn: 'dnssec-chain',
            });
          } else {
            add('error', 'DNSSEC', findingId('ds-mismatch', childName), `DS does not match any child DNSKEY for ${childName}`, 'The imported parent DS and child DNSKEY do not match.', {
              file: dsRecords[0].file,
              line: dsRecords[0].line,
              zone: childName,
              why: 'A DS that does not match a DNSKEY makes the child zone bogus for validating resolvers. Every signed answer below the delegation fails.',
              recommendation: 'Regenerate the DS from the current KSK (dnssec-dsfromkey or your policy tooling) and publish it in the parent before the child keys change.',
              learn: 'dnssec-chain',
            });
          }
        } else if (dsRecords.length && !childKeys.length && childZone.parsed.records.length) {
          add('warning', 'DNSSEC', findingId('ds-without-key', childName), `Parent publishes DS but child ${childName} has no DNSKEY`, 'The delegation claims DNSSEC but the imported child zone is unsigned.', {
            file: dsRecords[0].file,
            line: dsRecords[0].line,
            zone: childName,
            recommendation: 'Sign the child and publish its DNSKEY, or remove the DS until it is ready. A DS without a matching key makes the zone bogus.',
            learn: 'dnssec-chain',
          });
        } else if (!dsRecords.length && childKeys.length) {
          add('warning', 'DNSSEC', findingId('child-signed-no-ds', childName), `Child ${childName} is signed but the parent has no DS`, 'An island of security was found.', {
            file: childKeys[0].file,
            line: childKeys[0].line,
            zone: childName,
            why: 'Without a DS in the parent, validators treat the child as insecure. Signatures exist but do not build a chain of trust.',
            recommendation: 'Publish the DS at the parent delegation, then verify the chain from the root.',
            learn: 'dnssec-chain',
          });
        }
      }
    }

    // DNSSEC data quality.
    const inventory = zoneDnssecInventory(parsed);
    const managed = zoneUsesManagedSigning(zone);
    if (inventory.rrsigs.length && !inventory.keys.length) {
      add('error', 'DNSSEC', findingId('sig-without-key', zone.name), `Zone ${zone.name} has RRSIG but no DNSKEY`, 'Signatures cannot be validated without a DNSKEY at the apex.', {
        file: inventory.rrsigs[0].file,
        line: inventory.rrsigs[0].line,
        zone: zone.name,
        recommendation: 'Add the matching DNSKEY records, or re-sign the zone with the intended policy.',
        learn: 'dnssec-chain',
      });
    }
    if (inventory.keys.length && !inventory.rrsigs.length && !managed) {
      add('warning', 'DNSSEC', findingId('key-without-sig', zone.name), `Zone ${zone.name} publishes DNSKEY but is not signed`, 'No RRSIG records were found in the zone file.', {
        file: inventory.keys[0].file,
        line: inventory.keys[0].line,
        zone: zone.name,
        recommendation: 'Sign the zone and publish signatures, or remove the unused keys. If BIND manages signing inline, the file may intentionally be unsigned.',
        learn: 'dnssec-operations',
      });
    }
    for (const keyRecord of inventory.keys) {
      const key = parseDnskeyRdata(keyRecord.data);
      if (!key) continue;
      if (key.protocol !== 3) {
        add('error', 'DNSSEC', findingId('dnskey-protocol', zone.name, keyRecord.line), `Invalid DNSKEY protocol in ${zone.name}`, `Protocol is ${key.protocol}; DNSSEC requires 3.`, {
          file: keyRecord.file,
          line: keyRecord.line,
          zone: zone.name,
          recommendation: 'Regenerate the key with protocol 3.',
          learn: 'dnssec-chain',
        });
      }
      if (!(key.flags & 0x0100)) {
        add('warning', 'DNSSEC', findingId('dnskey-zone-flag', zone.name, keyRecord.line), `DNSKEY in ${zone.name} lacks the zone-key flag`, `Flags are ${key.flags}.`, {
          file: keyRecord.file,
          line: keyRecord.line,
          zone: zone.name,
          recommendation: 'A DNSKEY used to verify zone data must have the ZONE flag (256 for a ZSK, 257 for a KSK/SEP key).',
          learn: 'dnssec-chain',
        });
      }
      const alg = algorithmInfo(key.algorithm);
      if (['deprecated'].includes(alg.status)) {
        add('error', 'DNSSEC', findingId('dnskey-deprecated-alg', zone.name, key.algorithm), `Deprecated DNSSEC algorithm in ${zone.name}`, `${alg.name} (${key.algorithm}) is not safe to deploy.`, {
          file: keyRecord.file,
          line: keyRecord.line,
          zone: zone.name,
          recommendation: 'Move to ECDSAP256SHA256 (13), ED25519 (15) or RSASHA256 (8) with an appropriate key size.',
          learn: 'dnssec-operations',
        });
      } else if (alg.status === 'weak') {
        add('warning', 'DNSSEC', findingId('dnskey-weak-alg', zone.name, key.algorithm), `Legacy DNSSEC algorithm in ${zone.name}`, `${alg.name} is still accepted but is not a modern choice.`, {
          file: keyRecord.file,
          line: keyRecord.line,
          zone: zone.name,
          recommendation: 'Plan a key rollover to ECDSAP256SHA256 or Ed25519.',
          learn: 'dnssec-operations',
        });
      }
      if ([1, 5, 7, 8, 10].includes(key.algorithm)) {
        const bits = rsabits(key.publicKey);
        if (bits && bits < 2048) {
          add('warning', 'DNSSEC', findingId('rsa-key-small', zone.name, keyRecord.line), `RSA key in ${zone.name} is ${bits} bits`, 'RSA keys below 2048 bits are weak by current guidance.', {
            file: keyRecord.file,
            line: keyRecord.line,
            zone: zone.name,
            recommendation: 'Rotate to at least 2048-bit RSA, or preferably ECDSA P-256/Ed25519.',
            learn: 'dnssec-operations',
          });
        }
      }
      if (key.flags === 257) {
        add('info', 'DNSSEC', findingId('dnskey-ksk', zone.name, keyRecord.line), `KSK/SEP key in ${zone.name}`, `${keyTagLabelSafe(key)}.`, {
          file: keyRecord.file,
          line: keyRecord.line,
          zone: zone.name,
          learn: 'dnssec-chain',
        });
      }
    }

    for (const rrsigFinding of rrsigHealth(parsed)) {
      const record = rrsigFinding.record;
      add(rrsigFinding.severity, 'DNSSEC', findingId('rrsig', zone.name, record.line, rrsigFinding.message), `RRSIG issue in ${zone.name}`, rrsigFinding.message, {
        file: record.file,
        line: record.line,
        zone: zone.name,
        recommendation: 'Re-sign the zone or fix the key policy. Monitor signature expiry before it becomes an outage.',
        learn: 'dnssec-operations',
      });
    }

    const nsec3Iterations = inventory.nsec3param.map((record) => record.data?.iterations).filter((value) => Number.isFinite(value));
    if (nsec3Iterations.some((value) => value > 100)) {
      add('warning', 'DNSSEC', findingId('nsec3-iterations', zone.name), `High NSEC3 iteration count in ${zone.name}`, `NSEC3PARAM iterations: ${Math.max(...nsec3Iterations)}.`, {
        file: inventory.nsec3param[0].file,
        line: inventory.nsec3param[0].line,
        zone: zone.name,
        why: 'Extra NSEC3 iterations increase CPU cost for every negative answer and do not add meaningful security (RFC 9276).',
        recommendation: 'Use 0 iterations for new deployments and plan a carefully tested transition if you need to change it.',
        learn: 'dnssec-operations',
      });
    }
    if (inventory.nsec.length && inventory.nsec3.length) {
      add('warning', 'DNSSEC', findingId('mixed-denial', zone.name), `Zone ${zone.name} mixes NSEC and NSEC3`, 'Both denial-of-existence mechanisms are present.', {
        file: inventory.nsec[0].file,
        line: inventory.nsec[0].line,
        zone: zone.name,
        recommendation: 'Choose one denial mechanism via the DNSSEC policy and sign the zone consistently.',
        learn: 'dnssec-operations',
      });
    }
    const ownDs = records.filter((record) => record.owner === apex && record.type === 'DS');
    if (ownDs.length) {
      add('warning', 'DNSSEC', findingId('ds-at-apex', zone.name), `Zone ${zone.name} has a DS record at its own apex`, 'A DS for this zone normally belongs in the parent zone, not in the child.', {
        file: ownDs[0].file,
        line: ownDs[0].line,
        zone: zone.name,
        why: 'The DS RRset is authoritative in the parent. A DS at the child apex is usually a copy/paste error and can confuse operators and tooling.',
        recommendation: 'Publish the DS at the parent delegation. Use CDS/CDNSKEY if you are automating DS updates.',
        learn: 'dnssec-chain',
      });
    }
    for (const dsRecord of records.filter((record) => record.type === 'DS')) {
      const ds = parseDsRdata(dsRecord.data);
      if (!ds) continue;
      const digest = digestInfo(ds.digestType);
      const alg = algorithmInfo(ds.algorithm);
      if (digest.status === 'weak') {
        add('warning', 'DNSSEC', findingId('ds-sha1', zone.name, dsRecord.line), `Legacy DS digest in ${zone.name}`, `DS for ${dsRecord.owner} uses ${digest.name}.`, {
          file: dsRecord.file,
          line: dsRecord.line,
          zone: zone.name,
          recommendation: 'Publish SHA-256 DS records and complete a DS rollover.',
          learn: 'dnssec-chain',
        });
      }
      if (['deprecated', 'weak'].includes(alg.status)) {
        add(alg.status === 'deprecated' ? 'error' : 'warning', 'DNSSEC', findingId('ds-weak-alg', zone.name, dsRecord.line), `Weak DS algorithm in ${zone.name}`, `DS for ${dsRecord.owner} uses ${alg.name}.`, {
          file: dsRecord.file,
          line: dsRecord.line,
          zone: zone.name,
          recommendation: 'Roll the child key and parent DS to a modern algorithm.',
          learn: 'dnssec-operations',
        });
      }
    }

    if (!records.some((record) => record.type === 'CAA') && records.length && !isReverseName(apex)) {
      add('recommendation', 'Email & PKI', findingId('caa-missing', zone.name), `Zone ${zone.name} has no CAA policy`, 'No CAA records were found.', {
        file,
        line: zone.line,
        zone: zone.name,
        why: 'CAA lets a CA refuse to issue certificates for your domain unless an authorized CA is named. It reduces the impact of a mis-issued certificate.',
        recommendation: 'Add CAA at the apex for the CAs you actually use, plus an iodef contact if appropriate.',
        learn: 'hardening',
      });
    }
    if (records.some((record) => record.type === 'SPF')) {
      add('recommendation', 'Email & PKI', findingId('spf-rr', zone.name), `Zone ${zone.name} uses the obsolete SPF RR type`, 'SPF records should be published as TXT records.', {
        file: records.find((record) => record.type === 'SPF')?.file,
        line: records.find((record) => record.type === 'SPF')?.line,
        zone: zone.name,
        recommendation: 'Publish one SPF policy as a TXT record at the apex and remove the SPF RR.',
        learn: 'records',
      });
    }
  }

  /* ---------------------------------------------------------------- */
  /* Cross-zone PTR consistency                                       */
  /* ---------------------------------------------------------------- */

  for (const zone of model.zones || []) {
    for (const record of allRecords(zone)) {
      if (record.type !== 'PTR') continue;
      const reverseIp = reverseNameToIp(record.owner);
      const target = record.data?.target;
      if (!reverseIp || !target) continue;
      const addresses = forwardAddresses.get(target);
      if (!addresses) continue;
      if (!addresses.has(reverseIp)) {
        add('warning', 'Zone data', findingId('ptr-mismatch', zone.name, record.owner, target), `Forward/reverse mismatch for ${record.owner}`, `${record.owner} points to ${target}, but ${target} does not publish ${reverseIp}.`, {
          file: record.file,
          line: record.line,
          zone: zone.name,
          why: 'Forward and reverse DNS should agree. Mismatches break mail reputation, logging and some access controls.',
          recommendation: `Add ${reverseIp} to the forward zone for ${target}, or correct the PTR target.`,
          learn: 'delegation',
        });
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /* TSIG keys                                                        */
  /* ---------------------------------------------------------------- */

  for (const key of model.keys || []) {
    const algorithm = String(key.algorithm || '').toLowerCase();
    if (algorithm.includes('md5')) {
      add('error', 'Security', findingId('tsig-md5', key.name), `TSIG key ${key.name} uses MD5`, 'HMAC-MD5 is no longer acceptable for authentication.', {
        file: key.file,
        line: key.line,
        recommendation: 'Rotate to hmac-sha256, hmac-sha384 or hmac-sha512.',
        learn: 'transfers-tsig',
      });
    } else if (algorithm.includes('sha1')) {
      add('warning', 'Security', findingId('tsig-sha1', key.name), `TSIG key ${key.name} uses SHA-1`, 'HMAC-SHA1 is legacy.', {
        file: key.file,
        line: key.line,
        recommendation: 'Rotate to hmac-sha256 or stronger.',
        learn: 'transfers-tsig',
      });
    } else if (!algorithm) {
      add('warning', 'Structure', findingId('tsig-no-alg', key.name), `TSIG key ${key.name} has no algorithm`, 'The key block does not declare an algorithm.', {
        file: key.file,
        line: key.line,
        recommendation: 'Add algorithm hmac-sha256; and a secret from a secure random source.',
        learn: 'transfers-tsig',
      });
    }
    if (!key.secret) {
      add('error', 'Structure', findingId('tsig-no-secret', key.name), `TSIG key ${key.name} has no secret`, 'The key block does not contain a secret.', {
        file: key.file,
        line: key.line,
        recommendation: 'Add a secret generated with a cryptographically secure random source, and protect the file permissions.',
        learn: 'transfers-tsig',
      });
    } else {
      let length = null;
      try {
        length = Math.floor((key.secret.replace(/\s+/g, '').length * 3) / 4);
      } catch {
        length = null;
      }
      if (length !== null && length < 32) {
        add('warning', 'Security', findingId('tsig-short', key.name), `TSIG key ${key.name} is short`, `The decoded secret is about ${length} bytes.`, {
          file: key.file,
          line: key.line,
          recommendation: 'Use at least 32 bytes of entropy (a 256-bit key) for HMAC-SHA256.',
          learn: 'transfers-tsig',
        });
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /* Best-practice checklist                                          */
  /* ---------------------------------------------------------------- */

  const checklist = buildChecklist(model, findings, {
    recursion,
    globalTransferEntry,
    globalTransfer,
    validationEntry,
    validation,
  });

  return finalize(findings, checklist, { recursion, validation });
}

function keyTagLabelSafe(key) {
  const tag = dnskeyTag(key);
  return `${keyFlagLabel(key.flags)} · key tag ${tag ?? '?'} · ${algorithmInfo(key.algorithm).name}`;
}

function buildChecklist(model, findings, context) {
  const hasOptionsBlock = (model?.named?.statements || []).some((statement) => statement.keyword === 'options');
  const ids = new Set(findings.map((finding) => finding.id));
  const has = (prefix) => Array.from(ids).some((id) => id.startsWith(prefix));
  const meaningful = (prefix) => findings.some((finding) => finding.id.startsWith(prefix) && finding.severity !== 'info');
  const severityOf = (prefix) => {
    const matches = findings.filter((finding) => finding.id.startsWith(prefix));
    if (!matches.length) return null;
    return matches.reduce((worst, finding) => (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[worst] ? finding.severity : worst), 'info');
  };
  const item = (id, category, title, status, detail, learn, findingPrefix = null) => {
    let finalStatus = status;
    if (findingPrefix) {
      const severity = severityOf(findingPrefix);
      if (severity === 'error') finalStatus = 'fail';
      else if (severity === 'warning') finalStatus = 'review';
      else if (severity === 'recommendation' && finalStatus === 'pass') finalStatus = 'review';
    }
    return { id, category, title, status: finalStatus, detail, learn };
  };
  const zones = model.zones || [];
  const zonesWithParsed = zones.filter((zone) => zone.parsed);
  const dataZones = zonesWithParsed.filter((zone) => !['forward', 'hint', 'stub', 'redirect'].includes(String(zone.type || '').toLowerCase()));
  const recursionExplicit = Boolean(optionEntry(model, 'recursion'));
  const recursionSafe = recursionExplicit && (context.recursion !== true || (!meaningful('open-recursion') && !meaningful('open-cache') && !meaningful('recursion-missing-acl')));
  const dnssecValidation = context.validationEntry
    ? !['no', 'yes'].includes(context.validation)
    : false;
  const allZonesHaveSoa = dataZones.length > 0 && dataZones.every((zone) => zone.parsed.soa && zone.parsed.soa.owner === zone.name);
  const allZonesHaveNs = dataZones.length > 0 && dataZones.every((zone) => zone.parsed.apexNS?.length);
  const cnameRules = !meaningful('cname-') && !meaningful('dname-');
  const delegationClean = !meaningful('glue-missing') && !meaningful('ds-mismatch') && !meaningful('ds-without-key') && !meaningful('child-signed-no-ds');
  const dnssecClean = !meaningful('dnssec-') && !meaningful('dnskey-') && !meaningful('rrsig-') && !meaningful('ds-');
  const loggingSet = (model.channels || []).length > 0;
  const transfersSafe = !meaningful('transfer-any') && !meaningful('transfer-unset');
  const updatesSafe = !meaningful('allow-update') && !meaningful('journal-missing');
  const controlsSafe = !meaningful('controls-open') && !meaningful('statistics-open');
  const ttlClean = !meaningful('zone-ttl-') && !meaningful('soa-');
  const rateLimit = Boolean(optionEntry(model, 'rate-limit'));
  const rpz = (model.responsePolicies || []).length > 0;
  return [
    item('check-parse', 'Foundation', 'Configuration parses cleanly', has('parse:') || has('structure:') ? 'fail' : 'pass', 'No named.conf syntax or reference errors were found.', 'named-conf'),
    item('check-options', 'Foundation', 'Global options are explicit', hasOptionsBlock ? 'pass' : 'fail', 'An options block is the anchor for listening, recursion, files and DNSSEC policy.', 'named-conf'),
    item('check-directory', 'Foundation', 'File paths are rooted in an explicit directory', optionEntry(model, 'directory') ? 'pass' : 'review', 'Relative paths should not depend on how the service was started.', 'bind-architecture'),
    item('check-recursion', 'Access control', 'Recursion is restricted to intended clients', recursionSafe ? 'pass' : 'fail', 'Authoritative-only servers should use recursion no. Resolvers must restrict allow-recursion and the cache.', 'recursion-security'),
    item('check-transfers', 'Access control', 'Zone transfers are restricted', transfersSafe ? 'pass' : 'review', 'Use allow-transfer none or an explicit secondary/TSIG ACL.', 'transfers-tsig'),
    item('check-updates', 'Access control', 'Dynamic updates are authenticated', updatesSafe ? 'pass' : 'review', 'Updates should use update-policy with TSIG and a journal.', 'advanced-bind'),
    item('check-version', 'Information disclosure', 'Server version is hidden', has('version-hidden') || has('version-string') ? 'review' : 'pass', 'Set version none; to reduce casual fingerprinting.', 'hardening'),
    item('check-validation', 'DNSSEC', 'DNSSEC validation policy is explicit and safe', dnssecValidation ? 'pass' : 'review', 'Use dnssec-validation auto on resolvers and document the choice on authoritative-only servers.', 'dnssec-chain'),
    item('check-zones', 'Zone data', 'Every zone has SOA and apex NS', allZonesHaveSoa && allZonesHaveNs ? 'pass' : 'fail', 'A zone without SOA or NS is not a valid authoritative zone.', 'soa-ns-ttl'),
    item('check-cname', 'Zone data', 'CNAME and DNAME rules are respected', cnameRules ? 'pass' : 'fail', 'No apex CNAME, no CNAME plus other data, no MX/NS/SRV target pointing at an alias.', 'records'),
    item('check-delegation', 'Delegation', 'Delegations and glue are consistent', delegationClean ? 'pass' : 'review', 'Parent NS, child NS, DS, DNSKEY and glue should tell the same story.', 'delegation'),
    item('check-dnssec', 'DNSSEC', 'DNSSEC data is internally consistent', dnssecClean ? 'pass' : 'review', 'Keys, signatures, DS records, algorithms and expiry must agree.', 'dnssec-chain'),
    item('check-ttl', 'Zone data', 'TTL and SOA timers are deliberate', ttlClean ? 'pass' : 'review', 'A $TTL and sensible SOA timers make caching predictable.', 'soa-ns-ttl'),
    item('check-logging', 'Operations', 'Logging is configured and bounded', loggingSet ? 'pass' : 'review', 'Use explicit channels, categories and rotation.', 'operations'),
    item('check-controls', 'Operations', 'Management endpoints are protected', controlsSafe ? 'pass' : 'review', 'Restrict rndc controls and statistics to trusted networks.', 'hardening'),
    item('check-rate-limit', 'Security', 'Abuse resistance is considered', rateLimit ? 'pass' : 'review', 'Rate limiting and RPZ are optional but valuable on public resolvers.', 'hardening'),
    item('check-rpz', 'Security', 'Response policy is considered', rpz ? 'pass' : 'review', 'RPZ gives recursive resolvers a maintained local policy layer.', 'views-rpz'),
    item('check-ns-count', 'Resilience', 'Name service has redundancy', has('zone-one-ns') ? 'review' : 'pass', 'At least two independent name servers avoid a single point of failure.', 'soa-ns-ttl'),
    item('check-logs', 'Operations', 'Change and validation workflow is repeatable', zones.length ? 'pass' : 'review', 'Use Compare, named-checkconf/named-checkzone, staged reload and live verification for every change.', 'change-workflow'),
  ];
}

function finalize(findings, checklist = [], context = {}) {
  const sorted = findings.slice().sort((left, right) => {
    const severity = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severity !== 0) return severity;
    const fileCompare = String(left.file || '').localeCompare(String(right.file || ''));
    if (fileCompare !== 0) return fileCompare;
    return (left.line || 0) - (right.line || 0);
  });
  const counts = { error: 0, warning: 0, recommendation: 0, info: 0 };
  for (const finding of sorted) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  const score = Math.max(0, Math.min(100, 100 - counts.error * 12 - counts.warning * 4 - counts.recommendation * 1));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const categories = new Map();
  for (const finding of sorted) {
    if (!categories.has(finding.category)) categories.set(finding.category, { total: 0, error: 0, warning: 0, recommendation: 0, info: 0 });
    const entry = categories.get(finding.category);
    entry.total += 1;
    entry[finding.severity] += 1;
  }
  return {
    findings: sorted,
    counts,
    total: sorted.length,
    score,
    grade,
    checklist,
    categories: Array.from(categories.entries()).map(([name, values]) => ({ name, ...values })),
    analyzedAt: new Date().toISOString(),
    context,
    summary: `${counts.error} error(s), ${counts.warning} warning(s), ${counts.recommendation} recommendation(s)`,
  };
}
