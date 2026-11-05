/* Line, structural and semantic diff helpers. */

import { flattenStatements, statementToText } from './named-parser.js';
import { normalizeRdataForCompare } from './syntax.js';
import { normalizeNewlines } from '../utils.js';

export function splitLines(text) {
  const normalized = normalizeNewlines(text);
  if (normalized === '') return [];
  const lines = normalized.split('\n');
  // A trailing newline is not an extra empty line for review purposes.
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

/**
 * Myers line diff. Returns operations in document order:
 * { type: 'same'|'add'|'del', aLine?, bLine?, text }
 */
export function lineDiff(aText, bText) {
  const a = splitLines(aText);
  const b = splitLines(bText);
  const n = a.length;
  const m = b.length;
  if (n === 0 && m === 0) return [];
  if (n === 0) return b.map((text, index) => ({ type: 'add', bLine: index, text }));
  if (m === 0) return a.map((text, index) => ({ type: 'del', aLine: index, text }));

  // Large zone files can make a minimal Myers diff quadratic and freeze the
  // tab. Keep a common prefix/suffix and treat the middle as a block change.
  let prefix = 0;
  while (prefix < n && prefix < m && a[prefix] === b[prefix]) prefix += 1;
  let endA = n;
  let endB = m;
  while (endA > prefix && endB > prefix && a[endA - 1] === b[endB - 1]) {
    endA -= 1;
    endB -= 1;
  }
  if ((endA - prefix) * (endB - prefix) > 4_000_000) {
    const operations = [];
    for (let index = 0; index < prefix; index += 1) operations.push({ type: 'same', aLine: index, bLine: index, text: a[index] });
    for (let index = prefix; index < endA; index += 1) operations.push({ type: 'del', aLine: index, text: a[index] });
    for (let index = prefix; index < endB; index += 1) operations.push({ type: 'add', bLine: index, text: b[index] });
    for (let index = 0; index < n - endA; index += 1) {
      operations.push({ type: 'same', aLine: endA + index, bLine: endB + index, text: a[endA + index] });
    }
    return operations;
  }

  const max = n + m;
  const v = new Map();
  v.set(1, 0);
  const trace = [];
  let found = null;

  for (let d = 0; d <= max && found === null; d += 1) {
    trace.push(new Map(v));
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && (v.get(k - 1) ?? -Infinity) < (v.get(k + 1) ?? -Infinity))) {
        x = v.get(k + 1) ?? 0;
      } else {
        x = (v.get(k - 1) ?? 0) + 1;
      }
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x += 1;
        y += 1;
      }
      v.set(k, x);
      if (x >= n && y >= m) {
        found = d;
        break;
      }
    }
  }

  const operations = [];
  let x = n;
  let y = m;
  const editDistance = found ?? max;
  for (let d = editDistance; d > 0; d -= 1) {
    const previous = trace[d] || new Map();
    const k = x - y;
    let previousK;
    if (k === -d || (k !== d && (previous.get(k - 1) ?? -Infinity) < (previous.get(k + 1) ?? -Infinity))) {
      previousK = k + 1;
    } else {
      previousK = k - 1;
    }
    const previousX = previous.get(previousK) ?? 0;
    const previousY = previousX - previousK;
    while (x > previousX && y > previousY) {
      operations.push({ type: 'same', aLine: x - 1, bLine: y - 1, text: a[x - 1] });
      x -= 1;
      y -= 1;
    }
    if (x === previousX) {
      if (y > 0) {
        operations.push({ type: 'add', bLine: y - 1, text: b[y - 1] });
        y -= 1;
      }
    } else if (x > 0) {
      operations.push({ type: 'del', aLine: x - 1, text: a[x - 1] });
      x -= 1;
    }
  }
  while (x > 0 || y > 0) {
    if (x > 0 && y > 0 && a[x - 1] === b[y - 1]) {
      operations.push({ type: 'same', aLine: x - 1, bLine: y - 1, text: a[x - 1] });
      x -= 1;
      y -= 1;
    } else if (x > 0) {
      operations.push({ type: 'del', aLine: x - 1, text: a[x - 1] });
      x -= 1;
    } else if (y > 0) {
      operations.push({ type: 'add', bLine: y - 1, text: b[y - 1] });
      y -= 1;
    }
  }

  return operations.reverse();
}

export function diffStats(operations) {
  const stats = { added: 0, deleted: 0, same: 0, changed: 0, hunks: 0, total: operations.length };
  let inChange = false;
  for (const operation of operations) {
    if (operation.type === 'add') {
      stats.added += 1;
      if (!inChange) stats.hunks += 1;
      inChange = true;
    } else if (operation.type === 'del') {
      stats.deleted += 1;
      if (!inChange) stats.hunks += 1;
      inChange = true;
    } else {
      stats.same += 1;
      inChange = false;
    }
  }
  stats.changed = Math.max(stats.added, stats.deleted);
  stats.identical = stats.added === 0 && stats.deleted === 0;
  return stats;
}

export function diffTextStats(aText, bText) {
  return diffStats(lineDiff(aText, bText));
}

export function semanticZoneDiff(zoneA, zoneB, options = {}) {
  // SOA is compared separately: its serial changes on every publish and would
  // otherwise appear as a removed plus an added record in every diff.
  const recordsA = (zoneA?.records || []).filter((record) => record.type !== 'RRSIG' && record.type !== 'SOA');
  const recordsB = (zoneB?.records || []).filter((record) => record.type !== 'RRSIG' && record.type !== 'SOA');
  const keyOf = (record) => `${record.owner}|${record.type}|${normalizeRdataForCompare(record.type, record.rdata)}`;
  const mapA = new Map();
  const mapB = new Map();
  for (const record of recordsA) {
    const key = keyOf(record);
    if (!mapA.has(key)) mapA.set(key, []);
    mapA.get(key).push(record);
  }
  for (const record of recordsB) {
    const key = keyOf(record);
    if (!mapB.has(key)) mapB.set(key, []);
    mapB.get(key).push(record);
  }
  const added = [];
  const removed = [];
  const ttlChanged = [];
  for (const [key, list] of mapA) {
    const other = mapB.get(key) || [];
    if (other.length < list.length) {
      for (let index = other.length; index < list.length; index += 1) removed.push(list[index]);
    }
    const firstA = list[0];
    const firstB = other[0];
    if (firstA && firstB && !options.ignoreTTL && firstA.ttl !== firstB.ttl) {
      ttlChanged.push({ record: firstA, before: firstA.ttl, after: firstB.ttl });
    }
  }
  for (const [key, list] of mapB) {
    const other = mapA.get(key) || [];
    if (other.length < list.length) {
      for (let index = other.length; index < list.length; index += 1) added.push(list[index]);
    }
  }
  const serialA = zoneA?.soa?.data?.serial ?? null;
  const serialB = zoneB?.soa?.data?.serial ?? null;
  const soaA = zoneA?.soa?.data || null;
  const soaB = zoneB?.soa?.data || null;
  const soaFields = ['mname', 'rname', 'refresh', 'retry', 'expire', 'minimum'];
  const soaChanges = soaA && soaB
    ? soaFields.filter((field) => String(soaA[field]) !== String(soaB[field])).map((field) => ({ field, before: soaA[field], after: soaB[field] }))
    : [];
  return {
    added,
    removed,
    ttlChanged,
    serialChange: serialA !== serialB ? { before: serialA, after: serialB } : null,
    soaChanges,
    originA: zoneA?.origin || null,
    originB: zoneB?.origin || null,
    identical: added.length === 0 && removed.length === 0 && ttlChanged.length === 0 && soaChanges.length === 0 && serialA === serialB,
    counts: {
      a: recordsA.length,
      b: recordsB.length,
      added: added.length,
      removed: removed.length,
      ttlChanged: ttlChanged.length,
    },
  };
}

function statementKey(statement, context) {
  const bodyText = (statement.body || [])
    .map((child) => statementToText(child))
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();
  return `${context.join('>')}|${statement.keyword}|${(statement.args || []).join(' ')}|${bodyText}`;
}

export function semanticNamedDiff(modelA, modelB) {
  const listA = flattenStatements(modelA?.named?.statements || []);
  const listB = flattenStatements(modelB?.named?.statements || []);
  const mapA = new Map();
  const mapB = new Map();
  for (const item of listA) {
    const key = statementKey(item.statement, item.context);
    if (!mapA.has(key)) mapA.set(key, []);
    mapA.get(key).push(item.statement);
  }
  for (const item of listB) {
    const key = statementKey(item.statement, item.context);
    if (!mapB.has(key)) mapB.set(key, []);
    mapB.get(key).push(item.statement);
  }
  const added = [];
  const removed = [];
  for (const [key, list] of mapA) {
    const other = mapB.get(key) || [];
    if (other.length < list.length) {
      for (let index = other.length; index < list.length; index += 1) removed.push(list[index]);
    }
  }
  for (const [key, list] of mapB) {
    const other = mapA.get(key) || [];
    if (other.length < list.length) {
      for (let index = other.length; index < list.length; index += 1) added.push(list[index]);
    }
  }
  return {
    added,
    removed,
    identical: added.length === 0 && removed.length === 0,
    counts: { a: listA.length, b: listB.length, added: added.length, removed: removed.length },
  };
}

export function changedFilePaths(workspaceA, workspaceB) {
  const mapA = new Map((workspaceA?.files || []).map((file) => [file.path, file.content]));
  const mapB = new Map((workspaceB?.files || []).map((file) => [file.path, file.content]));
  const paths = new Set([...mapA.keys(), ...mapB.keys()]);
  return Array.from(paths).filter((path) => mapA.get(path) !== mapB.get(path)).sort();
}

export function summarizeDiff(operations, context = 2) {
  const rows = [];
  for (let index = 0; index < operations.length; index += 1) {
    const operation = operations[index];
    if (operation.type === 'same') continue;
    rows.push(operation);
    for (let ahead = 1; ahead <= context && index + ahead < operations.length; ahead += 1) {
      const next = operations[index + ahead];
      if (next.type === 'same') rows.push(next);
      else break;
    }
  }
  return rows;
}
