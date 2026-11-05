/* Live DNS: DoH lookup, propagation comparison, DNSSEC chain and zone verification. */

import {
  RESOLVER_LIST,
  buildDigCommands,
  compareDnsResults,
  explainDohLimits,
  queryDns,
  resolverById,
} from '../dns/doh.js';
import { chainDigCommands, walkDnssecChain } from '../dns/dnssec.js';
import { buildVerificationChecks, runVerification, summarizeVerification, verificationCaveats } from '../dns/verify.js';
import { parseWorkspace } from '../dns/workspace.js';
import { getCurrentWorkspace, getSettings, saveSettings } from '../storage.js';
import { articleById } from '../data/learn.js';
import { callout, codeBlock, icon, pill, toast, wireCopyButtons } from '../ui.js';
import { escapeHTML, formatDateTime, formatNumber } from '../utils.js';

export async function renderLive(view, query) {
  const workspace = getCurrentWorkspace();
  const model = workspace ? parseWorkspace(workspace) : null;
  const settings = getSettings();
  let consent = Boolean(settings.onlineConsent);
  let activeTab = ['lookup', 'dnssec', 'verify', 'how'].includes(query.get('tab')) ? query.get('tab') : 'lookup';
  let lookupResults = null;
  let lookupComparison = null;
  let chainResult = null;
  let verificationResults = null;
  let verificationSummary = null;
  let busy = false;
  let abortController = null;

  const initialName = query.get('name') || (model?.zones?.[0]?.name ? model.zones[0].name.replace(/\.$/, '') : 'example.com');
  const initialZone = query.get('zone') || model?.zones?.[0]?.name || '';

  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Live DNS · opt-in external checks</span><h1>What does the world see?</h1><p class="page-lede">Query Cloudflare (1.1.1.1) and Google (8.8.8.8) through DNS-over-HTTPS, compare propagation, recompute DS digests, walk the DNSSEC chain and verify your imported records against live answers.</p><div class="meta-strip">${pill('DoH JSON', 'accent', 'globe')}${pill('Cloudflare 1.1.1.1', 'neutral', 'wifi')}${pill('Google 8.8.8.8', 'neutral', 'wifi')}${pill('No config upload', 'ok', 'lock')}</div></div>
    <div class="page-actions"><a class="btn" href="#/workbench">${icon('code', 16)} Workbench</a><a class="btn" href="#/security">${icon('shield', 16)} Privacy model</a></div>
  </div>

  <div class="consent-banner ${consent ? 'enabled' : ''}" id="online-gate">
    <div class="consent-icon">${icon('globe', 22)}</div>
    <div class="consent-copy"><strong>${consent ? 'Online lookups are enabled' : 'Online lookups are off'}</strong><p>${consent ? 'Queries are sent only to the selected DoH resolver. Configuration files never leave this browser. You can disable this at any time.' : 'A browser cannot use dig or UDP/53. This page uses DNS-over-HTTPS JSON endpoints from Cloudflare or Google. Enabling sends the queried name and type to that resolver; it does not send your configuration files.'}</p></div>
    <div class="consent-actions">${consent ? `<button class="btn btn-sm btn-ghost" type="button" id="disable-online">Turn off</button>` : `<button class="btn btn-primary" type="button" id="enable-online">${icon('check', 15)} Enable online lookups</button>`}</div>
  </div>

  <div class="tabbar" role="tablist">
    <button class="tab" type="button" role="tab" data-live-tab="lookup" aria-selected="${activeTab === 'lookup'}">${icon('search', 15)} Lookup</button>
    <button class="tab" type="button" role="tab" data-live-tab="dnssec" aria-selected="${activeTab === 'dnssec'}">${icon('shield', 15)} DNSSEC chain</button>
    <button class="tab" type="button" role="tab" data-live-tab="verify" aria-selected="${activeTab === 'verify'}">${icon('check', 15)} Zone verification</button>
    <button class="tab" type="button" role="tab" data-live-tab="how" aria-selected="${activeTab === 'how'}">${icon('book', 15)} How it works</button>
  </div>

  <section class="live-panel" data-live-panel="lookup" ${activeTab === 'lookup' ? '' : 'hidden'}>
    <div class="query-card">
      <div class="query-grid">
        <label class="field span-2"><span>DNS name</span><input id="lookup-name" type="text" value="${escapeHTML(initialName)}" placeholder="www.example.com" autocomplete="off" spellcheck="false"><small>Absolute or relative; the app adds the root dot. IP addresses work with PTR.</small></label>
        <label class="field"><span>Type</span><select id="lookup-type" class="select">${['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'SSHFP', 'SVCB', 'HTTPS', 'NAPTR', 'DNAME', 'URI', 'SPF', 'ANY'].map((type) => `<option value="${type}">${type}</option>`).join('')}</select></label>
        <label class="field"><span>Resolver</span><select id="lookup-resolver" class="select"><option value="both">Both (compare)</option>${RESOLVER_LIST.map((resolver) => `<option value="${resolver.id}">${escapeHTML(resolver.name)} · ${resolver.address}</option>`).join('')}</select></label>
        <label class="field"><span>Preset from workspace</span><select id="lookup-preset" class="select"><option value="">Choose a record…</option>${recordPresets(model).map((option) => `<option value="${escapeHTML(option.value)}">${escapeHTML(option.label)}</option>`).join('')}</select></label>
        <label class="checkbox-field"><input type="checkbox" id="lookup-dnssec" checked><span>Request DNSSEC records (+dnssec)</span><small>Sets DO=1. The AD flag still depends on the resolver validating the chain.</small></label>
        <label class="checkbox-field"><input type="checkbox" id="lookup-cd"><span>Disable validation (+cd)</span><small>Diagnostic only. A +cd answer is not authenticated.</small></label>
      </div>
      <div class="query-actions"><button class="btn btn-primary" type="button" id="run-lookup" ${consent ? '' : 'disabled'}>${icon('play', 15)} Run query</button><span class="muted-note" id="lookup-status">${consent ? 'Ready.' : 'Enable online lookups first.'}</span></div>
    </div>
    <div id="lookup-output" class="live-output">
      ${lookupResults ? renderLookupOutput(lookupResults, lookupComparison) : `<div class="empty-panel"><h2>No query yet</h2><p>Ask for a name and type. Results show flags, TTLs, DNSSEC status and the exact dig commands to reproduce the query.</p></div>`}
    </div>
    <div class="section-head small"><h2>Reproduce it with dig</h2><p>Copy these commands into a terminal on a host that can reach port 53.</p></div>
    <div id="lookup-dig">${codeBlock(buildDigCommands({ name: initialName, type: 'A', resolver: 'cloudflare', dnssec: true }).map((item) => `# ${item.label}\n${item.command}`).join('\n\n'), { label: 'dig commands', copy: true })}</div>
    <div class="callout info">${icon('info', 18)}<div><strong>DoH is not a compiler</strong><p>${explainDohLimits().map((item) => escapeHTML(item)).join(' ')}</p></div></div>
  </section>

  <section class="live-panel" data-live-panel="dnssec" ${activeTab === 'dnssec' ? '' : 'hidden'}>
    <div class="query-card">
      <div class="query-grid">
        <label class="field span-2"><span>Name or zone</span><input id="chain-name" type="text" value="${escapeHTML(initialName)}" placeholder="example.com" autocomplete="off" spellcheck="false"><small>The walker finds the zone apex with SOA, then checks DS and DNSKEY at every delegation up to the root.</small></label>
        <label class="field"><span>Resolver</span><select id="chain-resolver" class="select">${RESOLVER_LIST.map((resolver) => `<option value="${resolver.id}">${escapeHTML(resolver.name)} · ${resolver.address}</option>`).join('')}</select></label>
        <label class="field"><span>What is checked</span><div class="readonly-note">DS presence, DNSKEY presence, key tag, DS digest (SHA-1/256/384), AD flag, RRSIG count.</div></label>
      </div>
      <div class="query-actions"><button class="btn btn-primary" type="button" id="run-chain" ${consent ? '' : 'disabled'}>${icon('shield', 15)} Walk the chain</button><span class="muted-note" id="chain-status">${consent ? 'Ready.' : 'Enable online lookups first.'}</span></div>
    </div>
    <div id="chain-output">${chainResult ? renderChain(chainResult) : `<div class="empty-panel"><h2>No chain walked yet</h2><p>Start at a name or zone. The tool queries the resolver’s DS and DNSKEY answers and recomputes the DS digest locally.</p></div>`}</div>
    <div class="callout warn">${icon('warning', 18)}<div><strong>What this proves</strong><p>The AD flag is the resolver’s validation result. The digest match proves that the parent DS commits to the child DNSKEY. This page does not re-implement RRSIG signature verification; use <code>delv</code>, your own validating resolver and <code>named-checkds</code> for the final DNSSEC gate.</p></div></div>
  </section>

  <section class="live-panel" data-live-panel="verify" ${activeTab === 'verify' ? '' : 'hidden'}>
    ${!model || !model.zones.length ? `<div class="empty-panel"><h2>Import a zone first</h2><p>Zone verification compares records from your imported files with live answers. Open the workbench and import named.conf and zone files.</p><a class="btn btn-primary" href="#/workbench">${icon('upload', 15)} Open workbench</a></div>` : `
    <div class="query-card">
      <div class="query-grid">
        <label class="field"><span>Zone</span><select id="verify-zone" class="select"><option value="all">All imported zones</option>${model.zones.map((zone) => `<option value="${escapeHTML(zone.name)}" ${initialZone === zone.name ? 'selected' : ''}>${escapeHTML(zone.name)}</option>`).join('')}</select></label>
        <label class="field"><span>Resolver</span><select id="verify-resolver" class="select">${RESOLVER_LIST.map((resolver) => `<option value="${resolver.id}">${escapeHTML(resolver.name)} · ${resolver.address}</option>`).join('')}</select></label>
        <label class="field"><span>Maximum checks</span><input id="verify-limit" type="number" min="1" max="80" value="30"><small>Checks are grouped by owner + type. DNSSEC records are included where present.</small></label>
        <label class="field"><span>What is compared</span><div class="readonly-note">A, AAAA, CNAME, MX, TXT, NS, CAA, SRV, DS, DNSKEY. TTL is shown but not compared.</div></label>
      </div>
      <div class="query-actions"><button class="btn btn-primary" type="button" id="run-verify" ${consent ? '' : 'disabled'}>${icon('play', 15)} Verify live records</button><span class="muted-note" id="verify-status">${consent ? 'Ready.' : 'Enable online lookups first.'}</span></div>
      <div class="progress" id="verify-progress" hidden><div class="progress-bar"></div><span></span></div>
    </div>
    <div id="verify-output">${verificationResults ? renderVerificationOutput(verificationResults, verificationSummary) : `<div class="empty-panel"><h2>No verification run yet</h2><p>This checks what public resolvers currently return against the records in your imported zone. Cached and location-specific answers can legitimately differ.</p></div>`}</div>
    `}
  </section>

  <section class="live-panel" data-live-panel="how" ${activeTab === 'how' ? '' : 'hidden'}>
    ${renderHowItWorks()}
  </section>
  `;

  // Restore select values that were previously chosen.
  view.querySelector('#lookup-resolver').value = settings.resolver === 'google' ? 'google' : (settings.resolver === 'both' ? 'both' : 'cloudflare');
  view.querySelector('#verify-resolver')?.setAttribute('value', settings.resolver === 'google' ? 'google' : 'cloudflare');
  if (view.querySelector('#verify-resolver')) view.querySelector('#verify-resolver').value = settings.resolver === 'google' ? 'google' : 'cloudflare';
  if (chainResult) view.querySelector('#chain-resolver').value = settings.resolver === 'google' ? 'google' : 'cloudflare';
  wireCopyButtons(view);

  view.querySelectorAll('[data-live-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      activeTab = button.dataset.liveTab;
      view.querySelectorAll('[data-live-tab]').forEach((item) => item.setAttribute('aria-selected', String(item === button)));
      view.querySelectorAll('[data-live-panel]').forEach((panel) => {
        panel.hidden = panel.dataset.livePanel !== activeTab;
      });
    });
  });

  const enableButton = view.querySelector('#enable-online');
  if (enableButton) {
    enableButton.addEventListener('click', () => {
      consent = true;
      saveSettings({ onlineConsent: true });
      updateConsentUi();
      toast('Online lookups enabled. Queries go only to the selected DoH resolver.', 'ok');
    });
  }
  view.querySelector('#disable-online')?.addEventListener('click', () => {
    consent = false;
    saveSettings({ onlineConsent: false });
    updateConsentUi();
    toast('Online lookups disabled.', 'ok');
  });

  function updateConsentUi() {
    const gate = view.querySelector('#online-gate');
    gate.classList.toggle('enabled', consent);
    gate.querySelector('.consent-copy strong').textContent = consent ? 'Online lookups are enabled' : 'Online lookups are off';
    gate.querySelector('.consent-copy p').textContent = consent
      ? 'Queries are sent only to the selected DoH resolver. Configuration files never leave this browser. You can disable this at any time.'
      : 'A browser cannot use dig or UDP/53. This page uses DNS-over-HTTPS JSON endpoints from Cloudflare or Google. Enabling sends the queried name and type to that resolver; it does not send your configuration files.';
    gate.querySelector('.consent-actions').innerHTML = consent
      ? '<button class="btn btn-sm btn-ghost" type="button" id="disable-online">Turn off</button>'
      : `<button class="btn btn-primary" type="button" id="enable-online">${icon('check', 15)} Enable online lookups</button>`;
    if (consent) {
      gate.querySelector('#disable-online').addEventListener('click', () => {
        consent = false;
        saveSettings({ onlineConsent: false });
        updateConsentUi();
      });
    } else {
      gate.querySelector('#enable-online').addEventListener('click', () => {
        consent = true;
        saveSettings({ onlineConsent: true });
        updateConsentUi();
      });
    }
    ['#run-lookup', '#run-chain', '#run-verify'].forEach((selector) => {
      const button = view.querySelector(selector);
      if (button) button.disabled = !consent;
    });
    ['#lookup-status', '#chain-status', '#verify-status'].forEach((selector) => {
      const node = view.querySelector(selector);
      if (node && !busy) node.textContent = consent ? 'Ready.' : 'Enable online lookups first.';
    });
  }

  function requireConsent() {
    if (consent) return true;
    toast('Enable online lookups before sending a query.', 'warn');
    view.querySelector('#online-gate')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    return false;
  }

  view.querySelector('#lookup-preset')?.addEventListener('change', (event) => {
    if (!event.target.value) return;
    const [name, type] = event.target.value.split('|');
    view.querySelector('#lookup-name').value = name;
    view.querySelector('#lookup-type').value = type;
  });

  view.querySelector('#run-lookup')?.addEventListener('click', async () => {
    if (!requireConsent() || busy) return;
    const name = view.querySelector('#lookup-name').value.trim();
    const type = view.querySelector('#lookup-type').value;
    const resolverChoice = view.querySelector('#lookup-resolver').value;
    const dnssec = view.querySelector('#lookup-dnssec').checked;
    const checkingDisabled = view.querySelector('#lookup-cd').checked;
    if (!name) {
      toast('Enter a DNS name.', 'danger');
      return;
    }
    saveSettings({ resolver: resolverChoice });
    busy = true;
    clearAbort();
    abortController = new AbortController();
    setBusy('#run-lookup', true, 'Querying…');
    setStatus('#lookup-status', `Querying ${resolverChoice === 'both' ? 'both resolvers' : resolverById(resolverChoice).name}…`);
    try {
      const ids = resolverChoice === 'both' ? ['cloudflare', 'google'] : [resolverChoice];
      const results = await Promise.all(ids.map((id) => queryDns({ resolver: id, name, type, dnssec, checkingDisabled, signal: abortController.signal })));
      const byId = Object.fromEntries(ids.map((id, index) => [id, results[index]]));
      lookupResults = byId;
      lookupComparison = ids.length === 2 ? compareDnsResults(byId.cloudflare, byId.google) : null;
      view.querySelector('#lookup-output').innerHTML = renderLookupOutput(byId, lookupComparison);
      view.querySelector('#lookup-dig').innerHTML = codeBlock(buildDigCommands({ name, type, resolver: ids[0], dnssec }).map((item) => `# ${item.label}\n${item.command}`).join('\n\n'), { label: 'dig commands', copy: true });
      wireCopyButtons(view);
      setStatus('#lookup-status', `Done in ${results.map((result) => `${result.resolver.name} ${result.elapsedMs ?? '—'} ms`).join(' · ')}.`);
    } catch (error) {
      setStatus('#lookup-status', error?.message || 'Query failed.');
      toast(error?.message || 'Live query failed.', 'danger');
    } finally {
      busy = false;
      setBusy('#run-lookup', false, `${icon('play', 15)} Run query`);
    }
  });

  view.querySelector('#run-chain')?.addEventListener('click', async () => {
    if (!requireConsent() || busy) return;
    const name = view.querySelector('#chain-name').value.trim();
    const resolver = view.querySelector('#chain-resolver').value;
    if (!name) return;
    saveSettings({ resolver });
    busy = true;
    clearAbort();
    abortController = new AbortController();
    setBusy('#run-chain', true, 'Walking chain…');
    setStatus('#chain-status', 'Finding zone apex, then querying DS and DNSKEY at each delegation…');
    try {
      chainResult = await walkDnssecChain(name, resolver, { signal: abortController.signal });
      view.querySelector('#chain-output').innerHTML = chainResult?.ok ? renderChain(chainResult) : `<div class="callout danger">${icon('error', 18)}<div><strong>Chain walk failed</strong><p>${escapeHTML(chainResult?.error || 'Unknown error')}</p></div></div>`;
      wireCopyButtons(view);
      setStatus('#chain-status', chainResult?.ok ? `Checked ${chainResult.chain.length} delegation level(s).` : (chainResult?.error || 'Failed.'));
    } catch (error) {
      setStatus('#chain-status', error?.message || 'Chain walk failed.');
      toast(error?.message || 'Could not walk the DNSSEC chain.', 'danger');
    } finally {
      busy = false;
      setBusy('#run-chain', false, `${icon('shield', 15)} Walk the chain`);
    }
  });

  view.querySelector('#run-verify')?.addEventListener('click', async () => {
    if (!requireConsent() || busy) return;
    const zoneName = view.querySelector('#verify-zone').value;
    const resolver = view.querySelector('#verify-resolver').value;
    const limit = Math.max(1, Math.min(80, Number(view.querySelector('#verify-limit').value) || 30));
    const zones = zoneName === 'all' ? model.zones : model.zones.filter((zone) => zone.name === zoneName);
    const checks = buildVerificationChecks(zones, { limit });
    if (!checks.length) {
      toast('No verifiable records were found in the selected zone(s).', 'warn');
      return;
    }
    saveSettings({ resolver });
    busy = true;
    clearAbort();
    abortController = new AbortController();
    setBusy('#run-verify', true, 'Verifying…');
    const progress = view.querySelector('#verify-progress');
    progress.hidden = false;
    progress.querySelector('.progress-bar').style.width = '0%';
    progress.querySelector('span').textContent = `0 / ${checks.length}`;
    setStatus('#verify-status', `Checking ${checks.length} record group(s) with ${resolverById(resolver).name}…`);
    try {
      verificationResults = await runVerification(checks, {
        resolver,
        signal: abortController.signal,
        onProgress: ({ completed, total }) => {
          progress.querySelector('.progress-bar').style.width = `${Math.round((completed / total) * 100)}%`;
          progress.querySelector('span').textContent = `${completed} / ${total}`;
        },
      });
      verificationSummary = summarizeVerification(verificationResults);
      view.querySelector('#verify-output').innerHTML = renderVerificationOutput(verificationResults, verificationSummary);
      setStatus('#verify-status', `${verificationSummary.match} matched, ${verificationSummary.mismatch} mismatched, ${verificationSummary.error + verificationSummary.nxdomain + verificationSummary.empty} unresolved.`);
    } catch (error) {
      setStatus('#verify-status', error?.message || 'Verification failed.');
      toast(error?.message || 'Could not verify the zones.', 'danger');
    } finally {
      busy = false;
      progress.hidden = true;
      setBusy('#run-verify', false, `${icon('play', 15)} Verify live records`);
    }
  });

  function clearAbort() {
    if (abortController) abortController.abort();
    abortController = new AbortController();
  }

  function setBusy(selector, value, label) {
    const button = view.querySelector(selector);
    if (!button) return;
    button.disabled = value || !consent;
    button.innerHTML = label;
  }

  function setStatus(selector, text) {
    const node = view.querySelector(selector);
    if (node) node.textContent = text;
  }

  return () => {
    if (abortController) abortController.abort();
  };
}

function recordPresets(model) {
  if (!model?.zones) return [];
  const presets = [];
  for (const zone of model.zones) {
    const seen = new Set();
    for (const record of zone.parsed?.records || []) {
      if (!['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'DS', 'DNSKEY'].includes(record.type)) continue;
      if (record.owner.startsWith('*.')) continue;
      const key = `${record.owner}|${record.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (presets.length >= 120) return presets;
      presets.push({ value: `${record.owner.replace(/\.$/, '')}|${record.type}`, label: `${record.owner} ${record.type}${zone.view ? ` · ${zone.view}` : ''}` });
    }
  }
  return presets;
}

function renderLookupOutput(byId, comparison) {
  const cards = Object.values(byId || {}).map((result) => renderResolverResult(result)).join('');
  const comparisonHtml = comparison ? `<div class="comparison-card ${comparison.consistent ? 'ok' : 'warn'}">
    <div class="comparison-head">${icon(comparison.consistent ? 'check' : 'warning', 18)}<strong>${comparison.consistent ? 'Resolvers agree' : 'Resolvers disagree — inspect propagation'}</strong>${pill(`${comparison.onlyA.length + comparison.onlyB.length} differing`, comparison.consistent ? 'ok' : 'warn', 'diff')}</div>
    <div class="comparison-grid">
      <div><h4>Only Cloudflare</h4>${comparison.onlyA.length ? `<ul>${comparison.onlyA.map((value) => `<li><code>${escapeHTML(value)}</code></li>`).join('')}</ul>` : '<p class="muted">None.</p>'}</div>
      <div><h4>Only Google</h4>${comparison.onlyB.length ? `<ul>${comparison.onlyB.map((value) => `<li><code>${escapeHTML(value)}</code></li>`).join('')}</ul>` : '<p class="muted">None.</p>'}</div>
    </div>
    <p class="muted-note">Differences can be legitimate: GeoDNS, round-robin pools, split horizon, caches and resolver policy all change answers. A difference is a question, not automatically an error.</p>
  </div>` : '';
  return `<div class="resolver-grid">${cards}</div>${comparisonHtml}`;
}

function renderResolverResult(result) {
  if (!result) return '';
  if (!result.ok) {
    return `<article class="resolver-card danger">
      <div class="resolver-head"><div>${icon('error', 18)}<strong>${escapeHTML(result.resolver?.name || 'Resolver')}</strong><span>${escapeHTML(result.resolver?.address || '')}</span></div>${pill('failed', 'danger', 'error')}</div>
      <p>${escapeHTML(result.error || 'The query failed.')}</p>
      <p class="muted-note">Check network access, CSP, resolver availability or whether the query type is accepted by the JSON API.</p>
    </article>`;
  }
  const answers = result.answers || [];
  return `<article class="resolver-card">
    <div class="resolver-head">
      <div>${icon('globe', 18)}<strong>${escapeHTML(result.resolver.name)}</strong><span>${escapeHTML(result.resolver.address)} · ${escapeHTML(result.type)} ${escapeHTML(result.name)}</span></div>
      <div class="resolver-flags">${pill(result.rcode, result.status === 0 ? 'ok' : result.rcode === 'NXDOMAIN' ? 'warn' : 'danger', result.status === 0 ? 'check' : 'warning')}${pill(result.flags.ad ? 'AD validated' : 'AD not set', result.flags.ad ? 'ok' : 'neutral', 'shield')}${pill(`${result.elapsedMs ?? '—'} ms`, 'neutral', 'clock')}</div>
    </div>
    <div class="flag-strip">${['AA', 'TC', 'RD', 'RA', 'AD', 'CD'].map((flag) => `<span class="flag ${result.flags[flag.toLowerCase()] ? 'on' : ''}">${flag} ${result.flags[flag.toLowerCase()] ? '1' : '0'}</span>`).join('')}</div>
    ${answers.length ? `<div class="table-scroll"><table class="record-table answer-table"><thead><tr><th>Type</th><th>TTL</th><th>Data</th></tr></thead><tbody>${answers.map((answer) => `<tr><td><span class="record-type">${escapeHTML(answer.type)}</span></td><td class="mono">${formatNumber(answer.ttl)}</td><td class="record-data"><code>${escapeHTML(answer.data)}</code></td></tr>`).join('')}</tbody></table></div>` : `<p class="muted">No answers in the ANSWER section. That can be NODATA rather than NXDOMAIN; read the RCODE and authority section.</p>`}
    <div class="answer-meta"><span>${formatNumber(result.authority.length)} authority</span><span>${formatNumber(result.additional.length)} additional</span>${result.comment ? `<span>${escapeHTML(result.comment)}</span>` : ''}</div>
    <details class="raw-json"><summary>Raw JSON</summary><pre>${escapeHTML(JSON.stringify(result.raw, null, 2))}</pre></details>
  </article>`;
}

function renderChain(result) {
  const statusTone = result.overall === 'secure' ? 'ok' : result.overall === 'bogus' ? 'danger' : 'warn';
  const label = {
    secure: 'Secure — a complete validated chain',
    insecure: 'Insecure — the chain intentionally stops at a missing DS',
    bogus: 'Bogus — a DS exists but the key or validation failed',
    unvalidated: 'Keys match, but the resolver did not set AD',
    unknown: 'Unknown',
  }[result.overall] || result.overall;
  return `<div class="chain-overall ${statusTone}">${icon(result.overall === 'secure' ? 'shield' : 'warning', 22)}<div><strong>${escapeHTML(label)}</strong><p>Apex <code>${escapeHTML(result.apex || result.name)}</code> · resolver ${escapeHTML(resolverById(result.resolver).name)} · checked ${escapeHTML(formatDateTime(result.checkedAt))}</p></div>${pill(result.overall, statusTone, result.overall === 'secure' ? 'check' : 'warning')}</div>
  <div class="chain-steps">${result.chain.map((step, index) => `<article class="chain-step ${step.status}">
    <div class="chain-step-head"><div class="chain-index">${index + 1}</div><div><h3>${escapeHTML(step.zone)}</h3><p>${step.isRoot ? 'Root trust anchor' : 'Delegation'} · ${escapeHTML(step.status)}</p></div><div class="resolver-flags">${pill(step.ad ? 'AD set' : 'AD not set', step.ad ? 'ok' : 'neutral', 'shield')}${pill(`${step.rrsigs.length} RRSIG`, step.rrsigs.length ? 'ok' : 'neutral', 'file')}</div></div>
    <div class="chain-step-body">
      <div class="chain-half"><h4>Parent DS (${step.dsRecords.length})</h4>${step.dsRecords.length ? `<div class="table-scroll"><table class="record-table compact"><thead><tr><th>Key tag</th><th>Algorithm</th><th>Digest</th></tr></thead><tbody>${step.dsRecords.map((record) => `<tr><td class="mono">${escapeHTML(record.data.split(/\s+/)[0])}</td><td>${escapeHTML(record.data.split(/\s+/)[1])}</td><td class="record-data"><code>${escapeHTML(record.data.split(/\s+/).slice(2).join(' ').slice(0, 72))}${record.data.length > 80 ? '…' : ''}</code></td></tr>`).join('')}</tbody></table></div>` : `<p class="muted">${step.isRoot ? 'Root uses a local trust anchor, so there is no parent DS.' : 'No DS returned. This delegation is insecure unless a chain of trust comes from elsewhere.'}</p>`}</div>
      <div class="chain-half"><h4>Child DNSKEY (${step.dnskeyRecords.length})</h4>${step.dnskeyRecords.length ? `<ul class="key-list">${step.dnskeyRecords.map((record) => `<li><code>${escapeHTML(record.data.slice(0, 90))}${record.data.length > 90 ? '…' : ''}</code></li>`).join('')}</ul>` : '<p class="muted">No DNSKEY returned.</p>'}</div>
    </div>
    <div class="chain-match">${step.matching.results.length ? step.matching.results.map((item) => `<div class="match-row ${item.status}">${icon(item.status === 'match' ? 'check' : 'warning', 14)}<span>DS key tag ${item.ds.keyTag}, algorithm ${item.ds.algorithm}, digest ${item.ds.digestType}: <strong>${escapeHTML(item.status)}</strong></span>${item.computed?.filter((entry) => entry.ok).map((entry) => `<code title="computed digest">${escapeHTML(entry.digest.slice(0, 24))}…</code>`).join('') || ''}</div>`).join('') : `<div class="match-row ${step.isRoot ? 'info' : 'warn'}">${icon('info', 14)} ${step.isRoot ? 'Root DNSKEY is anchored by the resolver’s built-in trust anchor.' : 'No DS records to match at this level.'}</div>`}</div>
  </article>`).join('')}</div>
  <div class="section-head small"><h2>Verify with dig</h2><p>Run these against the same resolver or an authoritative server.</p></div>
  ${codeBlock(chainDigCommands(result.chain, result.resolver).map((item) => `# ${item.label}\n${item.command}`).join('\n\n'), { label: 'DNSSEC dig commands' })}`;
}

function renderVerificationOutput(results, summary) {
  const tone = summary.mismatch || summary.error || summary.nxdomain ? 'warn' : 'ok';
  return `<div class="verification-summary ${tone}">
    <div>${icon(tone === 'ok' ? 'check' : 'warning', 20)}<div><strong>${summary.match} of ${summary.total} record groups match</strong><p>${summary.mismatch} mismatched · ${summary.empty} empty · ${summary.nxdomain} NXDOMAIN · ${summary.error} errors · ${summary.authenticated} authenticated (AD).</p></div></div>
    ${pill(tone === 'ok' ? 'consistent' : 'review', tone, tone === 'ok' ? 'check' : 'warning')}
  </div>
  <div class="table-scroll"><table class="record-table verification-table">
    <thead><tr><th>Status</th><th>Check</th><th>Expected</th><th>Observed</th><th>RCODE / AD</th></tr></thead>
    <tbody>${results.map((result) => `<tr class="verify-${result.status}">
      <td><span class="pill ${result.status === 'match' ? 'ok' : result.status === 'mismatch' ? 'danger' : 'warn'}">${escapeHTML(result.status)}</span></td>
      <td><code>${escapeHTML(result.check.owner)}</code> <span class="record-type">${escapeHTML(result.check.type)}</span></td>
      <td><div class="value-list">${Array.from(result.check.expected).map((value) => `<code>${escapeHTML(displayValue(value))}</code>`).join('')}</div></td>
      <td><div class="value-list">${Array.from(result.observed).map((value) => `<code>${escapeHTML(displayValue(value))}</code>`).join('') || '<span class="muted">none</span>'}</div>
        ${result.missing.length ? `<div class="missing-values"><strong>Missing:</strong> ${result.missing.map((value) => `<code>${escapeHTML(displayValue(value))}</code>`).join(' ')}</div>` : ''}
        ${result.unexpected.length ? `<div class="missing-values"><strong>Unexpected:</strong> ${result.unexpected.map((value) => `<code>${escapeHTML(displayValue(value))}</code>`).join(' ')}</div>` : ''}
      </td>
      <td class="mono">${escapeHTML(result.rcode || '—')}${result.ad ? ' · AD' : ''}</td>
    </tr>`).join('')}</tbody>
  </table></div>
  <div class="callout warn">${icon('warning', 18)}<div><strong>Read mismatches carefully</strong><ul>${verificationCaveats().map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul></div></div>`;
}

function displayValue(value) {
  if (value === null || value === undefined) return '';
  try {
    if (String(value).startsWith('[') || String(value).startsWith('{')) {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed.join(' ');
      return JSON.stringify(parsed);
    }
  } catch {
    /* keep original */
  }
  return String(value);
}

function renderHowItWorks() {
  const article = articleById('live-dns-dig');
  return `<div class="learn-config-intro"><div><span class="eyebrow">How it works</span><h2>Browsers cannot run dig</h2><p>This page uses DNS-over-HTTPS JSON from Cloudflare and Google. That is a real DNS query, but it is a recursive resolver’s view, not authoritative truth. Read the flags, compare resolvers and then verify with dig/delv.</p></div><div class="learn-config-stats"><div><strong>DoH</strong><span>transport</span></div><div><strong>AD</strong><span>validation flag</span></div><div><strong>DS</strong><span>parent trust</span></div><div><strong>dig</strong><span>terminal truth</span></div></div></div>
  ${article ? article.sections.map((section) => `<section class="doc-section" id="${escapeHTML(section.id)}"><h2>${escapeHTML(section.title)}</h2>${section.html}</section>`).join('') : ''}
  <div class="callout info">${icon('info', 18)}<div><strong>Why only Cloudflare and Google?</strong><p>The container’s Content-Security-Policy allows only these two DoH origins. A custom resolver would require changing the CSP and the container build, which is intentionally not a click-away action.</p></div></div>`;
}
