/* Home page: start here, import, examples and the deployment story. */

import { analyzeWorkspace } from '../dns/analyzer.js';
import { parseWorkspace } from '../dns/workspace.js';
import { getCurrentWorkspace } from '../storage.js';
import { SAMPLES } from '../data/samples.js';
import { ARTICLES } from '../data/learn.js';
import { DIRECTIVE_DOCS } from '../data/directives.js';
import { GLOSSARY } from '../data/glossary.js';
import { RECORD_DOCS } from '../data/records.js';
import { icon, pill, scoreGauge } from '../ui.js';
import { escapeHTML, formatDate, formatNumber } from '../utils.js';
import { wireImportControls } from './import-ui.js';

export async function renderHome(view) {
  const current = getCurrentWorkspace();
  let resume = null;
  if (current) {
    try {
      const model = parseWorkspace(current);
      const analysis = await analyzeWorkspace(current, model);
      resume = { workspace: current, model, analysis };
    } catch {
      resume = null;
    }
  }

  const buildCard = `<div class="build-card">
    <div class="build-card-head"><span class="status-dot"></span><div><strong>This build</strong><span>Static container · optional auth · no config API</span></div></div>
    <div class="build-grid">
      <div><span>Version</span><strong data-app-version>dev</strong></div>
      <div><span>Image</span><strong data-image-tag>local</strong></div>
      <div><span>Commit</span><strong><a data-commit-link><span data-commit>local</span></a></strong></div>
      <div><span>Built</span><strong data-build-date>local build</strong></div>
    </div>
    <div class="build-clock">${icon('clock', 18)}<div><span>Your browser clock</span><time data-live-clock>local time</time></div></div>
    <p class="build-note">Build metadata is baked into <code>version.json</code> by the Docker build. Local runs show dev/local.</p>
  </div>`;

  const miniTopology = `<div class="dns-diagram" aria-label="DNS resolution and validation path">
    <div class="dns-diagram-row">
      <span class="dns-node client">Client</span>
      <span class="dns-arrow">${icon('arrow', 16)}</span>
      <span class="dns-node resolver">Resolver</span>
      <span class="dns-arrow">${icon('arrow', 16)}</span>
      <span class="dns-node root">Root</span>
    </div>
    <div class="dns-diagram-row">
      <span class="dns-node tld">TLD</span>
      <span class="dns-arrow">${icon('arrow', 16)}</span>
      <span class="dns-node auth">Authoritative</span>
      <span class="dns-arrow">${icon('arrow', 16)}</span>
      <span class="dns-node answer">Answer</span>
    </div>
    <div class="dns-diagram-rail"><span>${icon('shield', 14)} DNSSEC chain</span><span>${icon('database', 14)} cache + TTL</span><span>${icon('globe', 14)} DoH checks</span></div>
  </div>`;

  const resumeCard = resume ? `<section class="resume-card">
    <div class="resume-main">
      <span class="eyebrow">Continue where you left off</span>
      <h2>${escapeHTML(resume.workspace.name)}</h2>
      <p class="resume-meta">${formatNumber(resume.workspace.files.length)} files · ${formatNumber(resume.model.summary.zones)} zones · ${formatNumber(resume.model.summary.records)} records · updated ${escapeHTML(formatDate(resume.workspace.updatedAt))}</p>
      <div class="meta-strip">
        ${pill(`${resume.analysis.counts.error} errors`, resume.analysis.counts.error ? 'danger' : 'ok', resume.analysis.counts.error ? 'error' : 'check')}
        ${pill(`${resume.analysis.counts.warning} warnings`, resume.analysis.counts.warning ? 'warn' : 'ok', 'warning')}
        ${pill(`${resume.analysis.counts.recommendation} recommendations`, 'neutral', 'info')}
        ${pill(`${resume.model.zones.filter((zone) => zone.parsed?.soa).length} zones with SOA`, 'ok', 'database')}
      </div>
    </div>
    <div class="resume-score">${scoreGauge(resume.analysis.score, 'health')}</div>
    <div class="resume-actions">
      <a class="btn btn-primary" href="#/workbench">${icon('edit', 16)} Open workbench</a>
      <a class="btn" href="#/analyze">${icon('shield', 16)} Review findings</a>
      <a class="btn btn-ghost" href="#/workbench?export=1">${icon('download', 16)} Export</a>
    </div>
  </section>` : '';

  const sampleCards = SAMPLES.map((sample) => `<article class="sample-card">
    <div class="sample-card-head">${pill(sample.files.length + ' files', 'accent', 'package')}<span class="sample-lines">${escapeHTML(sample.architecture)}</span></div>
    <h3>${escapeHTML(sample.title)}</h3>
    <p>${escapeHTML(sample.description)}</p>
    <div class="sample-arch"><code>${escapeHTML(sample.architecture)}</code></div>
    <ul class="sample-highlights">${sample.highlights.map((item) => `<li>${escapeHTML(item)}</li>`).join('')}</ul>
    <button class="btn btn-sm sample-load" type="button" data-sample-id="${escapeHTML(sample.id)}">${icon('upload', 14)} Load example</button>
  </article>`).join('');

  const featureCards = [
    ['analyze', 'shield', 'Analyze with reasons', 'Errors, warnings and best practices across named.conf, zones, delegation and DNSSEC — each with what, why and a fix.'],
    ['workbench', 'code', 'Multi-file workbench', 'named.conf includes, zone files, views, keys and journals. Edit, navigate and learn every directive in context.'],
    ['compare', 'diff', 'Line and semantic diff', 'Compare two files, or a saved snapshot with the current workspace. See record-level changes, TTLs and serials.'],
    ['live', 'globe', 'Live DNS and DNSSEC', 'Query Cloudflare and Google over DoH, verify expected records, walk the DS/DNSKEY chain and generate dig commands.'],
    ['zones', 'database', 'Zone explorer', 'Browse every record, inspect SOA/NS, find CNAME and glue mistakes, and verify forward/reverse consistency.'],
    ['learn', 'book', 'Learn the why', 'Long-form guides, a directive and record encyclopedia, and an 80-term glossary — linked from every finding.'],
  ];

  view.innerHTML = `
    <section class="home-hero">
      <div class="hero-copy">
        <span class="eyebrow">Local-first BIND DNS studio</span>
        <h1>Understand your DNS.<br><em>Change it safely.</em></h1>
        <p class="hero-lede">Import <code>named.conf</code>, includes and zone files. Get explainable errors, security and DNSSEC checks, semantic diffs, live DNS verification, and a validated multi-file export. Nothing is uploaded.</p>
        <div class="hero-actions">
          <button class="btn btn-primary btn-lg" type="button" data-import-files>${icon('upload', 17)} Import files</button>
          <button class="btn btn-lg" type="button" data-import-folder>${icon('folder', 17)} Import folder</button>
          <a class="btn btn-ghost btn-lg" href="#/workbench">${icon('grid', 17)} Open workbench</a>
        </div>
        <div class="home-buildline">
          <span><em>version</em><strong data-app-version>dev</strong></span>
          <span><em>image</em><strong data-image-tag>local</strong></span>
          <span><em>commit</em><a data-commit-link><strong data-commit>local</strong></a></span>
          <span class="home-live-time"><em>now</em><time data-live-clock>local time</time></span>
        </div>
        <div class="hero-trust">
          <span>${icon('lock', 15)} <strong>Configs stay in your browser</strong></span>
          <span>${icon('wifi', 15)} DoH is opt-in</span>
          <span>${icon('zap', 15)} No build step</span>
        </div>
        <div class="hero-stats">
          <div class="hero-stat"><strong>${DIRECTIVE_DOCS.length}</strong><span>directive guides</span></div>
          <div class="hero-stat"><strong>${RECORD_DOCS.length}</strong><span>record types</span></div>
          <div class="hero-stat"><strong>${ARTICLES.length}</strong><span>deep articles</span></div>
          <div class="hero-stat"><strong>${GLOSSARY.length}</strong><span>glossary terms</span></div>
        </div>
      </div>
      <div class="hero-side">
        ${buildCard}
        ${miniTopology}
      </div>
    </section>

    <div class="privacy-banner">
      <div class="privacy-banner-icon">${icon('shield', 22)}</div>
      <div>
        <strong>Local-first by architecture, not by promise.</strong>
        <p>The container serves static files and an optional password-session API. It never receives configuration data. Parsing, analysis, diffing, history and export run in this tab. Live DNS uses only the curated DoH endpoints you enable.</p>
      </div>
      <a class="btn btn-sm" href="#/security">Security model</a>
    </div>

    ${resumeCard}

    <section class="start-panel">
      <div class="start-copy">
        <span class="eyebrow">Start in seconds</span>
        <h2>Drop a folder, a ZIP, or a single file.</h2>
        <p>Folder import preserves relative paths, so includes and zone files resolve exactly as they do on disk. A ZIP exported from this app can be re-imported later.</p>
        <div class="start-actions">
          <button class="btn btn-primary" type="button" data-import-files>${icon('upload', 16)} Choose files</button>
          <button class="btn" type="button" data-import-folder>${icon('folder', 16)} Choose folder</button>
          <a class="btn btn-ghost" href="#/compare">${icon('diff', 16)} Compare two files</a>
        </div>
        <p class="muted-note">${icon('info', 14)} Supported: named.conf, includes, zone files, TSIG files (as text), ZIP bundles and BIND Workbench workspace JSON.</p>
      </div>
      <div class="dropzone" data-dropzone tabindex="0" role="button" aria-label="Drop BIND configuration files here">
        <div class="dropzone-icon">${icon('upload', 24)}</div>
        <strong>Drop files or a folder here</strong>
        <span>or use the buttons to browse</span>
        <small>Files are read locally with the browser File API</small>
      </div>
    </section>

    <section class="section-block">
      <div class="section-head"><div><span class="eyebrow">What it does</span><h2>Six views of the same truth</h2><p>Every feature is designed around one question: what will BIND actually do when this configuration loads?</p></div></div>
      <div class="feature-grid">
        ${featureCards.map(([href, iconName, title, body]) => `<a class="feature-card" href="#/${href}">
          <span class="feature-icon">${icon(iconName, 20)}</span>
          <h3>${escapeHTML(title)}</h3>
          <p>${escapeHTML(body)}</p>
          <span class="feature-link">Open ${escapeHTML(href === 'workbench' ? 'workbench' : href)} ${icon('arrow', 13)}</span>
        </a>`).join('')}
      </div>
    </section>

    <section class="section-block">
      <div class="section-head"><div><span class="eyebrow">Examples</span><h2>Learn from a real multi-file workspace</h2><p>All examples use documentation TLDs and TEST-NET addresses. The problem clinic is deliberately broken.</p></div></div>
      <div class="sample-grid">${sampleCards}</div>
    </section>

    <section class="split-block">
      <div>
        <span class="eyebrow">Deep checks</span>
        <h2>What “validate” means here</h2>
        <p>BIND Workbench does not pretend to be a compiler. It combines a structural parser, a semantic analyzer and optional live DNSSEC checks, then gives you the exact commands to run the real tools.</p>
        <div class="check-columns">
          <div><h3>Offline</h3><ul><li>named.conf grammar, includes and file references</li><li>SOA, NS, CNAME, MX, SRV and glue rules</li><li>Delegation and parent/child consistency</li><li>DNSSEC key, DS, RRSIG and NSEC/NSEC3 hygiene</li><li>Recursion, transfer, update and logging posture</li></ul></div>
          <div><h3>Live, opt-in</h3><ul><li>Cloudflare and Google DoH answers</li><li>Expected vs observed records from your zone</li><li>DS digest ↔ DNSKEY matching</li><li>Chain walk from apex to root</li><li>dig/delv command generation</li></ul></div>
        </div>
      </div>
      <div class="privacy-facts">
        <div class="fact">${icon('check', 18)}<div><strong>No config upload endpoint</strong><span>The server has no config API, database or write path. The optional auth API only handles the login session.</span></div></div>
        <div class="fact">${icon('check', 18)}<div><strong>Strict CSP</strong><span>Only self-hosted assets and two DoH origins are allowed.</span></div></div>
        <div class="fact">${icon('check', 18)}<div><strong>Safe export</strong><span>Original files plus manifest, hashes, validate.sh and dig plans.</span></div></div>
        <div class="fact">${icon('warning', 18)}<div><strong>Always run the real tools</strong><span>named-checkconf and named-checkzone with the exact BIND version remain the final gate.</span></div></div>
      </div>
    </section>

    <section class="section-block install-card">
      <div>
        <span class="eyebrow">Run it</span>
        <h2>One container. One port. No account.</h2>
        <p>Published as <code>ghcr.io/rogerbergling/bind-gui:latest</code>. Use the included Compose file; the container runs read-only, non-root and with all capabilities dropped.</p>
        <div class="install-actions">
          <a class="btn btn-primary" href="https://github.com/RogerBergling/bind-gui" target="_blank" rel="noopener noreferrer">${icon('external', 16)} GitHub</a>
          <a class="btn" href="#/security">${icon('shield', 16)} Security model</a>
          <a class="btn btn-ghost" href="#/learn/change-workflow">${icon('book', 16)} Change workflow</a>
        </div>
      </div>
      <div class="install-code">
        <div class="code-head"><span>docker compose</span><button class="btn btn-xs btn-ghost" type="button" data-copy="curl -O https://raw.githubusercontent.com/RogerBergling/bind-gui/main/compose.yaml&#10;docker compose up -d">${icon('copy', 13)} Copy</button></div>
        <pre><code>curl -O https://raw.githubusercontent.com/RogerBergling/bind-gui/main/compose.yaml
docker compose up -d</code></pre>
        <p class="muted-note">Then open <strong>http://localhost:8005</strong>. MIT licensed. No warranty.</p>
      </div>
    </section>
  `;

  wireImportControls(view, { navigate: true });
  return null;
}
