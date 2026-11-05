/* Security and privacy model page. */

import { icon, pill, callout, codeBlock } from '../ui.js';

export function renderSecurity(view) {
  view.innerHTML = `<div class="page-head">
    <div class="page-head-copy"><span class="eyebrow">Security &amp; privacy</span><h1>The configuration stays here</h1><p class="page-lede">BIND Workbench is a static browser application with no account, database, config upload endpoint or analytics. Parsing, analysis, diffing, history and export run in this tab. An optional server-side password gate protects access to the app. This page explains the threat model, the live-DNS exception and what the design does not protect.</p><div class="meta-strip">${pill('no config upload API', 'ok', 'lock')}${pill('strict CSP', 'ok', 'shield')}${pill('opt-in DoH', 'warn', 'globe')}${pill('MIT licensed', 'neutral', 'check')}</div></div>
    <div class="page-actions"><a class="btn" href="#/learn/hardening">${icon('book', 16)} Hardening guide</a><a class="btn" href="https://github.com/RogerBergling/bind-gui" target="_blank" rel="noopener noreferrer">${icon('external', 16)} Source</a></div>
  </div>

  <div class="security-hero">
    <div class="security-diagram">
      <div class="security-node browser"><span>${icon('code', 22)}</span><strong>Browser tab</strong><small>File API → parser → analyzer → diff → localStorage</small></div>
      <div class="security-arrow">${icon('arrow', 18)}<span>static files + optional auth</span></div>
      <div class="security-node server"><span>${icon('server', 22)}</span><strong>Container</strong><small>Python stdlib static server · GET/HEAD · no write path</small></div>
      <div class="security-arrow optional">${icon('globe', 18)}<span>opt-in only</span></div>
      <div class="security-node doh"><span>${icon('globe', 22)}</span><strong>DoH resolver</strong><small>Cloudflare or Google · query name/type only</small></div>
    </div>
    <div class="privacy-facts">
      <div class="fact">${icon('check', 18)}<div><strong>No server-side config handling</strong><span>The container never receives a configuration file or zone record.</span></div></div>
      <div class="fact">${icon('check', 18)}<div><strong>No third-party assets</strong><span>No CDN, fonts, analytics, crash reporting or advertising scripts.</span></div></div>
      <div class="fact">${icon('check', 18)}<div><strong>Strict response headers</strong><span>CSP, no-referrer, nosniff, COOP/CORP, frame denial and no-store caching.</span></div></div>
      <div class="fact">${icon('warning', 18)}<div><strong>Storage is still data</strong><span>Browser profiles, extensions and device access can read localStorage and exports.</span></div></div>
    </div>
  </div>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Data flow</span><h2>What is stored where</h2></div></div>
    <div class="table-scroll"><table class="record-table security-table"><thead><tr><th>Data</th><th>Where</th><th>Leaves the browser?</th><th>Notes</th></tr></thead><tbody>
      <tr><td>Imported named.conf and zones</td><td>Memory, then localStorage</td><td>No</td><td>Sent to no server endpoint.</td></tr>
      <tr><td>Analysis results</td><td>Memory</td><td>No</td><td>Recomputed on load; not persisted as a server record.</td></tr>
      <tr><td>Snapshots and history</td><td>localStorage</td><td>No</td><td>Up to 100 versions, bounded by a local size budget.</td></tr>
      <tr><td>Settings and theme</td><td>localStorage</td><td>No</td><td>Includes the online-lookup consent flag.</td></tr>
      <tr><td>Password session (optional)</td><td>Server memory + HttpOnly cookie</td><td>No configuration data</td><td>Only when <code>BIND_WORKBENCH_PASSWORD</code> is set. The password is compared server-side; the cookie contains a random session token.</td></tr>
      <tr><td>Live DNS query name/type</td><td>Selected DoH resolver</td><td>Yes, only after opt-in</td><td>DoH endpoint receives the queried name and type. Configuration files are never included.</td></tr>
      <tr><td>Downloaded exports</td><td>Your filesystem</td><td>As a file you request</td><td>Plaintext, possibly including TSIG secrets found in source files.</td></tr>
    </tbody></table></div>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Optional app password</span><h2>Gate the app at the server edge</h2></div></div>
    <div class="callout ok">${icon('lock', 18)}<div><strong>Server-side, not a JavaScript password</strong><p>Set <code>BIND_WORKBENCH_PASSWORD</code> to require a login before the application shell or any asset is served. The password is compared in the Python server with <code>hmac.compare_digest</code>; it never appears in HTML, JavaScript or the frontend bundle.</p></div></div>
    <ul class="security-list">
      <li>The login page is the only public HTML entry point; application scripts and JSON return <code>401</code> until authenticated.</li>
      <li>A successful login creates a random, <code>HttpOnly</code>, <code>SameSite=Strict</code> session cookie. Sessions live in process memory and expire after 12 hours by default.</li>
      <li>Five failed attempts per IP per minute trigger a temporary <code>429</code> throttle.</li>
      <li>The top bar shows a lock button when the gate is enabled; it clears the session and returns to the login page.</li>
      <li>This protects the whole app, including imports, history, compare and export. It does not encrypt transport; use HTTPS in front of it.</li>
      <li>It is a single shared secret, not a user account system. Use reverse-proxy authentication (Basic Auth, OIDC or an identity-aware proxy) for multi-user or internet-facing deployments.</li>
    </ul>
    <div class="callout warn">${icon('warning', 18)}<div><strong>Cookie and proxy detail</strong><p>The session cookie is marked <code>Secure</code> only when the server sees <code>X-Forwarded-Proto: https</code>. Configure your reverse proxy to set that header and to terminate TLS. Never expose a password-protected HTTP listener to an untrusted network.</p></div></div>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Live DNS exception</span><h2>Why DoH is different</h2></div></div>
    <div class="callout warn">${icon('warning', 18)}<div><strong>Online lookups are opt-in</strong><p>A browser cannot open UDP/TCP port 53, so this app uses DNS-over-HTTPS JSON from Cloudflare (1.1.1.1) and Google (8.8.8.8). When you enable lookups and run a query, the selected resolver sees the DNS name and type you asked for. It also sees your IP address, as any internet service does. The app does not send your configuration, findings, history or file names.</p></div></div>
    <ul class="security-list">
      <li>Only two DoH origins are allowed by the Content-Security-Policy: <code>https://cloudflare-dns.com</code> and <code>https://dns.google</code>.</li>
      <li>The app does not accept arbitrary resolver URLs; changing the allow-list requires a source/CSP change and image rebuild.</li>
      <li>Queries use <code>credentials: 'omit'</code>, <code>referrerPolicy: 'no-referrer'</code> and <code>cache: 'no-store'</code>.</li>
      <li>Turning online lookups off disables all query buttons and keeps the consent flag off until you enable it again.</li>
      <li>DoH protects the transport. It does not replace DNSSEC validation, and it does not make the resolver’s answer authoritative truth.</li>
    </ul>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Secrets</span><h2>TSIG secrets and private keys</h2></div></div>
    <div class="callout danger">${icon('lock', 18)}<div><strong>Do not treat this app as a secret manager</strong><p>If you import a configuration containing a TSIG secret or private key, that text is in the browser workspace, localStorage snapshots and any export you download. Use test secrets for demos. In production, reference protected files and never commit secrets to Git or bake them into container images.</p></div></div>
    <ul class="security-list">
      <li>Use dedicated TSIG keys per peer or client, rotate them, and store them with <code>0600</code> permissions owned by the BIND user.</li>
      <li>DNSSEC private keys belong in <code>key-directory</code> with strict ownership; back them up encrypted and test restoration.</li>
      <li>Exports include plaintext source files by design. Store the ZIP and workspace JSON accordingly.</li>
      <li>Browser extensions, shared devices and profile sync can read localStorage. Use a dedicated browser profile or a trusted device.</li>
      <li>Clear local data from the History page or the button below when you finish on a shared machine.</li>
    </ul>
    <button class="btn btn-danger" type="button" id="clear-all-data">${icon('trash', 16)} Clear all local data</button>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Transport &amp; container</span><h2>Response headers</h2><p>The local Python server and the container send the same headers. Keep the in-app text and the server code in sync.</p></div></div>
    ${codeBlock(`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
  img-src 'self' data:; font-src 'self';
  connect-src 'self' https://cloudflare-dns.com https://dns.google;
  object-src 'none'; worker-src 'none'; base-uri 'none';
  frame-ancestors 'none'; form-action 'none'
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-Permitted-Cross-Domain-Policies: none
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, { label: 'HTTP security headers', copy: true })}
    <div class="security-grid">
      <div class="fact">${icon('check', 18)}<div><strong>Non-root image</strong><span>Runs as UID/GID 10001 with no shell login and a read-only root filesystem in Compose.</span></div></div>
      <div class="fact">${icon('check', 18)}<div><strong>All capabilities dropped</strong><span>Compose uses <code>cap_drop: ALL</code> and <code>no-new-privileges</code>.</span></div></div>
      <div class="fact">${icon('check', 18)}<div><strong>No Docker socket</strong><span>The container does not need host control and Compose does not mount the socket.</span></div></div>
      <div class="fact">${icon('check', 18)}<div><strong>No persistence in the image</strong><span>History is in the browser; the container can be recreated safely.</span></div></div>
    </div>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Threat model</span><h2>What this design does not protect</h2></div></div>
    <div class="two-column">
      <div><h3>Protected by design</h3><ul class="security-list"><li>Configurations are not uploaded to an application server.</li><li>No account or server-side database to breach.</li><li>No third-party scripts or analytics in the page.</li><li>No arbitrary outbound HTTP from the app; only the two DoH origins.</li><li>Strict CSP reduces script injection impact; user content is escaped.</li></ul></div>
      <div><h3>Out of scope</h3><ul class="security-list"><li>A compromised device, browser, extension or hostile server operator serving modified JavaScript.</li><li>Anyone with access to your browser profile or exported files.</li><li>Secrets pasted into configuration text.</li><li>DNS infrastructure security itself: recursion, transfers, DNSSEC keys, firewalls and patching.</li><li>Correctness of the live DNS answer or the BIND binary you deploy.</li></ul></div>
    </div>
  </section>

  <section class="section-block">
    <div class="section-head"><div><span class="eyebrow">Exposure</span><h2>If you expose it beyond localhost</h2></div></div>
    <p>Put the container behind an HTTPS reverse proxy you control. The static server does not encrypt transport. The included Compose file binds the published port to <code>127.0.0.1</code> by default; change it deliberately if remote access is intended. Keep the image updated and review the Dockerfile and workflow. Do not add an upload API just to make the demo convenient.</p>
    ${codeBlock(`# Local-only compose binding example
ports:
  - "127.0.0.1:8005:8005"`, { label: 'compose port binding', copy: true })}
    <div class="callout info">${icon('info', 18)}<div><strong>No warranty</strong><p>MIT licensed software provided as-is. This is an independent tool, not official BIND or ISC software. The analyzer and guides complement, but never replace, <code>named-checkconf</code>, <code>named-checkzone</code>, <code>dig</code>/<code>delv</code>, the BIND ARM and a tested deployment process.</p></div></div>
  </section>
  `;

  view.querySelector('#clear-all-data')?.addEventListener('click', async () => {
    const { confirmDialog, toast } = await import('../ui.js');
    const { clearAllLocalData } = await import('../storage.js');
    const ok = await confirmDialog({
      title: 'Clear all local data?',
      message: 'This removes the current workspace, every snapshot and all settings from this browser. Export anything you need first. This cannot be undone.',
      confirmLabel: 'Clear everything',
    });
    if (!ok) return;
    clearAllLocalData();
    toast('All local data cleared.', 'ok');
    location.hash = '#/';
  });
  return null;
}
