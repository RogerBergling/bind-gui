/* Long-form learning library. Content is authored static HTML, never user data. */

export const ARTICLES = [
  {
    id: 'dns-mental-model',
    title: 'The DNS mental model',
    summary: 'Names, zones, RRsets, recursion and caching: the model behind every BIND decision.',
    level: 'Foundation',
    minutes: 9,
    tags: ['DNS', 'Fundamentals'],
    sections: [
      {
        id: 'names',
        title: 'Names are paths, not rows',
        html: `<p>DNS is a distributed, hierarchical database. A name such as <code>www.example.com.</code> is a path from the root (<code>.</code>) through <code>com.</code> and <code>example.com.</code> to <code>www.example.com.</code>. The trailing dot means “absolute”; without it, BIND interprets the name relative to the current <code>$ORIGIN</code>.</p>
<p>The hierarchy is split into <strong>zones</strong>. A zone is the part of the tree for which one authority is responsible. <code>example.com.</code> is a zone; <code>www.example.com.</code> is a name inside it. The zone apex owns the <code>SOA</code> and <code>NS</code> records that define the zone.</p>
<div class="callout info"><p><strong>Mental model:</strong> a zone is a file plus a delegation. The file says what is inside; the parent’s NS records say who is allowed to answer for it.</p></div>`,
      },
      {
        id: 'rrset',
        title: 'Records are grouped into RRsets',
        html: `<p>All records at the same owner, class and type form a <strong>resource record set</strong> (RRset). Two A records at <code>www.example.com.</code> are one RRset. DNSSEC signs RRsets, not individual records. Caches store RRsets, not rows.</p>
<p>This matters because a CNAME must be alone at its owner (apart from DNSSEC metadata), and because changes to any record in an RRset require the whole set to be re-signed. It also explains why “one record” is often not a useful unit of change.</p>`,
      },
      {
        id: 'resolution',
        title: 'Resolution: recursion versus authority',
        html: `<p>An <strong>authoritative server</strong> answers from zone data it owns. A <strong>recursive resolver</strong> follows referrals from the root down to the authoritative server, then caches the answer for the TTL. A <strong>stub resolver</strong> on a laptop simply asks a recursive resolver and trusts the result.</p>
<p>The same BIND binary can do both jobs, but they are different security roles. Mixing them without careful ACLs is how open resolvers appear. The safest design is usually: authoritative servers answer only their zones; dedicated resolvers recurse for known clients.</p>`,
      },
      {
        id: 'caching',
        title: 'TTL, negative caching and why changes take time',
        html: `<p>Every answer may be cached for its TTL. Negative answers (NXDOMAIN and NODATA) are cached using the SOA minimum or the negative TTL, whichever applies. This is why a deleted record can appear to “come back” after a change: an old positive answer is still cached somewhere.</p>
<p>TTL is a trade-off. Long TTLs reduce query volume and improve resilience; short TTLs make changes and rollbacks faster. During a planned migration, lower the TTL well before the change, then raise it again after the old data has expired everywhere.</p>`,
      },
      {
        id: 'flags',
        title: 'Header flags you should recognise',
        html: `<ul>
<li><strong>AA</strong> — authoritative answer. The server owns the data.</li>
<li><strong>RD</strong> — recursion desired. The client asks the server to recurse.</li>
<li><strong>RA</strong> — recursion available. The server offers recursion; it does not mean the client is allowed.</li>
<li><strong>AD</strong> — authenticated data. A validating resolver proved the DNSSEC chain for this answer.</li>
<li><strong>CD</strong> — checking disabled. The client asks the resolver not to validate. Useful for diagnosis, dangerous in production.</li>
<li><strong>TC</strong> — truncated. The client should retry over TCP (or a larger EDNS buffer).</li>
</ul>
<div class="callout warn"><p>An AD bit is only as trustworthy as the resolver that set it. On the wire, DNSSEC validation is end-to-end only if your own resolver validates.</p></div>`,
      },
    ],
  },
  {
    id: 'bind-architecture',
    title: 'How BIND is put together',
    summary: 'named, named.conf, zone files, includes, working directories and the files BIND writes.',
    level: 'Foundation',
    minutes: 8,
    tags: ['BIND', 'Architecture'],
    sections: [
      {
        id: 'process',
        title: 'The process and its files',
        html: `<p><code>named</code> is the BIND server process. It reads a configuration file (normally <code>named.conf</code>), loads zone data, establishes listeners and writes runtime state such as journals, managed keys and statistics.</p>
<p>A typical Debian/Ubuntu layout separates files by trust and writability:</p>
<ul>
<li><code>/etc/bind/named.conf</code> and includes — configuration, read-only for the service.</li>
<li><code>/etc/bind/db.*</code> — zone files, readable by the service.</li>
<li><code>/var/cache/bind</code> — writable working directory, journals, managed keys.</li>
<li><code>/var/log/named</code> — logs, if you use file channels.</li>
</ul>
<p>Containers often use <code>/etc/bind</code> and <code>/var/cache/bind</code> too, but the exact paths must match the image and the bind mount. Absolute paths are a common source of “works on the host, fails in the container”.</p>`,
      },
      {
        id: 'includes',
        title: 'Includes are textual, not modules',
        html: `<p><code>include</code> splices another file into the current context. An include inside a <code>view</code> inherits that view. An include at the top level becomes another top-level statement. BIND does not sandbox includes or merge them by name.</p>
<p>Practical consequences:</p>
<ul>
<li>A missing include is fatal.</li>
<li>Including the same file twice can create duplicate zones or duplicate options.</li>
<li>Include order matters for options that are first-wins or last-wins in your branch.</li>
<li>Relative paths depend on the <code>directory</code> option and the process working directory.</li>
</ul>
<p>BIND Workbench resolves includes inside the workspace first, then tries the configured directory, the including file’s directory and the basename. Unresolved files are reported, not silently skipped.</p>`,
      },
      {
        id: 'roles',
        title: 'Authoritative, recursive, forwarder, secondary',
        html: `<p>BIND’s role is defined by configuration, not by a separate binary:</p>
<ul>
<li><strong>Authoritative primary</strong>: owns zone files, <code>type primary</code>, transfers to secondaries.</li>
<li><strong>Authoritative secondary</strong>: <code>type secondary</code>, pulls transfers from a primary and keeps a local copy.</li>
<li><strong>Recursive resolver</strong>: <code>recursion yes</code>, restricted <code>allow-recursion</code>, cache limits, DNSSEC validation.</li>
<li><strong>Forwarder</strong>: sends queries to upstream resolvers; <code>forward only</code> or <code>first</code>.</li>
<li><strong>Hidden primary</strong>: serves transfers to secondaries but is not in the public NS set.</li>
</ul>
<p>Each role has a different threat model. A public authoritative server should not be an open resolver. A resolver should not accept untrusted dynamic updates. A hidden primary should not expose a management channel to the internet.</p>`,
      },
      {
        id: 'validation',
        title: 'What static validation can and cannot prove',
        html: `<p><code>named-checkconf</code> parses the configuration and, with <code>-z</code>, loads zones. <code>named-checkzone</code> validates a single master file, including record syntax and some semantic checks. They are the authoritative static validators and should be run with the exact BIND version used in production.</p>
<p>They do not prove that:</p>
<ul>
<li>the live delegation points at your servers;</li>
<li>the DNSSEC chain from the root is intact;</li>
<li>a firewall allows TCP/53 or UDP/53;</li>
<li>a secondary is actually transferring;</li>
<li>permissions, AppArmor/SELinux labels or container mounts are correct.</li>
</ul>
<p>BIND Workbench performs a deep structural and semantic analysis in the browser, but it always generates the exact <code>named-checkconf</code>/<code>named-checkzone</code> commands for the final gate.</p>`,
      },
    ],
  },
  {
    id: 'named-conf',
    title: 'Reading named.conf like an operator',
    summary: 'Statements, blocks, ACLs, views, zone declarations and the options that change security posture.',
    level: 'Foundation',
    minutes: 10,
    tags: ['BIND', 'Configuration'],
    sections: [
      {
        id: 'grammar',
        title: 'The grammar is small, the interactions are not',
        html: `<p>BIND configuration is a sequence of statements ending in semicolons. A statement may have a block: <code>options { … };</code>, <code>zone "example.com" { … };</code>, <code>view "internal" { … };</code>. Quoted strings are used for names, paths and secrets. Comments are <code>//</code>, <code>#</code> or <code>/* … */</code>.</p>
<pre><code>options {
  directory "/var/cache/bind";
  listen-on port 53 { 127.0.0.1; 192.0.2.53; };
  recursion no;
};</code></pre>
<p>Most outages are not grammar errors. They are semantic mismatches: a zone file name that does not match the zone, an include that loads the wrong view, an ACL that opens more than intended.</p>`,
      },
      {
        id: 'options',
        title: 'The options block is your policy surface',
        html: `<p>Start with these questions and make the answers explicit:</p>
<ul>
<li><strong>Who may query?</strong> <code>allow-query</code>, per view or zone.</li>
<li><strong>Who may recurse?</strong> <code>recursion</code> and <code>allow-recursion</code>.</li>
<li><strong>Who may transfer?</strong> <code>allow-transfer</code>, ideally with TSIG.</li>
<li><strong>Who may update?</strong> <code>update-policy</code> with keys and narrow permissions.</li>
<li><strong>Do we validate DNSSEC?</strong> <code>dnssec-validation auto</code> on resolvers.</li>
<li><strong>Where are files?</strong> <code>directory</code>, <code>key-directory</code>, <code>file</code>, <code>journal</code>.</li>
<li><strong>How do we observe it?</strong> logging, <code>statistics-channels</code>, monitoring.</li>
</ul>
<div class="callout danger"><p>The two most common serious mistakes are <code>recursion yes</code> with an unrestricted <code>allow-recursion</code>, and <code>allow-transfer { any; };</code>. Both turn a DNS server into someone else’s tool.</p></div>`,
      },
      {
        id: 'zones',
        title: 'Zone declarations and views',
        html: `<p>A zone declaration names the zone, sets its type, and points at a file. Inside a view, the same zone name can appear with different data or different access rules.</p>
<pre><code>view "internal" {
  match-clients { 10.0.0.0/8; };
  recursion yes;
  allow-recursion { 10.0.0.0/8; };
  zone "corp.example" {
    type primary;
    file "/etc/bind/db.corp.example";
  };
};</code></pre>
<p>Views are evaluated in order; the first matching view wins. A wildcard <code>match-clients { any; };</code> can accidentally become the default and hide a later view. Test every client network, including IPv6.</p>`,
      },
      {
        id: 'acl',
        title: 'ACLs: reuse, negation and review',
        html: `<p>An ACL is a named list of match elements. Predefined ACLs include <code>any</code>, <code>none</code>, <code>localhost</code>, <code>localnets</code> and others. You can nest ACLs and negate entries with <code>!</code>.</p>
<pre><code>acl "resolver-clients" {
  127.0.0.1;
  10.20.0.0/16;
  !10.20.99.0/24;
  key "resolver-client-key";
};</code></pre>
<p>Negation and ordering are easy to misread. Write a test matrix: an address inside, outside and in the excluded range. Then test the actual BIND version, because ACL evaluation details can differ around keys and nested blocks.</p>`,
      },
      {
        id: 'review',
        title: 'A review checklist for any named.conf',
        html: `<ol>
<li>Run <code>named-checkconf -z</code> with the production binary.</li>
<li>Trace every include and confirm the context.</li>
<li>Check listen addresses and firewall coverage for IPv4 and IPv6.</li>
<li>Confirm recursion, cache and transfer policy.</li>
<li>Confirm dynamic update authentication and journals.</li>
<li>Confirm DNSSEC validation and key storage.</li>
<li>Confirm logging, statistics and rndc protection.</li>
<li>Confirm paths, permissions and container mounts.</li>
<li>Compare the change with the previous version and have a rollback.</li>
</ol>`,
      },
    ],
  },
  {
    id: 'zone-files',
    title: 'Zone files from first principles',
    summary: '$ORIGIN, $TTL, relative names, parentheses, omitted owners and the mistakes that follow.',
    level: 'Foundation',
    minutes: 9,
    tags: ['Zone file', 'Syntax'],
    sections: [
      {
        id: 'directives',
        title: '$ORIGIN and $TTL',
        html: `<p><code>$ORIGIN</code> sets the suffix used for relative names. <code>$TTL</code> sets the default TTL for records that do not specify one. Both apply from the point they appear until changed.</p>
<pre><code>$ORIGIN example.com.
$TTL 3600
@  IN SOA ns1.example.com. hostmaster.example.com. (
     2026110501 3600 900 1209600 300 )
@  IN NS  ns1.example.com.
www IN A  192.0.2.80</code></pre>
<p><code>@</code> means the current origin. A name without a trailing dot is relative: <code>www</code> becomes <code>www.example.com.</code>. A trailing dot makes it absolute.</p>`,
      },
      {
        id: 'owners',
        title: 'Omitted owners and multi-line records',
        html: `<p>If a line begins with whitespace, the owner is omitted and the previous owner is reused. This is common in SOA records and in MX/TXT sets. Parentheses let a record span lines; semicolons start comments.</p>
<pre><code>@ IN SOA ns1.example.com. hostmaster.example.com. (
  2026110501 ; serial
  3600       ; refresh
  900        ; retry
  1209600    ; expire
  300 )      ; negative caching TTL

  IN NS ns1.example.com.
  IN NS ns2.example.com.</code></pre>
<p>The second and third lines intentionally inherit the owner <code>@</code>. If you add a new record without an owner by accident, it may attach to the wrong name.</p>`,
      },
      {
        id: 'semantics',
        title: 'Semantic rules the parser enforces',
        html: `<ul>
<li>Exactly one SOA at the zone apex.</li>
<li>At least one NS at the apex; two or more for resilience.</li>
<li>An in-zone NS target needs A/AAAA glue.</li>
<li>CNAME cannot coexist with other data and cannot be at the apex.</li>
<li>MX, NS and SRV targets must not be CNAMEs.</li>
<li>Records outside the zone origin are ignored by BIND, so they are errors in this app.</li>
<li>TXT strings are limited to 255 octets each; split long values into multiple strings.</li>
<li>TTL and SOA timers must be within valid ranges.</li>
</ul>
<div class="callout info"><p><code>named-checkzone</code> is the final authority for syntax. The app’s analyzer adds operational checks that named-checkzone does not attempt, such as delegation consistency and DNSSEC hygiene.</p></div>`,
      },
      {
        id: 'generate',
        title: '$INCLUDE and $GENERATE',
        html: `<p><code>$INCLUDE</code> inserts another master file, optionally with a new origin. The origin and current owner revert after the include. <code>$GENERATE</code> expands a range into records, with <code>$</code> and <code>\${offset,width,base}</code> substitutions.</p>
<pre><code>$GENERATE 1-20 dhcp-$ A 10.20.0.$
$GENERATE 0-255 host-\${0,3,d} A 192.0.2.$</code></pre>
<p>Generated records are real records to BIND, but they are easy to forget during reviews. The app expands them and counts them, so the exported bundle and the analysis show what will actually exist.</p>`,
      },
    ],
  },
  {
    id: 'records',
    title: 'Record types and when to use them',
    summary: 'A practical guide to A, AAAA, CNAME, MX, TXT, SRV, CAA, SVCB/HTTPS and the rules that connect them.',
    level: 'Foundation',
    minutes: 11,
    tags: ['Records', 'DNS'],
    sections: [
      {
        id: 'address',
        title: 'Address records: A and AAAA',
        html: `<p>A and AAAA are the final answers for most names. Publish both only when the service actually listens on both families. Multiple addresses at one owner form an RRset and clients may choose any of them; this is not a priority list.</p>
<p>Reverse DNS is separate. A PTR for an address belongs in the reverse zone and should point at a name whose forward A/AAAA contains that same address. Mail systems often require forward-confirmed reverse DNS.</p>`,
      },
      {
        id: 'aliases',
        title: 'Aliases: CNAME and DNAME',
        html: `<p>A CNAME says “this name is an alias; use the target instead”. It must be the only ordinary data at its owner and cannot be at the zone apex. DNSSEC metadata (RRSIG/NSEC) may coexist with it.</p>
<p>DNAME redirects a whole subtree by synthesizing CNAMEs. It is powerful and rarely needed. Test the complete subtree, including names that do not exist yet, before deploying it.</p>
<div class="callout warn"><p>Never point MX, NS or SRV targets at a CNAME. Some software tolerates it, but the standards do not, and failure modes are subtle.</p></div>`,
      },
      {
        id: 'mail',
        title: 'Mail: MX, SPF, DKIM, DMARC',
        html: `<p>MX names the mail exchangers; lower preference wins. SPF, DKIM and DMARC are TXT-based policies, not MX replacements:</p>
<ul>
<li><strong>SPF</strong> — one TXT record at the apex, for example <code>v=spf1 mx -all</code>.</li>
<li><strong>DKIM</strong> — a TXT record at <code>selector._domainkey</code> with a public key.</li>
<li><strong>DMARC</strong> — a TXT record at <code>_dmarc</code> with policy and reporting addresses.</li>
</ul>
<p>Publishing an obsolete SPF RR type does not configure SPF; receivers read TXT. Keep exactly one SPF policy.</p>`,
      },
      {
        id: 'service',
        title: 'Service discovery: SRV, SVCB, HTTPS',
        html: `<p>SRV advertises a target, port, priority and weight. SVCB and HTTPS describe service endpoints and parameters for modern clients, including HTTP/3 and ECH. Both have strict syntax and both are easy to break with a single missing dot.</p>
<pre><code>_sip._tcp 3600 IN SRV 10 60 5060 sip1.example.com.
www 3600 IN HTTPS 1 . alpn=h2,h3</code></pre>
<p>Test with the real client, not only dig. A record can be syntactically valid and still direct clients somewhere useless.</p>`,
      },
      {
        id: 'security',
        title: 'Security records: CAA, TLSA, SSHFP',
        html: `<p>CAA restricts which CAs may issue certificates. TLSA and SSHFP bind certificates or SSH host keys to names through DNS. TLSA/SSHFP are only trustworthy with DNSSEC validation; without it they are just assertions from the same channel an attacker may control.</p>
<p>Publish a CAA policy for the CAs you actually use and include an <code>iodef</code> contact. For TLSA, always publish the next certificate’s association before rotating the current one.</p>`,
      },
    ],
  },
  {
    id: 'soa-ns-ttl',
    title: 'SOA, NS and TTL: the timers that run your zone',
    summary: 'Serials, refresh/retry/expire, negative caching, apex NS redundancy and safe TTL changes.',
    level: 'Intermediate',
    minutes: 9,
    tags: ['SOA', 'TTL', 'Operations'],
    sections: [
      {
        id: 'soa',
        title: 'The SOA fields',
        html: `<p>The SOA is a compact operational contract:</p>
<ul>
<li><strong>MNAME</strong> — the primary server name. It should normally be an apex NS.</li>
<li><strong>RNAME</strong> — the responsible mailbox as a DNS name: <code>hostmaster.example.com.</code>, not <code>hostmaster@example.com</code>.</li>
<li><strong>SERIAL</strong> — the zone version. It must increase on every publish.</li>
<li><strong>REFRESH</strong> — how often a secondary checks the primary.</li>
<li><strong>RETRY</strong> — how long a secondary waits after a failed check.</li>
<li><strong>EXPIRE</strong> — how long a secondary keeps serving after it can no longer reach the primary.</li>
<li><strong>MINIMUM</strong> — the negative-caching TTL (and historically the default TTL).</li>
</ul>`,
      },
      {
        id: 'timers',
        title: 'Choosing timers',
        html: `<p>There is no universal correct set, but common starting points are:</p>
<table class="doc-table"><thead><tr><th>Field</th><th>Typical</th><th>Reason</th></tr></thead><tbody>
<tr><td>REFRESH</td><td>1h–12h</td><td>Fast enough for changes, slow enough not to hammer the primary.</td></tr>
<tr><td>RETRY</td><td>5m–1h</td><td>Retry sooner than the next refresh, but not in a tight loop.</td></tr>
<tr><td>EXPIRE</td><td>1–4 weeks</td><td>Keep a secondary serving during a primary outage.</td></tr>
<tr><td>MINIMUM</td><td>5m–1h</td><td>Bound negative caching so mistakes do not live for days.</td></tr>
</tbody></table>
<p>If <code>EXPIRE</code> is shorter than <code>REFRESH + RETRY</code>, a secondary can stop answering during a normal jitter window. That is a common self-inflicted outage.</p>`,
      },
      {
        id: 'serial',
        title: 'Serial strategy',
        html: `<p>Use a monotonic value. <code>YYYYMMDDnn</code> is human-readable and works for most teams: <code>2026110501</code>, then <code>2026110502</code>. If you publish more than 99 times a day, use a counter or epoch seconds. Never let the serial wrap or go backwards; secondaries may ignore the update or enter a transfer loop.</p>
<div class="callout info"><p>This app cannot know whether the serial increased compared with production. Compare against a saved version or your change record before publishing.</p></div>`,
      },
      {
        id: 'ttl',
        title: 'TTL strategy and safe changes',
        html: `<p>TTL controls how long the world may keep an old answer. For a planned change:</p>
<ol>
<li>Lower the TTL well in advance (at least the old TTL duration).</li>
<li>Wait for the old TTL to expire everywhere that matters.</li>
<li>Make the change.</li>
<li>Verify with multiple resolvers and authoritative servers.</li>
<li>Raise the TTL after the new answer is stable.</li>
</ol>
<p>For rollback, the old TTL also applies. A short TTL is not a substitute for a tested change; it only shortens the window of stale data.</p>`,
      },
      {
        id: 'ns',
        title: 'Apex NS and redundancy',
        html: `<p>Publish at least two apex NS records on independent infrastructure. A single NS is a single point of failure even if the server is reliable. In-bailiwick NS targets need glue A/AAAA in the same zone. Out-of-bailiwick targets need their own authoritative resolution.</p>
<p>The parent delegation NS set and the child apex NS set should match. Mismatches are a common cause of “it works from one resolver but not another”.</p>`,
      },
    ],
  },
  {
    id: 'delegation',
    title: 'Delegation, glue and zone cuts',
    summary: 'How authority moves from parent to child, why glue exists and how DS records complete the picture.',
    level: 'Intermediate',
    minutes: 8,
    tags: ['Delegation', 'DNSSEC'],
    sections: [
      {
        id: 'cut',
        title: 'The zone cut',
        html: `<p>A delegation is a pair of NS records in the parent zone at the child name. The parent remains authoritative for everything above and around the cut, but not for data at or below the child apex (except glue and DS).</p>
<pre><code>; parent example.com zone
child   IN NS ns1.child.example.com.
child   IN NS ns2.other.example.net.
ns1.child IN A 192.0.2.80   ; glue, because ns1 is inside child</code></pre>
<p><code>ns1.child.example.com.</code> is in-bailiwick: resolving it would require the child, which requires ns1. Glue breaks the loop. <code>ns2.other.example.net.</code> is out-of-bailiwick and does not need glue in this zone.</p>`,
      },
      {
        id: 'glue',
        title: 'Glue rules',
        html: `<ul>
<li>Glue is needed only for NS targets inside the delegated child.</li>
<li>Glue is authoritative data in the parent, not the child, even though it names a child host.</li>
<li>Keep glue synchronized with the child’s A/AAAA records.</li>
<li>Do not put arbitrary records below a delegation in the parent; they are not authoritative and may be ignored.</li>
</ul>
<p>Missing glue produces SERVFAIL or timeouts. Wrong glue produces intermittent failures that depend on cache state.</p>`,
      },
      {
        id: 'ds',
        title: 'DS: the DNSSEC hand-off',
        html: `<p>A DS record in the parent commits to a DNSKEY in the child. The chain is:</p>
<pre><code>root trust anchor
  → root DNSKEY (validated locally)
  → com DS (signed by root)
  → com DNSKEY
  → example.com DS (signed by com)
  → example.com DNSKEY
  → www.example.com A (signed by example.com ZSK)</code></pre>
<p>A missing DS means “insecure delegation”: the child may be signed, but validators do not use that signature. A wrong DS means “bogus”: every signed answer under the child fails validation until the DS is fixed.</p>`,
      },
      {
        id: 'operations',
        title: 'Changing a delegation safely',
        html: `<ol>
<li>Confirm the child NS servers answer authoritatively for the child apex.</li>
<li>Publish the child apex NS set before changing the parent.</li>
<li>If DNSSEC is involved, publish the child DNSKEY and the new DS in the correct order.</li>
<li>Keep the old DS valid until caches have expired.</li>
<li>Verify from multiple resolvers and from the parent and child authoritative servers.</li>
<li>Watch for lame delegation and DNSSEC bogus responses.</li>
</ol>`,
      },
    ],
  },
  {
    id: 'dnssec-chain',
    title: 'DNSSEC: the chain of trust',
    summary: 'DNSKEY, DS, RRSIG, NSEC/NSEC3, AD and what “secure”, “insecure”, “bogus” actually mean.',
    level: 'Advanced',
    minutes: 12,
    tags: ['DNSSEC', 'Security'],
    sections: [
      {
        id: 'why',
        title: 'What DNSSEC does and does not do',
        html: `<p>DNSSEC adds origin authentication and integrity: a validating resolver can prove that an answer was signed by the zone that owns the data and was not modified in transit. It does <strong>not</strong> provide confidentiality. Queries and answers are still visible on the wire unless you also use DoT/DoH.</p>
<p>It also does not make a wrong record right. A signed typo is still a typo. DNSSEC protects against forgery, not against operational mistakes.</p>`,
      },
      {
        id: 'keys',
        title: 'Keys and signatures',
        html: `<ul>
<li><strong>DNSKEY</strong> — public keys at the zone apex. Flags 256 = ZSK, 257 = KSK/SEP.</li>
<li><strong>RRSIG</strong> — a signature over one RRset, with algorithm, key tag, signer and validity window.</li>
<li><strong>DS</strong> — parent-side digest of a child KSK. This is where trust crosses the delegation.</li>
<li><strong>NSEC / NSEC3</strong> — authenticated denial of existence.</li>
</ul>
<p>A zone signs its data with a ZSK and signs the DNSKEY RRset with a KSK. The parent publishes a DS for the KSK. Validators build the chain from a trust anchor (normally the root KSK) down to the answer.</p>`,
      },
      {
        id: 'states',
        title: 'Secure, insecure, bogus, indeterminate',
        html: `<ul>
<li><strong>Secure</strong> — a complete chain of valid signatures from a trust anchor.</li>
<li><strong>Insecure</strong> — no DS at some delegation; the data may be signed, but the chain intentionally stops.</li>
<li><strong>Bogus</strong> — a DS exists but validation fails (missing/expired signature, wrong key, wrong DS, algorithm issue).</li>
<li><strong>Indeterminate</strong> — the resolver cannot determine the state, often due to a network failure or unsupported algorithm.</li>
</ul>
<div class="callout danger"><p>A bogus zone is usually a total outage for validating clients. Monitor DNSSEC expiry and DS/key changes like you monitor certificate expiry.</p></div>`,
      },
      {
        id: 'denial',
        title: 'NSEC vs NSEC3',
        html: `<p>DNSSEC must also prove that a name or type does not exist. NSEC links names in canonical order; it is simple but allows zone walking. NSEC3 hashes names; it makes walking harder but costs CPU and adds complexity. RFC 9276 recommends zero additional iterations for new deployments.</p>
<p>BIND can manage denial-of-existence through <code>dnssec-policy</code>. Do not hand-edit NSEC/NSEC3 records in an inline-signed zone; the server owns them.</p>`,
      },
      {
        id: 'verify',
        title: 'Verifying the chain from the outside',
        html: `<p>Use the Live DNS page or run:</p>
<pre><code>dig @1.1.1.1 example.com DS +dnssec +multi
dig @1.1.1.1 example.com DNSKEY +dnssec +multi
dig @1.1.1.1 www.example.com A +dnssec +comments</code></pre>
<p>The <code>ad</code> flag means the resolver validated the answer. The app additionally recomputes the DS digest against the published DNSKEY, so you can see whether the parent DS and child key actually agree. This is stronger than looking at AD alone, but it is still not a substitute for validating with your own resolver and monitoring.</p>`,
      },
    ],
  },
  {
    id: 'dnssec-operations',
    title: 'Running DNSSEC without an outage',
    summary: 'Policies, key rollover, algorithms, signature timing, inline signing and the operational traps.',
    level: 'Advanced',
    minutes: 12,
    tags: ['DNSSEC', 'Operations'],
    sections: [
      {
        id: 'policy',
        title: 'Policy-driven signing',
        html: `<p>Modern BIND uses <code>dnssec-policy</code> to define algorithms, key lifetimes, signing intervals and denial-of-existence parameters. The zone references the policy:</p>
<pre><code>dnssec-policy "default" {
  keys {
    ksk lifetime unlimited algorithm ecdsap256sha256;
    zsk lifetime 90d algorithm ecdsap256sha256;
  };
};

zone "example.com" {
  type primary;
  file "db.example.com";
  dnssec-policy "default";
  inline-signing yes;
};</code></pre>
<p>BIND maintains keys and signatures in <code>key-directory</code>. That directory must be writable by BIND and protected from other users.</p>`,
      },
      {
        id: 'rollover',
        title: 'KSK and ZSK rollover',
        html: `<p>A ZSK rollover is local: publish the new ZSK, sign, wait for caches, retire the old key. A KSK rollover crosses the parent DS and is the risky part.</p>
<ol>
<li>Generate the new KSK and publish its DNSKEY.</li>
<li>Generate the new DS and publish it in the parent alongside the old DS.</li>
<li>Wait for the old DS TTL and resolver caches.</li>
<li>Switch signing to the new KSK.</li>
<li>Remove the old DS, then the old DNSKEY.</li>
</ol>
<p>Keep a rollback window. Monitoring must cover both the DS and the DNSKEY during the transition.</p>`,
      },
      {
        id: 'algorithms',
        title: 'Algorithms and key sizes',
        html: `<p>For new deployments, ECDSAP256SHA256 (13) is a strong default; Ed25519 (15) is compact and fast where supported. RSASHA256 (8) is widely supported but larger; use at least 2048-bit keys. RSASHA1 and DSA are legacy and should be migrated.</p>
<p>Algorithm 13/15 reduces response size and CPU cost compared with RSA. Check resolver and registry support before choosing a less common algorithm.</p>`,
      },
      {
        id: 'expiry',
        title: 'Signature validity and monitoring',
        html: `<p>RRSIG expiration is an outage timer. Monitor it like a certificate: warn well before expiry and alert on failures. BIND’s policy-driven signing refreshes signatures automatically, but the monitoring still matters because a broken signer, key or disk can stop the process.</p>
<ul>
<li>Track the earliest RRSIG expiry per zone.</li>
<li>Alert on <code>dnssec-policy</code> key events and failures.</li>
<li>Check <code>rndc dnssec -status <zone></code> regularly.</li>
<li>Test a restore from backup, not just a backup.</li>
</ul>`,
      },
      {
        id: 'traps',
        title: 'Common DNSSEC traps',
        html: `<ul>
<li>Publishing a DS before the child is signed, or after the key was removed.</li>
<li>Changing algorithms without a planned rollover.</li>
<li>Hand-editing NSEC/NSEC3 in an inline-signed zone.</li>
<li>Losing the key directory on container restart.</li>
<li>Forgetting that <code>allow-transfer</code> also needs to protect signed zones.</li>
<li>Assuming a valid AD bit from a public resolver proves your own resolver is healthy.</li>
<li>Using NSEC3 with high iteration counts on a busy zone.</li>
</ul>`,
      },
    ],
  },
  {
    id: 'recursion-security',
    title: 'Recursion, caching and open-resolver defense',
    summary: 'Why open resolvers are dangerous, how to scope recursion, and how to defend the cache.',
    level: 'Intermediate',
    minutes: 9,
    tags: ['Security', 'Recursion'],
    sections: [
      {
        id: 'risk',
        title: 'What an open resolver gives an attacker',
        html: `<p>A recursive resolver will do work on behalf of anyone who can reach it. That means:</p>
<ul>
<li><strong>Amplification/reflection</strong> — small spoofed queries produce larger answers aimed at a victim.</li>
<li><strong>Cache probing</strong> — an attacker can discover which internal names resolve.</li>
<li><strong>Resource exhaustion</strong> — random or deep names consume CPU, memory and upstream bandwidth.</li>
<li><strong>Reputation damage</strong> — your IP appears in abuse reports and blocklists.</li>
</ul>
<div class="callout danger"><p>If <code>recursion yes</code> is set and <code>allow-recursion</code> is missing or contains <code>any</code>, assume the resolver is open until proven otherwise from an external network.</p></div>`,
      },
      {
        id: 'scope',
        title: 'Scope recursion to real clients',
        html: `<pre><code>options {
  recursion yes;
  allow-recursion { localhost; localnets; 10.20.0.0/16; };
  allow-query-cache { localhost; localnets; 10.20.0.0/16; };
  max-cache-size 512m;
  max-recursion-queries 100;
  max-recursion-depth 10;
};</code></pre>
<p>An authoritative-only server should use <code>recursion no;</code>. If it must answer both roles, use views and separate policies rather than one broad rule.</p>`,
      },
      {
        id: 'cache',
        title: 'Cache protections',
        html: `<ul>
<li>Use random source ports and unpredictable query IDs (BIND does this by default).</li>
<li>Keep DNSSEC validation enabled to reject forged data.</li>
<li>Set <code>max-cache-size</code> and monitor eviction.</li>
<li>Consider QNAME minimisation, DNS cookies and response rate limiting.</li>
<li>Patch promptly; resolver bugs are high-impact.</li>
<li>Do not forward internal names to public resolvers.</li>
</ul>`,
      },
      {
        id: 'testing',
        title: 'Testing from the outside',
        html: `<p>From a network that should not have recursion:</p>
<pre><code>dig @203.0.113.53 example.com A +recurse
dig @203.0.113.53 isc.org A +recurse</code></pre>
<p>If you get a recursive answer, the ACL is wrong. Test IPv4 and IPv6, and test from every client class you intend to allow. Remember that firewalls can hide an open resolver from you while leaving it exposed to the internet.</p>`,
      },
    ],
  },
  {
    id: 'transfers-tsig',
    title: 'Zone transfers, TSIG and secondaries',
    summary: 'AXFR/IXFR, NOTIFY, hidden primaries, transfer ACLs and how to authenticate replication.',
    level: 'Intermediate',
    minutes: 9,
    tags: ['Transfers', 'TSIG', 'Replication'],
    sections: [
      {
        id: 'flow',
        title: 'How replication works',
        html: `<ol>
<li>The primary changes its serial and sends NOTIFY to the NS set (and <code>also-notify</code> targets).</li>
<li>A secondary checks the primary’s SOA serial.</li>
<li>If the serial is newer, the secondary requests IXFR; the primary may answer with a delta or fall back to AXFR.</li>
<li>The secondary writes the zone and journal, then serves it authoritatively.</li>
<li>If the primary is unreachable, the secondary keeps serving until EXPIRE.</li>
</ol>
<p>TSIG can authenticate the transfer. The key name and secret must match on both sides, and the primary’s <code>allow-transfer</code> must permit the key.</p>`,
      },
      {
        id: 'policy',
        title: 'A safe transfer policy',
        html: `<pre><code>key "xfr-key" {
  algorithm hmac-sha256;
  secret "BASE64-SECRET";
};

options {
  allow-transfer { none; };
};

zone "example.com" {
  type primary;
  file "/etc/bind/db.example.com";
  allow-transfer { 192.0.2.54; key "xfr-key"; };
};</code></pre>
<p>Use <code>none</code> globally, then opt in per zone. If a secondary is behind NAT or uses multiple source addresses, document and test the exact addresses. Prefer TSIG over source-address trust.</p>`,
      },
      {
        id: 'hidden',
        title: 'Hidden primary and multi-primary',
        html: `<p>A hidden primary is not listed in the public NS set; only secondaries transfer from it. This protects the primary from direct queries and gives you a smaller attack surface. The secondaries are public and must be hardened and monitored.</p>
<p>Multi-primary setups exist, but they introduce serial conflict and update-routing complexity. Use them only with a clear write model. Catalog zones can automate provisioning, but they also turn the catalog into a control plane.</p>`,
      },
      {
        id: 'troubleshoot',
        title: 'Troubleshooting transfers',
        html: `<ul>
<li><code>rndc status</code> and <code>rndc zonestatus example.com</code> show the zone state.</li>
<li>Check that the secondary can reach the primary on TCP/53; AXFR uses TCP.</li>
<li>Check the primary’s logs for “transfer of … denied”.</li>
<li>Verify TSIG key names, algorithms and clocks.</li>
<li>Look for journal corruption or a full disk.</li>
<li>Compare serials with <code>dig @primary example.com SOA</code> and <code>dig @secondary example.com SOA</code>.</li>
</ul>`,
      },
    ],
  },
  {
    id: 'views-rpz',
    title: 'Views, split horizon and RPZ',
    summary: 'Serving different answers to different clients, and using response policy zones safely.',
    level: 'Advanced',
    minutes: 9,
    tags: ['Views', 'RPZ', 'Policy'],
    sections: [
      {
        id: 'views',
        title: 'Views are ordered policy scopes',
        html: `<p>A view combines <code>match-clients</code>, optional <code>match-destinations</code>, recursion policy and zones. BIND evaluates views in order and uses the first match. A catch-all view can make later views unreachable.</p>
<pre><code>view "internal" {
  match-clients { 10.0.0.0/8; };
  recursion yes;
  allow-recursion { 10.0.0.0/8; };
  zone "corp.example" { type primary; file "db.corp.example"; };
};

view "external" {
  match-clients { any; };
  recursion no;
  zone "example.com" { type primary; file "db.example.com.external"; };
};</code></pre>
<p>Test source addresses from every network, including IPv6 and NAT boundaries. A view mistake can expose internal zones or hide public ones.</p>`,
      },
      {
        id: 'rpz',
        title: 'Response Policy Zones',
        html: `<p>RPZ is a DNS firewall. A policy zone can block a name (NXDOMAIN), return a fixed address, or rewrite a CNAME. It is useful for malware blocking and local policy, especially on recursive resolvers.</p>
<pre><code>options {
  response-policy { zone "rpz.example"; };
};</code></pre>
<p>RPZ requires recursion and a zone that is updated like any other. Test with <code>qname-wait-recurse</code> and observe-only modes. A bad feed can break legitimate services, so monitor policy hit rates and allow an emergency bypass.</p>`,
      },
      {
        id: 'safety',
        title: 'Split-horizon safety rules',
        html: `<ul>
<li>Keep internal and external zone files separate and reviewed independently.</li>
<li>Do not use the same SOA serial logic for both if they diverge; track versions per view.</li>
<li>Make the default view explicit and test the fallback.</li>
<li>Ensure DNSSEC signing matches the data each view serves.</li>
<li>Document which clients are expected to see which answer.</li>
<li>Monitor for unexpected view selection after network changes.</li>
</ul>`,
      },
    ],
  },
  {
    id: 'operations',
    title: 'Operating BIND: logs, metrics, reloads and incident response',
    summary: 'What to log, what to measure, how to reload safely and how to investigate DNS failures.',
    level: 'Intermediate',
    minutes: 9,
    tags: ['Operations', 'Monitoring', 'Troubleshooting'],
    sections: [
      {
        id: 'logging',
        title: 'Logging that earns its disk space',
        html: `<p>At minimum, route <code>default</code>, <code>security</code>, <code>xfer-out</code>, <code>xfer-in</code>, <code>dnssec</code> and <code>update</code> to a bounded channel. Add <code>queries</code> only temporarily or with strict retention.</p>
<pre><code>logging {
  channel main {
    file "/var/log/named/main.log" versions 5 size 20m;
    severity info;
    print-time yes;
    print-category yes;
    print-severity yes;
  };
  category default { main; };
  category security { main; };
  category dnssec { main; };
  category xfer-out { main; };
  category update { main; };
};</code></pre>
<p>Protect log integrity. Query logs can contain personal data and internal names.</p>`,
      },
      {
        id: 'metrics',
        title: 'Metrics that matter',
        html: `<ul>
<li>Query rate, cache hit ratio and cache memory.</li>
<li>SERVFAIL, REFUSED and FORMERR rates.</li>
<li>DNSSEC validation failures and signature expiry.</li>
<li>Zone transfer success/failure and serial lag.</li>
<li>Recursion limit hits and rate-limit drops.</li>
<li>Disk space for journals, keys and logs.</li>
<li>Process health, file descriptors and CPU.</li>
</ul>
<p><code>statistics-channels</code> exposes JSON/XML; scrape it from a protected management path. Alert on trends, not just hard failures.</p>`,
      },
      {
        id: 'reload',
        title: 'Reload versus restart',
        html: `<p><code>rndc reload</code> reloads configuration and zones without dropping the process. <code>rndc reconfig</code> reloads named.conf and new zones. A restart is heavier and drops caches. Always validate first:</p>
<pre><code>named-checkconf -z /etc/bind/named.conf
rndc reload
rndc status
rndc zonestatus example.com</code></pre>
<p>If a reload fails, the old configuration may keep serving. Read the logs; do not assume success because the command returned zero.</p>`,
      },
      {
        id: 'incident',
        title: 'Incident response for DNS',
        html: `<ol>
<li>Confirm scope: one name, one zone, one resolver or everything?</li>
<li>Check authoritative answers with <code>dig +norecurse</code> against each NS.</li>
<li>Check the parent delegation and DS.</li>
<li>Check DNSSEC with <code>delv</code> or <code>dig +dnssec</code> and look at AD/SERVFAIL.</li>
<li>Check transfer state and serials on secondaries.</li>
<li>Check logs for REFUSED, transfer failures and DNSSEC errors.</li>
<li>If you changed something, compare with the previous version and roll back if the old state was healthy.</li>
</ol>`,
      },
    ],
  },
  {
    id: 'hardening',
    title: 'A practical BIND hardening baseline',
    summary: 'Recursion, transfers, updates, version disclosure, management channels, rate limits and least privilege.',
    level: 'Intermediate',
    minutes: 10,
    tags: ['Security', 'Hardening'],
    sections: [
      {
        id: 'baseline',
        title: 'The baseline',
        html: `<ul>
<li><code>version none;</code> and a patched BIND.</li>
<li>Explicit <code>listen-on</code> / <code>listen-on-v6</code>; firewall both families.</li>
<li>Authoritative-only: <code>recursion no;</code>.</li>
<li>Resolver: <code>allow-recursion</code>, <code>allow-query-cache</code>, cache and recursion limits.</li>
<li><code>allow-transfer { none; };</code> globally, then explicit secondary/TSIG ACLs.</li>
<li><code>update-policy</code> with narrow names/types and dedicated keys; never <code>allow-update { any; };</code>.</li>
<li><code>dnssec-validation auto;</code> on resolvers; DNSSEC policy on authoritative zones.</li>
<li>Protected <code>controls</code> and <code>statistics-channels</code>.</li>
<li>Bounded logging and monitoring.</li>
<li>Rate limiting and RPZ where appropriate.</li>
</ul>`,
      },
      {
        id: 'secrets',
        title: 'Secrets and file permissions',
        html: `<p>TSIG secrets and DNSSEC private keys are credentials. They must not be world-readable, committed to Git or baked into container images. Use a secret manager or mounted files with restrictive permissions, and rotate them.</p>
<ul>
<li>TSIG files: <code>0600</code>, owned by the BIND user.</li>
<li>Key directory: <code>0700</code>, no shared group access unless required.</li>
<li>Configuration: read-only for the service, writable only through change control.</li>
<li>Backups: encrypted, access-controlled and tested.</li>
</ul>`,
      },
      {
        id: 'network',
        title: 'Network and host controls',
        html: `<p>BIND is not a firewall. Put DNS behind network policy:</p>
<ul>
<li>Allow UDP/TCP 53 only from intended clients or the internet for public authoritative service.</li>
<li>Restrict rndc/statistics to a management network.</li>
<li>Do not expose the key directory or configuration over HTTP.</li>
<li>Run as a non-root user with a read-only root filesystem where possible.</li>
<li>Use AppArmor/SELinux profiles and a hardened systemd unit.</li>
<li>Patch BIND promptly and subscribe to ISC security announcements.</li>
</ul>`,
      },
      {
        id: 'review',
        title: 'Review triggers',
        html: `<p>Re-run the analyzer and external checks after every change, and at least on a fixed cadence:</p>
<ul>
<li>zone or delegation changes;</li>
<li>DNSSEC key/DS rollover;</li>
<li>BIND upgrade;</li>
<li>network or firewall change;</li>
<li>new view, RPZ feed or catalog zone;</li>
<li>incident or abuse report.</li>
</ul>`,
      },
    ],
  },
  {
    id: 'change-workflow',
    title: 'A safe change workflow for DNS',
    summary: 'Import, compare, analyze, validate, export, deploy and verify without guessing.',
    level: 'Foundation',
    minutes: 7,
    tags: ['Workflow', 'Operations'],
    sections: [
      {
        id: 'workflow',
        title: 'The loop',
        html: `<pre><code>Import → inspect → analyze → compare → edit → export → named-checkconf/zone
   → stage → reload → verify live → record the result</code></pre>
<p>BIND Workbench is built around this loop:</p>
<ol>
<li><strong>Import</strong> named.conf and every included zone file, preserving paths.</li>
<li><strong>Inspect</strong> the file tree, includes, zones and records.</li>
<li><strong>Analyze</strong> syntax, security, delegation and DNSSEC.</li>
<li><strong>Compare</strong> the proposed files with the current production version.</li>
<li><strong>Export</strong> the multi-file bundle plus a manifest and validation script.</li>
<li><strong>Validate</strong> with the exact BIND binary using <code>named-checkconf</code> and <code>named-checkzone</code>.</li>
<li><strong>Deploy</strong> with a reviewed change, reload and rollback path.</li>
<li><strong>Verify</strong> authoritative and recursive answers, DNSSEC AD, and propagation.</li>
</ol>`,
      },
      {
        id: 'compare',
        title: 'Compare semantically, not only visually',
        html: `<p>A line diff is necessary but not sufficient. The app also compares zone records by owner, type and canonical RDATA, so it can show:</p>
<ul>
<li>records added or removed;</li>
<li>TTL changes;</li>
<li>SOA serial changes;</li>
<li>directive-level named.conf changes.</li>
</ul>
<p>This catches reordered files that are semantically identical, and highlights a serial change even when the surrounding text moved.</p>`,
      },
      {
        id: 'export',
        title: 'Export the whole bundle',
        html: `<p>The export includes the original files, a SHA-256 manifest, <code>validate.sh</code>, <code>VALIDATE.md</code> and <code>VERIFY.md</code>. The validation script is intentionally simple: it runs <code>named-checkconf -z</code> and <code>named-checkzone</code> per zone. It does not reload or mutate anything.</p>
<p>Always review the script and manifest. Absolute paths and permissions are environment-specific; the bundle is not a deployment system.</p>`,
      },
      {
        id: 'rules',
        title: 'Non-negotiable rules',
        html: `<ul>
<li>Never edit production without a saved previous version.</li>
<li>Never skip named-checkconf/named-checkzone because the browser analyzer passed.</li>
<li>Never copy a zone over a running server without considering journal and DNSSEC state.</li>
<li>Never treat cached public resolver answers as authoritative truth.</li>
<li>Never put secrets in a configuration you might share or commit.</li>
<li>Have a rollback and test it.</li>
</ul>`,
      },
    ],
  },
  {
    id: 'advanced-bind',
    title: 'Advanced BIND features worth knowing',
    summary: 'Dynamic updates, catalog zones, inline signing, DNS cookies, DoT/DoH and modern automation.',
    level: 'Advanced',
    minutes: 9,
    tags: ['BIND', 'Advanced'],
    sections: [
      {
        id: 'dynamic',
        title: 'Dynamic updates and journals',
        html: `<p><code>allow-update</code> or <code>update-policy</code> enables RFC 2136 changes. Updates go through a journal; the master file may not change until BIND rewrites it. Use TSIG, narrow name/type permissions, a dedicated key per client and a tested journal backup.</p>
<pre><code>update-policy {
  grant "dhcp-key" self *.dhcp.example.com. A AAAA PTR;
};</code></pre>
<p>Never expose dynamic updates without authentication. Never assume the on-disk text file reflects the current state while the journal is active.</p>`,
      },
      {
        id: 'catalog',
        title: 'Catalog zones and fleet automation',
        html: `<p>Catalog zones automate zone provisioning. A catalog zone lists member zones and their properties; primaries and secondaries create or remove zones from that list. This is powerful for large fleets, but it turns DNS data into a control plane. Restrict transfers/updates with TSIG, monitor catalog changes and keep a known-good catalog backup.</p>`,
      },
      {
        id: 'encrypted',
        title: 'DoT, DoH and encrypted transport',
        html: `<p>DNS-over-TLS and DNS-over-HTTPS protect the transport between client and resolver. They do not replace DNSSEC: the resolver can still return forged data if it is malicious or compromised. For public resolvers, DoH/DoT can improve privacy; for authoritative servers, they add a web/TLS attack surface and operational complexity.</p>
<p>If you deploy them, terminate TLS correctly, monitor certificate expiry, rate-limit and log deliberately. Consider whether a reverse proxy provides a better security boundary than exposing BIND directly.</p>`,
      },
      {
        id: 'cookies',
        title: 'DNS cookies, EDE and QNAME minimisation',
        html: `<ul>
<li><strong>DNS cookies</strong> — a lightweight off-path spoofing defense and a way to distinguish legitimate clients.</li>
<li><strong>EDE</strong> — structured error details that make DNSSEC and policy failures easier to diagnose.</li>
<li><strong>QNAME minimisation</strong> — sends less of the name at each delegation step, improving privacy.</li>
<li><strong>Serve-stale</strong> — keeps answers available during upstream failures, with a bounded stale TTL.</li>
</ul>
<p>These features are not a substitute for the basics: correct delegation, DNSSEC validation, restricted recursion and patched software.</p>`,
      },
    ],
  },
  {
    id: 'live-dns-dig',
    title: 'Live DNS, dig, delv and DoH',
    summary: 'How to query live DNS from a browser, what the flags mean, and how to go deeper with dig and delv.',
    level: 'Foundation',
    minutes: 8,
    tags: ['Tools', 'dig', 'DoH'],
    sections: [
      {
        id: 'browser',
        title: 'Why a browser uses DoH',
        html: `<p>Browsers cannot open UDP or TCP port 53, so the app uses DNS-over-HTTPS JSON endpoints from Cloudflare (1.1.1.1) and Google Public DNS (8.8.8.8). The query name and type are sent to the chosen resolver only after you explicitly enable online lookups. Configuration files stay in the browser.</p>
<p>DoH answers are resolver answers, not authoritative truth. They may be cached, GeoDNS-specific or filtered by policy. Use them for propagation and validation checks, not as a replacement for querying the zone’s own name servers.</p>`,
      },
      {
        id: 'dig',
        title: 'dig commands that answer real questions',
        html: `<pre><code># Basic answer from a specific resolver
dig @1.1.1.1 example.com A +dnssec +multi

# Authoritative answer, no recursion
dig @ns1.example.com example.com A +norecurse +dnssec +multi

# Follow the delegation from the root
dig +trace example.com A +dnssec

# DNSSEC chain
dig @1.1.1.1 example.com DS +dnssec +multi
dig @1.1.1.1 example.com DNSKEY +dnssec +multi

# Diagnose a bogus answer without validation
dig @1.1.1.1 example.com A +dnssec +cd +comments

# Reverse lookup
dig @1.1.1.1 -x 192.0.2.80 +dnssec +multi</code></pre>
<p>Read the flags line (<code>qr rd ra ad cd</code>), the ANSWER section and the AUTHORITY section. A NOERROR response with no answer is NODATA, not NXDOMAIN. A SERVFAIL often means validation failure or an unreachable authoritative path.</p>`,
      },
      {
        id: 'delv',
        title: 'delv: validation-aware querying',
        html: `<p><code>delv</code> is BIND’s DNSSEC-aware lookup tool. It validates using a trust anchor and reports whether the answer is secure, insecure, bogus or indeterminate.</p>
<pre><code>delv @1.1.1.1 example.com A +rtrace
delv +vtrace example.com A</code></pre>
<p><code>+rtrace</code> shows the validation path; <code>+vtrace</code> adds verbose validation details. This is often faster than guessing why a resolver returns SERVFAIL.</p>`,
      },
      {
        id: 'app',
        title: 'What the Live DNS page adds',
        html: `<ul>
<li>Queries both Cloudflare and Google and highlights propagation differences.</li>
<li>Recomputes the DS digest against published DNSKEYs.</li>
<li>Walks the chain from the zone apex to the root.</li>
<li>Builds checks from your imported zone and compares expected with observed records.</li>
<li>Generates copy-ready dig and delv commands.</li>
</ul>
<p>None of this proves that your server is correctly configured. It proves what public resolvers currently see. Combine it with authoritative queries, named-checkconf/zone and your own validating resolver.</p>`,
      },
    ],
  },
];

export const ARTICLE_BY_ID = new Map(ARTICLES.map((article) => [article.id, article]));

export function articleById(id) {
  return ARTICLE_BY_ID.get(String(id || '').toLowerCase()) || null;
}

export const LEARNING_PATHS = [
  { title: 'New to DNS', description: 'Start with the model, then zone files and records.', articles: ['dns-mental-model', 'zone-files', 'records'] },
  { title: 'BIND operator', description: 'Configuration, operations, transfers and change control.', articles: ['bind-architecture', 'named-conf', 'transfers-tsig', 'operations', 'change-workflow'] },
  { title: 'DNSSEC', description: 'Chain of trust, signing operations and failure modes.', articles: ['dnssec-chain', 'dnssec-operations', 'delegation'] },
  { title: 'Security review', description: 'Recursion, hardening and policy.', articles: ['recursion-security', 'hardening', 'views-rpz'] },
];
