/* Anonymised example workspaces. All addresses are from TEST-NET ranges. */

export const SAMPLES = [
  {
    id: 'authoritative-example',
    title: 'Authoritative example.com',
    description: 'A clean multi-file authoritative setup with a delegated child and a reverse zone.',
    highlights: [
      'named.conf includes a separate options and local file',
      'Explicit recursion no, transfer policy and hidden version',
      'Forward and reverse zones with a child delegation',
      'Useful starting point for import, compare and export',
    ],
    architecture: 'primary + delegated child + reverse zone',
    files: [
      {
        path: 'named.conf',
        content: `// Example authoritative BIND configuration.
// Replace every example.com, 192.0.2.0/24 and path with your own values.

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
`,
      },
      {
        path: 'named.conf.options',
        content: `options {
    directory "/var/cache/bind";

    // Listen only where this server is supposed to answer.
    listen-on port 53 { 127.0.0.1; 192.0.2.53; };
    listen-on-v6 port 53 { ::1; 2001:db8::53; };

    // Authoritative only: never become an open resolver.
    recursion no;

    // No zone transfers unless a secondary is explicitly allowed below.
    allow-transfer { none; };

    // Validate DNSSEC when this server recurses for itself or a forwarder.
    dnssec-validation auto;

    // Do not advertise the BIND version.
    version none;

    // Smaller responses, less fragmentation.
    minimal-responses yes;

    // Keep diagnostics local and bounded.
    statistics-channels {
        inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
    };
};
`,
      },
      {
        path: 'named.conf.local',
        content: `logging {
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
};

zone "example.com" {
    type primary;
    file "/etc/bind/zones/db.example.com";
    allow-transfer { 192.0.2.54; };
    notify yes;
    also-notify { 192.0.2.54; };
};

zone "lab.example.com" {
    type primary;
    file "/etc/bind/zones/db.lab.example.com";
    allow-transfer { 192.0.2.54; };
};

zone "2.0.192.in-addr.arpa" {
    type primary;
    file "/etc/bind/zones/db.2.0.192";
    allow-transfer { 192.0.2.54; };
};
`,
      },
      {
        path: 'zones/db.example.com',
        content: `$ORIGIN example.com.
$TTL 3600

@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2026110501 ; serial
        3600       ; refresh
        900        ; retry
        1209600    ; expire
        300 )      ; negative caching TTL

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.net.

; Glue for the in-bailiwick name server.
ns1     IN  A       192.0.2.53
ns1     IN  AAAA    2001:db8::53

; Public services.
@       IN  A       192.0.2.80
@       IN  AAAA    2001:db8::80
www     IN  A       192.0.2.80
www     IN  AAAA    2001:db8::80
mail    IN  A       192.0.2.25
mail    IN  AAAA    2001:db8::25

@       IN  MX      10 mail.example.com.

; Mail policy (replace with your real values).
@       IN  TXT     "v=spf1 mx -all"
_dmarc  IN  TXT     "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

; Certificate issuance policy.
@       IN  CAA     0 issue "letsencrypt.org"
@       IN  CAA     0 iodef "mailto:security@example.com"

; Service discovery.
_sip._tcp   IN  SRV 10 60 5060 sip.example.com.
sip         IN  A   192.0.2.90

; Delegation of a child zone. Glue is required because the NS is in-bailiwick.
lab     IN  NS      ns1.lab.example.com.
ns1.lab IN  A       192.0.2.100
`,
      },
      {
        path: 'zones/db.lab.example.com',
        content: `$ORIGIN lab.example.com.
$TTL 3600

@   IN  SOA ns1.lab.example.com. hostmaster.lab.example.com. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.lab.example.com.
ns1     IN  A   192.0.2.100
app     IN  A   192.0.2.101
`,
      },
      {
        path: 'zones/db.2.0.192',
        content: `$ORIGIN 2.0.192.in-addr.arpa.
$TTL 3600

@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.example.com.
@       IN  NS  ns2.example.net.

25      IN  PTR mail.example.com.
53      IN  PTR ns1.example.com.
80      IN  PTR www.example.com.
90      IN  PTR sip.example.com.
100     IN  PTR ns1.lab.example.com.
101     IN  PTR app.lab.example.com.
`,
      },
    ],
  },
  {
    id: 'split-horizon',
    title: 'Split horizon with views and TSIG',
    description: 'Internal and external views, a secondary zone, a TSIG-protected transfer and an RPZ.',
    highlights: [
      'Views with explicit match-clients',
      'A secondary zone using primaries and TSIG',
      'Response policy zone for local blocking',
      'Statistics and logging channels',
    ],
    architecture: 'views + secondary + RPZ',
    files: [
      {
        path: 'named.conf',
        content: `// Example split-horizon resolver/authoritative mix.
// Replace keys, addresses and paths before use.

acl "internal-clients" {
    10.20.0.0/16;
    127.0.0.1;
    ::1;
};

key "xfr-key" {
    algorithm hmac-sha256;
    secret "c2FtcGxlLW9ubHktcmVwbGFjZS10aGlzLXdpdGgtYS1yZWFsLTMyLWJ5dGUta2V5";
};

options {
    directory "/var/cache/bind";
    listen-on port 53 { 127.0.0.1; 192.0.2.53; };
    listen-on-v6 port 53 { ::1; };
    recursion no;
    allow-transfer { none; };
    dnssec-validation auto;
    version none;
    minimal-responses yes;
    statistics-channels {
        inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
    };
};

logging {
    channel main {
        file "/var/log/named/main.log" versions 5 size 20m;
        severity info;
        print-time yes;
    };
    category default { main; };
    category security { main; };
};

view "internal" {
    match-clients { internal-clients; };
    recursion yes;
    allow-recursion { internal-clients; };
    allow-query { internal-clients; };
    allow-query-cache { internal-clients; };

    zone "corp.example" {
        type primary;
        file "/etc/bind/zones/db.corp.example";
        allow-transfer { none; };
    };

    zone "2.0.192.in-addr.arpa" {
        type primary;
        file "/etc/bind/zones/db.2.0.192";
        allow-transfer { none; };
    };

    zone "rpz.example" {
        type primary;
        file "/etc/bind/zones/db.rpz.example";
    };

    response-policy { zone "rpz.example"; };

    zone "example.net" {
        type secondary;
        primaries { 192.0.2.54 key "xfr-key"; };
        file "/var/cache/bind/db.example.net";
    };
};

view "external" {
    match-clients { any; };
    recursion no;
    allow-query { any; };

    zone "example.net" {
        type primary;
        file "/etc/bind/zones/db.example.net";
        allow-transfer { 192.0.2.54 key "xfr-key"; };
        notify yes;
        also-notify { 192.0.2.54; };
    };
};
`,
      },
      {
        path: 'zones/db.corp.example',
        content: `$ORIGIN corp.example.
$TTL 300

@   IN  SOA ns1.corp.example. hostmaster.corp.example. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.corp.example.
ns1     IN  A   192.0.2.53
wiki    IN  A   10.20.0.10
git     IN  A   10.20.0.11
`,
      },
      {
        path: 'zones/db.example.net',
        content: `$ORIGIN example.net.
$TTL 3600

@   IN  SOA ns1.example.net. hostmaster.example.net. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.example.net.
@       IN  NS  ns2.example.net.
ns1     IN  A   192.0.2.53
ns2     IN  A   192.0.2.54
www     IN  A   192.0.2.81
@       IN  MX  10 mail.example.net.
mail    IN  A   192.0.2.26
@       IN  CAA 0 issue "letsencrypt.org"
`,
      },
      {
        path: 'zones/db.rpz.example',
        content: `$ORIGIN rpz.example.
$TTL 300

@   IN  SOA ns1.corp.example. hostmaster.corp.example. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.corp.example.
; Block a known-bad domain.
bad.example     IN  CNAME .
; Redirect a test host to a local sinkhole.
sinkhole.example IN  A 192.0.2.250
`,
      },
      {
        path: 'zones/db.2.0.192',
        content: `$ORIGIN 2.0.192.in-addr.arpa.
$TTL 3600

@   IN  SOA ns1.corp.example. hostmaster.corp.example. (
        2026110501 3600 900 1209600 300 )

@       IN  NS  ns1.corp.example.
53      IN  PTR ns1.example.net.
54      IN  PTR ns2.example.net.
`,
      },
    ],
  },
  {
    id: 'problem-clinic',
    title: 'Problem clinic',
    description: 'Deliberately broken configuration used to demonstrate every analyzer category.',
    highlights: [
      'Open recursion and open transfers',
      'Unauthenticated dynamic updates and a weak TSIG key',
      'CNAME conflicts, missing glue and bad SOA timers',
      'Out-of-zone data, duplicate records and DNSSEC mistakes',
    ],
    architecture: 'intentionally unsafe teaching example',
    files: [
      {
        path: 'named.conf',
        content: `options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    recursion yes;
    allow-recursion { any; };
    allow-query-cache { any; };
    allow-transfer { any; };
    dnssec-validation no;

    // Deliberately discloses the version.
    version "BIND 9.18.0";

    statistics-channels {
        inet 0.0.0.0 port 8053;
    };
};

key "legacy-key" {
    algorithm hmac-md5;
    secret "c2hvcnQ=";
};

zone "problem.example" {
    type primary;
    file "/etc/bind/zones/db.problem.example";
    allow-update { any; };
};

zone "problem.example" {
    type primary;
    file "/etc/bind/zones/db.problem.example.backup";
};
`,
      },
      {
        path: 'zones/db.problem.example',
        content: `$ORIGIN problem.example.
$TTL 60

@   IN  SOA ns1.problem.example. hostmaster@problem.example. (
        0 60 3600 300 90000 )

@   IN  NS  ns1.problem.example.
@   IN  NS  ns2.problem.example.

; CNAME at the apex and mixed with other data below.
@       IN  CNAME   www.problem.example.
www     IN  A       192.0.2.80
www     IN  CNAME   web.problem.example.
web     IN  A       192.0.2.81

; MX target is an alias.
@       IN  MX      10 alias.problem.example.
alias   IN  CNAME   mail.problem.example.
mail    IN  A       192.0.2.25

; Delegation with a missing glue record.
child           IN  NS  ns1.child.problem.example.
; ns1.child.problem.example. has no A/AAAA in this parent.

; DNSSEC-looking data without a real chain.
@       IN  DNSKEY  256 3 13 c2FtcGxlLWtleQ==
@       IN  DS      12345 13 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
@       IN  NSEC3PARAM 1 0 150 -

; Duplicate record and out-of-zone data.
dup     IN  A       192.0.2.99
dup     IN  A       192.0.2.99
outside.example. IN A 192.0.2.200
`,
      },
      {
        path: 'zones/db.problem.example.backup',
        content: `$ORIGIN problem.example.
$TTL 3600
@ IN SOA ns1.problem.example. hostmaster.problem.example. ( 2026110501 3600 900 1209600 300 )
@ IN NS ns1.problem.example.
`,
      },
    ],
  },
  {
    id: 'complete-authoritative',
    title: 'Complete authoritative production layout',
    description: 'A full multi-file example: ACLs, TSIG, options, logging, DNSSEC policy, inline signing, primary/secondary/reverse zones and a delegated child.',
    highlights: [
      'Separate named.conf includes for ACLs, keys, options, logging, DNSSEC policy and zones',
      'Modern DNSSEC policy with ECDSA keys, NSEC3 zero iterations and inline signing',
      'Primary example.com, reverse zone, delegated lab child and a TSIG secondary example.net',
      'Restricted rndc/statistics, bounded logs, rate limiting and CAA/mail/service records',
      'README.txt with deployment, validation, DNSSEC DS and permissions guidance',
    ],
    architecture: 'complete production-style authoritative server',
    files: [
      {
        path: 'named.conf',
        content: `// ============================================================================
// BIND Workbench — complete authoritative example
// ============================================================================
// This is a production-shaped layout for BIND 9.18/9.20.
// Replace example.com, 192.0.2.0/24, 2001:db8::/32, paths and TSIG secrets.
// Validate with the exact BIND binary before deployment:
//   named-checkconf -z /etc/bind/named.conf
//   named-checkzone example.com /etc/bind/zones/db.example.com
// ============================================================================

// Definitions are included before they are referenced.
include "/etc/bind/named.conf.acl";
include "/etc/bind/named.conf.keys";
include "/etc/bind/named.conf.dnssec";
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.logging";
include "/etc/bind/named.conf.local";
`,
      },
      {
        path: 'named.conf.acl',
        content: `// Reusable address match lists. Keep names and addresses under change control.

acl "secondaries" {
    192.0.2.54;   // ns2 primary/secondary example
    192.0.2.55;   // hidden secondary / monitoring replica
};

acl "monitoring" {
    127.0.0.1;
    192.0.2.60;
};

// RRL exceptions: do not let monitoring or localhost be rate-limited.
acl "rrl-exempt" {
    localhost;
    192.0.2.60;
};
`,
      },
      {
        path: 'named.conf.keys',
        content: `// Example-only TSIG secrets. Generate new values, store them in a protected file
// and rotate them. Never commit real production keys.
//
//   python3 -c 'import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())'

key "xfr-key" {
    algorithm hmac-sha256;
    secret "2X/JVvA42Rd55xbxuSqhoapZWXm4eI6v+SptLMbrlS8=";
};

key "rndc-key" {
    algorithm hmac-sha256;
    secret "HQgI3E8BstXvbkKpSoUloBU8w2mqgW2vlvEq00hOCQo=";
};
`,
      },
      {
        path: 'named.conf.dnssec',
        content: `// DNSSEC policy for locally signed primary zones.
// BIND creates and rotates keys in key-directory and maintains a signed copy
// of an inline-signed zone. Back up /var/lib/bind/keys and monitor key events.
//
//   rndc dnssec -status example.com
//   rndc dnssec -checkds published example.com

dnssec-policy "example-nsec3" {
    dnskey-ttl 3600;
    keys {
        ksk lifetime unlimited algorithm ecdsap256sha256;
        zsk lifetime 90d algorithm ecdsap256sha256;
    };
    max-zone-ttl 86400;
    nsec3param iterations 0 optout no salt-length 0;
    signatures-refresh 5d;
    signatures-validity 14d;
    signatures-validity-dnskey 14d;
    zone-propagation-delay 300;
};
`,
      },
      {
        path: 'named.conf.options',
        content: `options {
    // Runtime files. This directory must be writable by the BIND user.
    directory "/var/cache/bind";

    // DNSSEC keys and state. Keep this directory private to the BIND user.
    key-directory "/var/lib/bind/keys";

    // Bind only to the addresses this server is supposed to serve.
    listen-on port 53 { 127.0.0.1; 192.0.2.53; };
    listen-on-v6 port 53 { ::1; 2001:db8::53; };

    // Authoritative-only server: do not become an open resolver.
    recursion no;
    allow-query { any; };
    allow-query-cache { none; };

    // No transfers by default. Each primary zone opts in explicitly.
    allow-transfer { none; };

    // DNSSEC validation is still useful for any local recursion and is a
    // safe, explicit default. Primary zones are signed by the policy below.
    dnssec-validation auto;
    dnssec-policy "example-nsec3";

    // Do not disclose the BIND version.
    version none;

    // Smaller responses and a modern EDNS buffer.
    minimal-responses yes;
    edns-udp-size 1232;

    // Hardening: new zones cannot be created through rndc at runtime.
    allow-new-zones no;

    // Response Rate Limiting. Tune from measurements; this is a starting point.
    rate-limit {
        responses-per-second 20;
        errors-per-second 5;
        nxdomains-per-second 5;
        referrals-per-second 5;
        slip 2;
        exempt-clients { rrl-exempt; };
    };

};

// Restrict the statistics endpoint to localhost/management. This is a
// top-level statement, not an options child.
statistics-channels {
    inet 127.0.0.1 port 8053 allow { monitoring; };
};

// rndc control channel: localhost + TSIG only.
controls {
    inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };
};
`,
      },
      {
        path: 'named.conf.logging',
        content: `logging {
    channel main {
        file "/var/log/named/main.log" versions 7 size 20m suffix timestamp;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };

    channel xfer {
        file "/var/log/named/xfer.log" versions 5 size 10m suffix timestamp;
        severity info;
        print-time yes;
        print-category yes;
    };

    channel dnssec {
        file "/var/log/named/dnssec.log" versions 5 size 10m suffix timestamp;
        severity info;
        print-time yes;
        print-category yes;
    };

    channel security {
        file "/var/log/named/security.log" versions 5 size 10m suffix timestamp;
        severity info;
        print-time yes;
        print-category yes;
    };

    category default { main; };
    category general { main; };
    category security { security; };
    category xfer-in { xfer; };
    category xfer-out { xfer; };
    category dnssec { dnssec; };
    category update { main; };
    category update-security { security; };
    category notify { xfer; };
    category lame-servers { main; };
};
`,
      },
      {
        path: 'named.conf.local',
        content: `// Named primary list for the example.net secondary.
primaries "example-net-primary" {
    192.0.2.60 key "xfr-key";
};

// ---------------------------------------------------------------------------
// Primary zones
// ---------------------------------------------------------------------------

zone "example.com" {
    type primary;
    file "/etc/bind/zones/db.example.com";
    allow-transfer { "secondaries"; key "xfr-key"; };
    notify yes;
    also-notify { 192.0.2.54; 192.0.2.55; };
    dnssec-policy "example-nsec3";
    inline-signing yes;
};

zone "lab.example.com" {
    type primary;
    file "/etc/bind/zones/db.lab.example.com";
    allow-transfer { "secondaries"; key "xfr-key"; };
    notify yes;
    also-notify { 192.0.2.54; 192.0.2.55; };
    dnssec-policy "example-nsec3";
    inline-signing yes;
};

zone "2.0.192.in-addr.arpa" {
    type primary;
    file "/etc/bind/zones/db.2.0.192";
    allow-transfer { "secondaries"; key "xfr-key"; };
    notify yes;
    also-notify { 192.0.2.54; 192.0.2.55; };
    dnssec-policy "example-nsec3";
    inline-signing yes;
};

// ---------------------------------------------------------------------------
// Secondary zone
// ---------------------------------------------------------------------------

zone "example.net" {
    type secondary;
    primaries { "example-net-primary"; };
    file "/var/cache/bind/db.example.net";
    allow-transfer { none; };
    notify no;
};
`,
      },
      {
        path: 'zones/db.example.com',
        content: `; ============================================================================
; example.com — authoritative master file
; Replace TEST-NET addresses and example names with your own data.
; DNSSEC is managed by dnssec-policy + inline-signing in named.conf.local.
; ============================================================================

$ORIGIN example.com.
$TTL 3600

@       IN  SOA ns1.example.com. hostmaster.example.com. (
            2026110501 ; serial — increment on every publish
            3600       ; refresh
            900        ; retry
            1209600    ; expire (14 days)
            300 )      ; negative caching TTL

; ---------------------------------------------------------------------------
; Delegation and glue
; ---------------------------------------------------------------------------
@           IN  NS      ns1.example.com.
@           IN  NS      ns2.example.net.

ns1         IN  A       192.0.2.53
ns1         IN  AAAA    2001:db8::53

; ---------------------------------------------------------------------------
; Web and service endpoints
; ---------------------------------------------------------------------------
@           IN  A       192.0.2.80
@           IN  AAAA    2001:db8::80
www         IN  A       192.0.2.80
www         IN  AAAA    2001:db8::80
status      IN  A       192.0.2.82

mail        IN  A       192.0.2.25
mail        IN  AAAA    2001:db8::25
sip         IN  A       192.0.2.90
sip         IN  AAAA    2001:db8::90
autodiscover IN A       192.0.2.25

; ---------------------------------------------------------------------------
; Mail policy
; ---------------------------------------------------------------------------
@           IN  MX      10 mail.example.com.
@           IN  MX      20 mx2.example.net.
@           IN  TXT     "v=spf1 mx -all"
_dmarc      IN  TXT     "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1"

; Replace selector1 and the placeholder with the public key generated by your
; DKIM tooling. The record is commented out so the example stays syntactically
; valid without pretending to contain a real key.
; selector1._domainkey IN TXT "v=DKIM1; k=rsa; p=REPLACE_WITH_PUBLIC_KEY"

; ---------------------------------------------------------------------------
; Certificate issuance policy
; ---------------------------------------------------------------------------
@           IN  CAA     0 issue "letsencrypt.org"
@           IN  CAA     0 issuewild "letsencrypt.org"
@           IN  CAA     0 iodef "mailto:security@example.com"

; ---------------------------------------------------------------------------
; Service discovery
; ---------------------------------------------------------------------------
_sip._tcp           IN  SRV 10 60 5060 sip.example.com.
_imaps._tcp         IN  SRV 10 60 993 mail.example.com.
_autodiscover._tcp  IN  SRV 0 0 443 autodiscover.example.com.

; ---------------------------------------------------------------------------
; Delegation of lab.example.com
; The parent must provide glue for both in-bailiwick name servers.
; After the child is signed, publish the DS generated from its KSK here.
; ---------------------------------------------------------------------------
lab         IN  NS      ns1.lab.example.com.
lab         IN  NS      ns2.lab.example.com.
ns1.lab     IN  A       192.0.2.100
ns1.lab     IN  AAAA    2001:db8::100
ns2.lab     IN  A       192.0.2.102
ns2.lab     IN  AAAA    2001:db8::102

; Example DS placeholder (uncomment after signing the child):
; lab       IN  DS      12345 13 2 REPLACE_WITH_CHILD_DS_DIGEST
`,
      },
      {
        path: 'zones/db.lab.example.com',
        content: `; ============================================================================
; lab.example.com — delegated child zone
; Signed locally with the same policy. Publish its DS in example.com.
; ============================================================================

$ORIGIN lab.example.com.
$TTL 300

@       IN  SOA ns1.lab.example.com. hostmaster.lab.example.com. (
            2026110501
            3600
            900
            1209600
            300 )

@       IN  NS      ns1.lab.example.com.
@       IN  NS      ns2.lab.example.com.

ns1     IN  A       192.0.2.100
ns1     IN  AAAA    2001:db8::100
ns2     IN  A       192.0.2.102
ns2     IN  AAAA    2001:db8::102

app     IN  A       192.0.2.101
app     IN  AAAA    2001:db8::101
api     IN  CNAME   app.lab.example.com.

@       IN  CAA     0 issue "letsencrypt.org"
@       IN  TXT     "v=spf1 -all"
`,
      },
      {
        path: 'zones/db.2.0.192',
        content: `; ============================================================================
; 2.0.192.in-addr.arpa — reverse zone for 192.0.2.0/24
; Keep PTR targets synchronized with the forward zones.
; ============================================================================

$ORIGIN 2.0.192.in-addr.arpa.
$TTL 3600

@       IN  SOA ns1.example.com. hostmaster.example.com. (
            2026110501
            3600
            900
            1209600
            300 )

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.net.

25      IN  PTR     mail.example.com.
53      IN  PTR     ns1.example.com.
80      IN  PTR     www.example.com.
82      IN  PTR     status.example.com.
90      IN  PTR     sip.example.com.
92      IN  PTR     mx2.example.net.
100     IN  PTR     ns1.lab.example.com.
101     IN  PTR     app.lab.example.com.
102     IN  PTR     ns2.lab.example.com.
`,
      },
      {
        path: 'zones/db.example.net',
        content: `; ============================================================================
; example.net — current secondary copy
; The live file is usually written by BIND in /var/cache/bind after transfer.
; This copy is included so the workspace is complete and reviewable.
; ============================================================================

$ORIGIN example.net.
$TTL 3600

@       IN  SOA ns1.example.net. hostmaster.example.net. (
            2026110501
            3600
            900
            1209600
            300 )

@       IN  NS      ns1.example.net.
@       IN  NS      ns2.example.net.

ns1     IN  A       192.0.2.53
ns2     IN  A       192.0.2.54
www     IN  A       192.0.2.91
mail    IN  A       192.0.2.26
mx2     IN  A       192.0.2.92

@       IN  MX      10 mail.example.net.
@       IN  TXT     "v=spf1 mx -all"
@       IN  CAA     0 issue "letsencrypt.org"
`,
      },
      {
        path: 'README.txt',
        content: `BIND Workbench — complete authoritative example
================================================

This workspace is a production-shaped BIND 9.18/9.20 authoritative layout.
It is not a drop-in production configuration: every example.com name,
192.0.2.0/24 / 2001:db8::/32 address, path and TSIG secret must be replaced.

Files
-----
named.conf
  Entry point. Includes ACLs, keys, DNSSEC policy, options, logging and zones.
named.conf.acl
  Reusable secondaries, monitoring and RRL-exempt address lists.
named.conf.keys
  Example TSIG keys for transfers and rndc. Replace and protect them.
named.conf.dnssec
  dnssec-policy "example-nsec3": ECDSA P-256 keys, NSEC3 zero iterations,
  inline signing and signature lifetimes.
named.conf.options
  Listeners, recursion no, query/transfer policy, RRL, statistics, controls.
named.conf.logging
  Bounded file channels for main, transfers, DNSSEC and security events.
named.conf.local
  Primary example.com, delegated lab.example.com, reverse zone and the
  example.net secondary.
zones/db.*
  Master files. DNSSEC signatures are generated by BIND; the source files
  stay unsigned when inline-signing is enabled.

Before deployment
-----------------
1. Replace every example name, address, path and key.
2. Generate fresh TSIG secrets:
     python3 -c 'import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())'
3. Protect key-directory and key files:
     install -d -m 0700 -o bind -g bind /var/lib/bind/keys
     chown bind:bind /var/cache/bind /var/log/named
4. Validate with the exact BIND version:
     named-checkconf -z /etc/bind/named.conf
     named-checkzone example.com /etc/bind/zones/db.example.com
     named-checkzone lab.example.com /etc/bind/zones/db.lab.example.com
     named-checkzone 2.0.192.in-addr.arpa /etc/bind/zones/db.2.0.192
5. Review the rndc controls and statistics allow lists. Do not expose them.
6. Test from a secondary before changing the parent delegation.

DNSSEC workflow
---------------
- example.com, lab.example.com and the reverse zone use
  dnssec-policy "example-nsec3" and inline-signing yes.
- BIND creates keys under /var/lib/bind/keys and manages signatures.
- Monitor:
     rndc dnssec -status example.com
     rndc dnssec -checkds published example.com
- Publish the DS for example.com at its parent registry/zone.
- After signing lab.example.com, generate its DS and add it to the parent
  example.com zone:
     dnssec-dsfromkey -2 /var/lib/bind/keys/Klab.example.com.+013+*.key
  Then uncomment/replace the DS placeholder in zones/db.example.com and
  reload the parent. Without a DS, the child is an island of security.
- The reverse zone also needs its DS published by the address-space owner.

Secondary example.net
---------------------
- The named list "example-net-primary" points at 192.0.2.60 with TSIG.
- The secondary stores its live copy in /var/cache/bind.
- Transfer ACLs on the primary must allow the secondary address and key.
- Do not edit the live secondary file while BIND owns the journal.

Operational checks
------------------
  rndc status
  rndc reload
  rndc zonestatus example.com
  dig @192.0.2.53 example.com SOA +dnssec +multi
  dig @192.0.2.53 example.com DNSKEY +dnssec +multi
  dig @192.0.2.53 example.com NSEC3PARAM +dnssec +multi
  delv @192.0.2.53 example.com DNSKEY +rtrace

Never commit real TSIG secrets or DNSSEC private keys. This example is for
learning and review; use named-checkconf, named-checkzone, a staging server
and a tested rollback plan before production.
`,
      },
    ],
  },
];

export function sampleById(id) {
  return SAMPLES.find((sample) => sample.id === id) || null;
}

export function sampleFileCount(sample) {
  return sample?.files?.length || 0;
}
