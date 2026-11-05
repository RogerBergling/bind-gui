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
];

export function sampleById(id) {
  return SAMPLES.find((sample) => sample.id === id) || null;
}

export function sampleFileCount(sample) {
  return sample?.files?.length || 0;
}
