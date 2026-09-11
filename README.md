# full-reverse

Reverse-DNS (PTR) lookup tool for IPv4 CIDR ranges. It expands each CIDR,
performs a reverse lookup for every address using
github.com/miekg/dns, and writes one JSON object per address (JSONL) to
stdout.

## Build

```sh
go build -o full-reverse .
```

## Usage

```
full-reverse [-d DNS_SERVER]... [-c CONCURRENCY] [-r RETRIES] [-t TIMEOUT] [CIDR|FILE...]
```

CIDRs may be passed as arguments, read from files, or piped on stdin. An
argument that names a readable file is read as a list of CIDRs; otherwise it
is treated as a literal CIDR. In files and stdin, blank lines, `#` comments,
and comma/whitespace separated values are accepted.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-d` | `/etc/resolv.conf` | DNS server to query, e.g. `8.8.8.8` or `8.8.8.8:53`; may be repeated |
| `-c` | `32` | number of concurrent reverse lookups |
| `-r` | `4` | retries for timeouts and I/O errors; NXDOMAIN is never retried |
| `-t` | `2.5s` | timeout per attempt |

Only IPv4 CIDRs are supported. Targets iterate over the whole prefix,
including the network and broadcast addresses.

Queries bypass the libc/NSS path and are sent directly to DNS servers. When no
`-d` is given, nameservers are read from `/etc/resolv.conf` and tried in order.
When multiple `-d` servers are given, lookups are assigned to them in
round-robin order; retries stay on the assigned server. Truncated UDP responses
are retried over TCP.

A failed lookup is retried up to `-r` times (so the default of `4` means at
most 5 attempts). Each attempt has its own `-t` timeout. NXDOMAIN / no-such-host
responses are never retried.

## Output

JSONL on stdout. Progress and a final summary are logged to stderr, each line
prefixed with an RFC 3339 (ISO 8601) timestamp in the system's local timezone.
The run starts with a line stating how many IPs will be looked up. For runs
larger than a /24, an intermediate progress line is emitted for every 256 IPs
scanned, and the run ends with counts of resolved, PTR-less, and failed
lookups. A final metrics line is then logged for each DNS resolver, reporting
the number of requests it handled, resolver errors, and average response time.
`ptr` is always an array (possibly empty). Addresses with no PTR record
(NXDOMAIN / no such host) are skipped silently; `error` is only present for
real lookup failures such as timeouts or SERVFAIL.

```sh
$ echo '1.1.1.0/30' | ./full-reverse -d 1.1.1.1 -d 8.8.8.8 -c 4
2026-09-11T14:35:20-04:00 looking up 4 IPs across 1 CIDR(s)
{"ip":"1.1.1.1","ptr":["one.one.one.one"]}
{"ip":"1.1.1.2","ptr":["security.cloudflare-dns.com"]}
{"ip":"1.1.1.3","ptr":["family.cloudflare-dns.com"]}
2026-09-11T14:35:20-04:00 done: 4 IPs looked up, 3 resolved, 1 without PTR, 0 failed in 17ms
2026-09-11T14:35:20-04:00 resolver 1.1.1.1:53: 2 request(s), 0 error(s), avg response 16.12ms
2026-09-11T14:35:20-04:00 resolver 8.8.8.8:53: 2 request(s), 0 error(s), avg response 15.811ms
```
