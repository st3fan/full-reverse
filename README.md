# full-reverse

Reverse-DNS (PTR) lookup tool for IPv4 CIDR ranges and ASNs. It expands each
CIDR (or every announced prefix of an ASN), performs a reverse lookup for every
address using github.com/miekg/dns, and writes one JSON object per address
(JSONL) to stdout.

## Install

Requires Go 1.27.2 or later.

```sh
go install github.com/st3fan/full-reverse@latest
```

To install a specific version:

```sh
go install github.com/st3fan/full-reverse@v0.1.0
```

Go installs the `full-reverse` executable in `GOBIN`, or `$(go env GOPATH)/bin`
when `GOBIN` is unset (normally `$HOME/go/bin`). Add that directory to your
`PATH`, then run `full-reverse -h` to check the installation.

## Usage

```
full-reverse [OPTIONS] [CIDR|IP|ASN|AS-NAME|FILE...]
```

Most options have a short and a long form (e.g. `-d` / `--dns-server`), and
options may appear before or after positional targets. Run `full-reverse -h`
to list them.

Targets may be passed as arguments, read from files, or piped on stdin. A
plain IP such as `1.1.1.1` is treated as a `/32` prefix. Use `-i FILE` (or
`--input FILE`) to read a list with one target per line; `-i -` reads that list
from stdin. The flag may be repeated. A positional argument that names a
readable file is also read as a list of targets; otherwise it is treated as a
literal CIDR, IP, ASN, or AS name (a positional `-` reads stdin). In files and
stdin, blank lines, `#` comments, and comma/whitespace separated values are
accepted.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-i`, `--input` | – | read targets from a file, one per line; use `-` for stdin; may be repeated |
| `-a`, `--lookup-as` | `false` | look up the announcing ASN for IPs whose ASN is not already known |
| `-d`, `--dns-server` | `/etc/resolv.conf` | DNS server to query, e.g. `8.8.8.8` or `8.8.8.8:53`; may be repeated |
| `-c`, `--concurrency` | `32` | maximum active DNS attempts |
| `--rate` | `0` | maximum total DNS sends per second; 0 disables pacing |
| `--resolver-rate` | `0` | maximum DNS sends per second per configured resolver; 0 disables pacing |
| `-r`, `--retries` | `4` | retries for timeouts and I/O errors; NXDOMAIN is never retried |
| `-t`, `--timeout` | `2.5s` | timeout per attempt |
| `-q`, `--quiet` | `false` | silence progress and summary logging |
| `-f`, `--forward-confirmed-only` | `false` | only report PTR records that forward-confirm (see below) |

Only IPv4 is supported; plain IPs are treated as `/32`. Targets iterate over
the whole prefix, including the network and broadcast addresses. CIDRs, IPs,
ASNs, and AS names may be mixed freely:

```sh
full-reverse 1.1.1.0/24 8.8.8.8 AS15348 AMAZON-AES
```

An ASN is expanded to its currently announced prefixes from the
[RIPE Stat announced-prefixes API](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes).
IPv6 prefixes are ignored and duplicates are removed; the fetched prefixes are
scanned in addition to any explicit CIDRs. ASNs accept `AS15169`, `as15169`, or
`15169`.

An AS name such as `AMAZON-AES` or `APPLE-ENGINEERING` is the aut-num's
`as-name` (not the organization). It is resolved to an ASN via the
[RIPE Stat searchcomplete API](https://stat.ripe.net/docs/data-api/api-endpoints/searchcomplete).
A name that matches several ASNs (for example `GOOGLE`) is rejected with the
candidate list; use an AS number in that case.

### Looking up an IP's ASN

By default, the `asn` field is `null`, or the announcing AS number when the
IP's prefix was expanded from an ASN. With `-a`/`--lookup-as`, an IP whose ASN
is not already known is resolved via the
[RIPE Stat prefix-overview API](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview)
and the result is added to the numeric `asn` field. Whenever the ASN is known,
the AS is resolved (via as-overview) and reported as `as_name` and `as_org`;
RIPE Stat's combined holder ("<as-name> - <org>") is split on the first
`" - "`. If there is no such separator, the whole holder is used as `as_name`
and `as_org` is `null`. If RIPE Stat returns no ASN (for example an
unannounced address), all three fields stay `null`:

```sh
$ full-reverse -a 8.8.8.8
{"ip":"8.8.8.8","target":"8.8.8.8","prefix":"8.8.8.0/24","asn":15169,"as_name":"GOOGLE","as_org":"Google LLC","ptr":["dns.google"]}

$ full-reverse -a 192.0.2.1
{"ip":"192.0.2.1","target":"192.0.2.1","prefix":null,"asn":null,"as_name":null,"as_org":null,"ptr":["bogon.example.test"]}
```

Before calling the API, the tool loads every cached announced-prefixes
response and indexes the prefixes they contain, so an IP covered by a cached
AS prefix resolves without a network call. Prefixes learned from `AS` targets
and from earlier lookups in the same run are indexed too, and prefix discovery is
serialized to share newly learned prefixes without guessing their boundaries.
Duplicate in-flight requests for an IP or ASN share their result, including
failures; failures remain eligible for a later retry. Cached reads never wait
for unrelated HTTP requests. Successful unknown-AS responses are also
remembered for the duration of the run: a reported IPv4 prefix covering the
queried address is reused for that prefix; otherwise only that address is
remembered. Known ASN entries take precedence, and failed API requests remain
eligible for retry. Cache hits and outgoing API requests are logged to stderr,
e.g.:

```
RIPE Stat: using cached announced-prefixes for AS3333
Fetching https://stat.ripe.net/data/prefix-overview/data.json?resource=9.9.9.9
```

### RIPE Stat response cache

RIPE Stat responses are cached for one hour (hardcoded) under
`$XDG_CACHE_HOME/full-reverse/ripestat`, or `~/.cache/full-reverse/ripestat`
when `XDG_CACHE_HOME` is unset, and reused while younger than the TTL; expired
entries are refetched and overwritten. Two kinds of responses are stored:

- announced-prefixes results as `AS<number>.json`
- prefix-overview results as `overview/<resource>.json`
- as-overview results as `as-overview/AS<number>.json`
- searchcomplete results as `search/<query>.json`

Caching is best-effort: unreadable or corrupt cache files are ignored and
never fail a run.

Queries bypass the libc/NSS path and are sent directly to DNS servers. When no
`-d` is given, nameservers are read from `/etc/resolv.conf` and tried in order.
When multiple `-d` servers are given, lookups are assigned to them in
round-robin order; retries stay on the assigned server. Truncated UDP responses
are retried over TCP.

UDP queries share persistent sockets per resolver endpoint, with validation of
reply sources, IDs, and questions. See the [transport design](docs/dns-transport.md)
for query limits, socket rotation, and shutdown behavior.

A failed lookup is retried up to `-r` times (so the default of `4` means at
most 5 attempts). Each attempt has its own `-t` timeout. NXDOMAIN / no-such-host
responses are never retried. Successful empty answers also complete without retrying.

### Scheduling and rate limits

The engine enumerates addresses incrementally and admits at most `2 × -c`
addresses at once. At most `-c` DNS attempts are active;
a completed attempt releases its active slot before retrying or checking a PTR
name's A record. Fresh work and retries alternate when both are queued, and
ready resolvers are scheduled round-robin. A slow resolver retains its assigned
addresses but does not prevent ready work for another resolver from starting.
With `-a`, four separate metadata workers enrich admitted addresses alongside
DNS. A shared window of at most `max(64, 2 × -c)` addresses bounds unfinished
DNS/metadata joins and their queues. A record becomes ready when both stages
finish; metadata HTTP latency does not consume a DNS slot. If the window fills,
admission pauses until a joined address completes. Cache hits bypass the
metadata queue. Prefix discovery and AS-name HTTP requests each have a single
independent lane (at most two enrichment HTTP requests at once). All admitted
addresses needing metadata are enriched, including addresses with no PTR;
only the same successful/error DNS records as before are emitted. Metadata
failures warn and leave missing fields null without failing a DNS result.

`--rate` limits all DNS sends together; `--resolver-rate` limits each configured
resolver entry (the system nameserver list counts as one entry). When both are
set, each send must satisfy both limits. Retries, A queries, system nameserver
fallback, and TCP fallback all consume the same budgets. Duplicate `-d` entries
have separate per-entry limits; use `--rate` to cap their combined load. Sends
are spaced evenly, with no accumulated credit or catch-up burst after a pause.
RIPE Stat HTTP requests do not consume the DNS budget.

The initial pacing wait is outside an attempt's `-t` timeout. Once that attempt
starts, its remaining deadline includes any system nameserver or TCP fallback
and their pacing waits. Each retry gets a fresh timeout after its initial send
grant. A rate limit therefore bounds sends independently of `-c`; it does not
change retry counts or introduce resolver failover.

Both rate controls default to `0`, preserving existing unpaced behavior and
baseline completeness. Local fixture measurements do not establish a safe rate
for a remote resolver. Set explicit limits to match your resolver's capacity;
for example, `--rate 100 --resolver-rate 50` caps total sends at 100/s and each
configured entry at 50/s. These are example limits, not measured recommendations.

Cancellation stops admission, cancels queued and active attempts, joins active
DNS and metadata workers, and closes the transport receivers. Completed output is retained;
unfinished addresses do not produce fabricated failure records. A normal run
drains every admitted address through completion before reporting its summary.

### Forward-confirmed PTR records

With `-f`/`--forward-confirmed-only`, each PTR record is validated with a forward
lookup:

1. Reverse lookup: `192.0.2.10` → PTR → `mail.example.com`
2. Forward confirmation: `mail.example.com` → A → does it include `192.0.2.10`?

Only names whose A records map back to the original IP are reported. When an IP
has several PTR names, the confirmed ones are kept and the rest dropped; if none
confirm, the IP is counted as `unconfirmed` and no record is emitted. Forward
lookups use the same resolver, timeout, and retry settings as the reverse
lookup. NXDOMAIN or a failed forward lookup counts as not confirmed.

## Output

JSONL on stdout. Progress and a final summary are logged to stderr, each line
prefixed with an RFC 3339 (ISO 8601) timestamp in the system's local timezone;
`-q`/`--quiet` silences these log lines (fatal errors are still printed).
Ctrl+C cancels input reading and pending lookups. Cancellation and output write
failures terminate the run with a nonzero exit status.
Stdout has one writer with 64 queued record slots and a 64 KiB byte buffer.
Full buffers flush as needed; a 100 ms timer flushes partial buffers during a
scan. Producers apply backpressure when the queue fills. Records remain in
completion order, with no sorting or accumulation of the whole scan. Stderr
diagnostics are written immediately and independently of the stdout buffer.

Normal completion and cancellation join producers, drain all accepted JSONL
records, flush stdout, and wait for underlying writes to finish. Cancellation
can reject records that have not entered the queue; incomplete lookups do not
produce failure records. Any write, short-write, or final-flush failure cancels
pending work and returns a nonzero status. Once stdout fails, queued records
cannot be delivered; that failure is reported instead of silently succeeding.
The success summary is logged only after the final stdout flush succeeds.

The run starts with a line stating how many IPs will be looked up. Each ASN
expands to a line listing all of its announced IPv4 prefixes. For runs larger
than a /24, an intermediate progress line is emitted for every 256 IPs scanned,
and the run ends with counts of resolved, PTR-less, unconfirmed, and failed
lookups. A final metrics line is then logged for each DNS resolver, reporting
the number of requests it handled, resolver errors, and average response time.
`ptr` is always an array (possibly empty). Each record carries `target` (the
target as given on the command line: a CIDR, IP, ASN, or AS name), a `prefix`
(the BGP/announced prefix when known, otherwise `null`), an `asn` field, an
`as_name` field, and an `as_org` field. The AS fields are `null` when unknown;
`asn` is numeric (e.g. `15169`, not `"AS15169"`). `prefix` is populated for
AS-expanded targets and for `-a` lookups; it stays `null` for a plain CIDR/IP
without AS information.
Addresses with no PTR record (NXDOMAIN / no such host) are skipped silently;
`error` is only present for real lookup failures such as timeouts or SERVFAIL.

```sh
$ echo '1.1.1.0/30' | full-reverse -d 1.1.1.1 -d 8.8.8.8 -c 4
2026-09-11T14:35:20-04:00 looking up 4 IPs across 1 CIDR(s)
{"ip":"1.1.1.1","target":"1.1.1.0/30","prefix":null,"asn":null,"as_name":null,"as_org":null,"ptr":["one.one.one.one"]}
{"ip":"1.1.1.2","target":"1.1.1.0/30","prefix":null,"asn":null,"as_name":null,"as_org":null,"ptr":["security.cloudflare-dns.com"]}
{"ip":"1.1.1.3","target":"1.1.1.0/30","prefix":null,"asn":null,"as_name":null,"as_org":null,"ptr":["family.cloudflare-dns.com"]}
2026-09-11T14:35:20-04:00 done: 4 IPs looked up, 3 resolved, 1 without PTR, 0 unconfirmed, 0 failed in 17ms
2026-09-11T14:35:20-04:00 resolver 1.1.1.1:53: 2 request(s), 0 error(s), avg response 16.12ms
2026-09-11T14:35:20-04:00 resolver 8.8.8.8:53: 2 request(s), 0 error(s), avg response 15.811ms
```

When scanning an AS, `target` is the AS as given and `prefix` is the announced
prefix, e.g.:

```json
{"ip":"193.0.19.4","target":"AS3333","prefix":"193.0.18.0/23","asn":3333,"as_name":"RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre (RIPE NCC)","as_org":null,"ptr":["web.admindns.ripe.net"]}
```

## Benchmarks

For repeatable local performance and completeness checks, see the
[lookup benchmark guide](benchmarks/README.md).
