# Lookup benchmarks

The [initial baseline](BASELINE.md) includes checked three-sample reports for the
current engine, before any persistent-socket or scheduling redesign.

Run from the repository root with Python 3 and the Go version required by `go.mod`:

```sh
python3 scripts/benchmark.py --output /tmp/full-reverse-throughput.json
python3 scripts/benchmark.py --bench '^BenchmarkLookupScale$' --output /tmp/full-reverse-scale.json
```

The runner uses one full scan per sample (`-benchtime=1x`) and three samples per
configuration. It records the exact command, UTC timestamps, Git revision and
dirty state, Go/OS/architecture, CPU model/count, GOMAXPROCS setting, parsed
metrics, and raw output. Existing reports are never overwritten. A failed check
or an expression matching no benchmarks gives a nonzero exit status. Failed
events/output and missing repeat samples are rejected even if Go exits zero; inspect
`success` before treating a report as a baseline. Keep the host otherwise idle
and use the same machine, Go version, settings, and harness when comparing revisions.

To select scenarios or change the repeat count:

```sh
python3 scripts/benchmark.py --bench '^BenchmarkLookup$/^(fast|loss)$/^c(32|128)$' --count 5 --output /tmp/full-reverse-selected.json
```

Go's benchmark expressions are slash-separated regular expressions. Direct Go
commands also work, including profiles:

```sh
go test -run '^$' -bench '^BenchmarkLookup$/^fast$/^c32$' -benchtime=1x -count 3 -benchmem .
go test -run '^$' -bench '^BenchmarkLookupScale$' -benchtime=1x -memprofile /tmp/full-reverse-heap.pprof -o /tmp/full-reverse-bench.test .
go tool pprof -alloc_space /tmp/full-reverse-bench.test /tmp/full-reverse-heap.pprof
```

All DNS and HTTP traffic goes to ephemeral loopback listeners. The target
prefixes below are synthetic DNS question data; no packets go to those addresses.
No public recursive resolver or external RIPE API is queried. Fixture correctness
also runs in ordinary `go test ./...` using a smaller prefix.

## Workloads and expected results

Each throughput scan contains 256 addresses (`192.0.2.0/24`), with concurrency
32, 64, 128, and 256, a 250ms attempt timeout, and one retry. These are benchmark
settings, not proposed CLI defaults. Logging is quiet (`-q` semantics). PTR names
encode the original IPv4 address.

| Scenario | Fixture behavior | Expected per scan |
| --- | --- | --- |
| fast | Immediate PTR replies | 256 records, 256 UDP PTR queries |
| delayed | 2ms delay per PTR reply | 256 records, 256 UDP PTR queries |
| loss | Drop first query for every 16th address | 256 records, 272 UDP PTR queries, 16 retries |
| duplicates | Send every PTR reply twice | 256 unique records, 256 UDP PTR queries, 256 extra replies |
| reordered | Vary delay from 0–7ms by address | 256 records, 256 UDP PTR queries |
| late | First reply for every 16th address delayed 375ms; retry replies immediately | 256 records, 272 UDP PTR queries, 16 retries |
| negative | Equal groups of NXDOMAIN, empty answer, persistent SERVFAIL, and PTR | 64 PTR records, 64 error records, 320 UDP PTR queries, 64 retries |
| truncated | All UDP replies truncated; TCP returns PTR | 256 records, 256 UDP PTR queries, 256 TCP queries |
| forward | Every PTR returns a name; only even addresses forward-confirm | 128 records, 256 UDP PTR queries, 256 UDP A queries |
| asn-cold | Fresh empty disk cache; overview reports one covering prefix and ASN | 256 enriched records, 256 UDP PTR queries, 1 HTTP request |
| asn-warm | Prepopulate announced-prefix and AS-overview disk responses | 256 enriched records, 256 UDP PTR queries, 0 measured HTTP requests |

Cold metadata caches are new per iteration. Warm preparation makes two local HTTP
requests before timing, then resets the API counter; the engine must still load
the disk cache and construct its per-run index. These runs measure IP enrichment
with `-a` semantics, not AS-name search or AS-target expansion.

`BenchmarkLookupScale` holds concurrency at 32 and uses delayed replies over
1,024, 4,096, and 16,384 addresses (`198.18.0.0/22`, `/20`, `/18`). It expects
one correct record and one UDP PTR query per address. Compare peak memory,
allocations per address, and goroutine/handler peaks as the address count grows.

## Measurements and correctness

`ns/op`, `B/op`, and `allocs/op` are Go benchmark measurements for one engine run.
`addresses/s` counts all input addresses, including expected missing and failed
lookups. `udp-ptr/op`, `udp-a/op`, and `tcp/op` count requests received on the
fixture's wire endpoints. `retries/op` counts repeated UDP questions; TCP fallback
is counted separately. `api/op`, `records/op`, and `errors/op` count measured HTTP
requests, emitted records, and emitted lookup failures.

Every run verifies each record's IP, target, PTR names, error class, and nullable
metadata, rejects duplicate/unexpected records, checks that all expected records
arrived, and checks per-address query/attempt counts. Missing-PTR and unconfirmed
addresses must produce no record. `complete=1` is reported only after validation.
The benchmark fails if load causes unintended timeouts or retries; it does not
report a faster incomplete scan as a success.

Timing excludes listener/cache preparation and final verification. It includes
streaming JSON decoding and validation on output writes, fixture DNS/HTTP work,
and process-memory sampling every 10ms. Late fixture handlers are joined after
timing and before resetting counters. A deliberately late reply may reach a
closed socket; this fixture tests completion and cleanup, not proof of rejection
of an old reply after future socket/ID reuse. Transport-specific adversarial
validation belongs to issue #12.

`peak-heap-delta-B` is the highest sampled process HeapAlloc above a post-GC
starting value, including an end-of-run sample. `peak-goroutines` is an absolute
sampled process peak; `peak-handlers` is an exact active DNS-handler peak. Go's
allocation counters and heap profiles include the engine, fixtures, verifier,
and sampler. Short-lived peaks between samples can be missed. HeapAlloc includes
uncollected garbage; it is not retained/live heap after GC.

The verifier streams records and keeps a preallocated seen bitmap rather than
retaining JSON output. The fixture also preallocates per-address attempt arrays.
These harness allocations grow with the input and happen before timing/memory
sampling. The scale suite can expose unexpected growth and concurrency changes,
but does not prove an engine-only constant-memory bound. Use profiles and code
inspection to attribute changes; compare fixture/harness overhead consistently.

Loopback results do not predict internet throughput or the best resolver limits.
Any real-network benchmark requires agreed targets/resolvers and a publication
policy. When doing one, distinguish a cold recursive resolver cache from warm
cached DNS responses, as well as cold/warm RIPE metadata caches.

The report runner's failure-detection and split-output parsing regressions can be
checked with:

```sh
python3 -B -m unittest discover -s scripts
```
