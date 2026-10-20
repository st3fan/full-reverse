# DNS scheduler comparison

Measured source: `bf47682d9aa309fde92ec9a13426fe2ece052b34` (clean tree), 2026-10-20T11:57:05.323188+00:00.
Compared with the [persistent UDP baseline](UDP-TRANSPORT.md), using the same
Go version, machine, fixtures, three samples, and unpaced defaults.

Raw reports: [throughput](scheduler-throughput.json), [scale](scheduler-scale.json).
All 132 throughput and nine scaling samples passed, preserving expected record,
error, retry, UDP PTR/A, TCP, and HTTP counts in every configuration.

## Throughput

Medians of three single-scan samples; rates are input addresses/second.
Ratios are scheduler throughput / UDP-baseline throughput; above 1 is faster.
All configurations are shown, including regressions.

| Scenario | UDP c32 | Scheduler c32 | c32 ratio | c64 ratio | c128 ratio | c256 ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fast | 54,977 | 46,975 | 0.85x | 0.96x | 0.89x | 0.87x |
| delayed | 11,340 | 11,092 | 0.98x | 1.00x | 0.91x | 0.93x |
| loss | 1,003 | 1,005 | 1.00x | 1.00x | 1.00x | 1.00x |
| duplicates | 49,830 | 47,274 | 0.95x | 0.86x | 0.85x | 0.92x |
| reordered | 6,896 | 6,907 | 1.00x | 0.98x | 0.95x | 1.02x |
| late | 1,005 | 1,001 | 1.00x | 1.00x | 1.00x | 1.00x |
| negative | 61,868 | 58,524 | 0.95x | 0.99x | 0.99x | 0.72x |
| truncated | 18,809 | 18,073 | 0.96x | 0.97x | 0.94x | 1.06x |
| forward | 39,025 | 40,289 | 1.03x | 1.06x | 0.83x | 1.03x |
| asn-cold | 47,994 | 43,012 | 0.90x | 0.96x | 0.81x | 0.84x |
| asn-warm | 50,064 | 44,782 | 0.89x | 1.00x | 0.66x | 0.63x |

## Scale

Fixed concurrency 32 and 2ms fixture delay. Heap and allocation measurements
include the local DNS fixture, verifier, sampler, and garbage; they exclude
kernel socket buffers and do not prove an engine-only memory bound.

| Addresses | UDP addresses/s | Scheduler addresses/s | UDP B/address | Scheduler B/address | Scheduler peak heap MiB | Scheduler peak goroutines |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 11,322 | 11,241 | 4,531 | 4,698 | 2.66 | 72 |
| 4,096 | 11,504 | 11,500 | 4,333 | 4,508 | 2.79 | 72 |
| 16,384 | 11,673 | 11,560 | 4,286 | 4,463 | 2.74 | 72 |

## Interpretation and defaults

Individual attempts and forward queries now return through a bounded scheduler.
This provides retry fairness and shared pacing but adds queue, channel, and task
allocation overhead. Several fast loopback configurations regress, especially
warm ASN cases at high concurrency; this is not a universal throughput gain.
Delayed scaling stays within about 1% of the UDP baseline. Loss/late cases remain
timeout dominated. Three short samples are comparison evidence, not a claim of
statistical significance or remote resolver capacity.

The existing unpaced default is preserved to avoid an arbitrary throughput
change without measurements of the user's resolver. Neither these loopback
fixtures nor the earlier baseline establish safe remote rates. Explicit
`--rate` and `--resolver-rate` controls allow capacity-specific limits. No
external scan was performed. Timing tests and fake-clock scheduler tests verify
pacing separately from these unpaced throughput comparisons.

Admission tests verify at most twice concurrency tracked addresses, at most
concurrency active tasks, backpressure, and cancellation. Iterator tests cover
incremental /0 traversal and the final IPv4 address. Wire tests cover retry
fairness, pacing outside the initial attempt deadline, shared retry/A/TCP/system
fallback budgets, and cancellation; existing transport/CLI tests retain reply
validation, metadata, negative-answer, output-failure, and shutdown coverage.
ASN enrichment remains serialized and output remains unbuffered, for separate
issues #14 and #15.
