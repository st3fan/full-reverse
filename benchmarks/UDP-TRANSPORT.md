# Persistent UDP transport comparison

Measured source: `f457dab801710f27e8c9e24e323395d3942a049d` (clean tree), 2026-10-20T02:00:28.037655+00:00.
Baseline source: `579b4752abbc8c1389d85346888121b059d8372a`. Both use go1.27.2, linux/amd64, Intel N150, four logical CPUs and the same harness/settings.

Raw reports: [throughput](udp-throughput.json), [scale](udp-scale.json). The [baseline](BASELINE.md) and [methodology](README.md) describe the fixtures and measurement limits.

All 132 throughput samples and nine scaling samples passed. Every configuration retained identical expected record/error counts, DNS attempt counts, retries, TCP queries, and HTTP requests. No external scan was performed.

## Throughput

Each cell uses medians of three single-scan samples. Ratios are new throughput / baseline throughput; above 1 is faster. All configurations are shown, including regressions. Rates are input addresses/second, including expected missing and failed outcomes.

| Scenario | Baseline c32 | New c32 | c32 ratio | c64 ratio | c128 ratio | c256 ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| fast | 42,593 | 54,977 | 1.29x | 1.31x | 1.26x | 1.16x |
| delayed | 10,867 | 11,340 | 1.04x | 0.99x | 1.13x | 2.36x |
| loss | 1,003 | 1,003 | 1.00x | 1.00x | 1.00x | 1.01x |
| duplicates | 40,436 | 49,830 | 1.23x | 1.17x | 1.25x | 1.51x |
| reordered | 7,017 | 6,896 | 0.98x | 0.99x | 0.97x | 1.04x |
| late | 1,002 | 1,005 | 1.00x | 1.00x | 1.00x | 1.01x |
| negative | 43,091 | 61,868 | 1.44x | 1.27x | 1.35x | 1.42x |
| truncated | 18,211 | 18,809 | 1.03x | 1.19x | 1.04x | 1.04x |
| forward | 29,924 | 39,025 | 1.30x | 1.21x | 1.50x | 1.33x |
| asn-cold | 45,072 | 47,994 | 1.06x | 0.93x | 1.26x | 1.66x |
| asn-warm | 49,848 | 50,064 | 1.00x | 1.02x | 1.08x | 1.08x |

## Scale and allocation

Fixed concurrency 32 and 2ms fixture delay. Allocation figures include the engine, in-process DNS fixture, streaming verifier, and sampler. Peak heap excludes kernel socket buffers and can miss short-lived peaks.

| Addresses | Baseline addresses/s | New addresses/s | Baseline allocated B/address | New allocated B/address | Baseline peak heap MiB | New peak heap MiB | New peak goroutines |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 10,966 | 11,322 | 5,309 | 4,531 | 2.88 | 2.61 | 72 |
| 4,096 | 11,011 | 11,504 | 5,275 | 4,333 | 2.82 | 2.79 | 72 |
| 16,384 | 11,051 | 11,673 | 5,273 | 4,286 | 2.68 | 2.69 | 72 |

## Interpretation

Persistent sockets remove per-UDP-exchange dialing and share one receiver per endpoint. Each run now pays for initial ID-pool randomization and a receive buffer; the 256-address suite includes that startup cost. TCP remains per exchange, and TCP validation is stricter.

The timeout-dominated loss/late fixtures remain near the fixed 250ms retry floor. This transport change intentionally leaves retry scheduling, rate control, and ASN-enrichment concurrency unchanged. Short loopback cases show scheduling variability; three samples are comparison evidence rather than a statistically established improvement across networks.

The scale suite checks completeness while input count increases 16x. Its process-memory measurements include fixture overhead and garbage, and do not prove a strict engine-only bound. The receiver requests a 4MiB OS buffer per socket (subject to OS caps), which is outside Go heap accounting.

Adversarial transport tests cover stale IDs and identical repeated questions, rotation/exhaustion, source/question/flag mismatches, malformed packets, cancellation, ICMP refusal recovery, and shutdown. These complement the synthetic throughput fixtures, which do not model NAT tuple rewriting or real recursive resolver caches.
