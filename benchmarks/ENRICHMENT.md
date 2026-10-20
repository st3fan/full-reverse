# Independent ASN enrichment comparison

Measured source: `75fbd5e51e2770b42de713bd210e2b500b8dffb0` (clean tree), 2026-10-20T12:07:52.901303+00:00.
Compared with `scheduler-throughput.json` / `scheduler-scale.json` on the same
machine, Go version, fixtures, unpaced settings, and three samples per case.

Raw reports: [throughput](enrichment-throughput.json), [scale](enrichment-scale.json).
All 132 throughput samples and nine scaling samples passed. Every configuration
preserved expected records, errors, retries, UDP PTR/A, TCP, and HTTP counts.

## Throughput

Medians of three single-scan samples; rates are input addresses/second.
Ratios are new throughput / previous throughput; above 1 is faster.
All configurations are shown, including regressions.

| Scenario | Previous c32 | New c32 | c32 ratio | c64 ratio | c128 ratio | c256 ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| fast | 46,975 | 60,597 | 1.29x | 1.13x | 1.29x | 1.24x |
| delayed | 11,092 | 11,398 | 1.03x | 1.01x | 1.05x | 1.15x |
| loss | 1,005 | 1,006 | 1.00x | 1.00x | 1.00x | 1.00x |
| duplicates | 47,274 | 55,224 | 1.17x | 1.22x | 1.10x | 1.03x |
| reordered | 6,907 | 6,934 | 1.00x | 1.00x | 1.08x | 1.05x |
| late | 1,001 | 1,006 | 1.00x | 1.00x | 1.00x | 1.00x |
| negative | 58,524 | 56,921 | 0.97x | 0.99x | 0.99x | 1.38x |
| truncated | 18,073 | 16,613 | 0.92x | 1.00x | 1.03x | 0.69x |
| forward | 40,289 | 11,894 | 0.30x | 0.59x | 0.60x | 0.56x |
| asn-cold | 43,012 | 29,310 | 0.68x | 0.65x | 0.78x | 0.66x |
| asn-warm | 44,782 | 28,225 | 0.63x | 0.68x | 1.14x | 1.10x |

## Scale

Fixed concurrency 32 and 2ms fixture delay. Allocations and heap include the local
DNS fixture, verifier, sampler, and garbage; kernel socket buffers are excluded.
They do not prove an engine-only memory bound.

| Addresses | Previous addresses/s | New addresses/s | Previous B/address | New B/address | New peak heap MiB | New peak goroutines |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 11,241 | 11,631 | 4,698 | 4,746 | 2.81 | 72 |
| 4,096 | 11,500 | 11,745 | 4,508 | 4,541 | 2.81 | 72 |
| 16,384 | 11,560 | 11,781 | 4,463 | 4,496 | 2.75 | 72 |

## Interpretation

DNS and metadata now run independently, joining only before output. The blocked
HTTP fixture proves a slow RIPE request no longer consumes DNS slots, while an
unrelated AS-name request and cached records still progress. Four metadata
workers and a shared admission window bound unfinished joins. Prefix and name
requests each have one lane, so enrichment makes at most two simultaneous HTTP
requests. Prefix discovery rechecks learned ranges after waiting rather than
assuming adjacent addresses share a prefix.

Cold cases still make exactly one HTTP request; warm cases make zero. The
additional producer, queue, and join synchronization imposes overhead on fast
loopback ASN cases (c32 cold 0.68x and warm 0.63x of the scheduler baseline).
This change addresses blocking and backpressure, not an across-the-board speed
increase. The full table includes high-concurrency improvements and regressions.
These short three-sample cases do not establish statistical significance or
remote service capacity. No external scan was performed.

All admitted addresses requiring metadata are enriched, including addresses
without a reported PTR. API failures remain best effort, warnings are retained,
and positive-prefix precedence and unknown-AS caching are covered by tests.
