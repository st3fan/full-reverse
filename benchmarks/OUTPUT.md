# Buffered output comparison

Measured source: `797f9ced89c1ab1e5e15bdb7f3f1321b9ad77b65` (clean tree), 2026-10-20T12:13:55.094469+00:00.
Compared with `enrichment-throughput.json` / `enrichment-scale.json` on the same
machine, Go version, fixtures, unpaced settings, and three samples per case.

Raw reports: [throughput](output-throughput.json), [scale](output-scale.json).
All 132 throughput samples and nine scaling samples passed. Every configuration
preserved expected records, errors, retries, UDP PTR/A, TCP, and HTTP counts.

## Throughput

Medians of three single-scan samples; rates are input addresses/second.
Ratios are new throughput / previous throughput; above 1 is faster.
All configurations are shown, including regressions.

| Scenario | Previous c32 | New c32 | c32 ratio | c64 ratio | c128 ratio | c256 ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| fast | 60,597 | 55,776 | 0.92x | 1.02x | 0.86x | 1.03x |
| delayed | 11,398 | 11,540 | 1.01x | 1.00x | 0.97x | 0.78x |
| loss | 1,006 | 1,006 | 1.00x | 1.00x | 1.00x | 1.00x |
| duplicates | 55,224 | 50,828 | 0.92x | 0.92x | 0.94x | 0.96x |
| reordered | 6,934 | 6,831 | 0.99x | 0.99x | 0.98x | 0.96x |
| late | 1,006 | 1,008 | 1.00x | 1.00x | 1.00x | 1.00x |
| negative | 56,921 | 60,350 | 1.06x | 0.88x | 1.01x | 0.96x |
| truncated | 16,613 | 15,797 | 0.95x | 1.00x | 1.08x | 1.26x |
| forward | 11,894 | 37,287 | 3.13x | 1.67x | 1.59x | 1.59x |
| asn-cold | 29,310 | 54,848 | 1.87x | 2.09x | 1.81x | 2.18x |
| asn-warm | 28,225 | 57,939 | 2.05x | 1.86x | 1.32x | 1.68x |

## Scale

Fixed concurrency 32 and 2ms fixture delay. Allocations and heap include the local
DNS fixture, verifier, sampler, and garbage; kernel socket buffers are excluded.
They do not prove an engine-only memory bound.

| Addresses | Previous addresses/s | New addresses/s | Previous B/address | New B/address | New peak heap MiB | New peak goroutines |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 11,631 | 11,799 | 4,746 | 4,817 | 2.83 | 73 |
| 4,096 | 11,745 | 11,943 | 4,541 | 4,563 | 2.92 | 73 |
| 16,384 | 11,781 | 12,044 | 4,496 | 4,512 | 2.77 | 73 |

## Dense output

[Raw dense report](output-dense.json), same clean revision. Each operation
serializes 10,000 identical complete records from 32 producers. The direct mode
models the previous per-record JSON encoding and mutex-protected write. Buffered
mode uses the new owner and includes startup, draining, and flushing. `discard`
is an in-memory sink; `/dev/null` includes actual write syscalls. Both validate
the expected total byte count; full-engine fixtures additionally parse fields
and check each address for duplicates and completeness.

| Sink | Mode | Median milliseconds / 10,000 records | Writes / 10,000 records | Allocated B / record |
| --- | --- | ---: | ---: | ---: |
| discard | direct | 3.48 | 10,000 | 354 |
| discard | buffered | 7.70 | 20 | 360 |
| devnull | direct | 10.67 | 10,000 | 354 |
| devnull | buffered | 5.70 | 20 | 360 |

## Interpretation

Buffering substantially reduces underlying write calls by batching records.
Encoding, channel handoff, and owner scheduling still cost CPU, so fewer writes
do not guarantee a faster in-memory or short loopback workload. The dense table
and full engine table show measured timings rather than assuming syscall savings
translate directly to throughput. Three short samples do not establish
statistical significance or performance for every output sink.

The queue holds at most 64 records plus the owner's current record, with a
64 KiB byte buffer and bounded producer backpressure. Full buffers flush as
needed; a 100 ms timer flushes partial output during the scan. Normal completion
and cancellation drain accepted records before returning. Writer failures
(including short/zero writes and final flushes) cancel work and fail the run.
Tests cover these policies, concurrent line integrity, immediate stderr logging,
and prompt DNS cancellation after a streaming output failure.

All benchmark completeness, metadata, retry, API, and wire-count expectations
remain unchanged. No external scan was performed.

To repeat the dense comparison (choose a fresh output filename):

```sh
python3 scripts/benchmark.py --bench '^BenchmarkJSONLOutput$' --output /tmp/dense-comparison.json
```
