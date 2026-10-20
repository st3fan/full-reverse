# Initial local baseline

Measured revision: `579b4752abbc8c1389d85346888121b059d8372a` (clean source tree).
The application code is the engine extracted in PR #17; this revision adds only benchmark/test tooling and documentation.

Environment: go1.27.2, linux/amd64, Intel(R) N150, 4 logical CPUs.
Started: 2026-10-20T01:32:23.125028+00:00. GOMAXPROCS was unset; benchmark names record the runtime setting (`-4`).

Raw samples, environment, commands, timestamps, and output are preserved in [throughput](baseline-throughput.json) and [scale](baseline-scale.json) reports.
All 132 throughput samples and 9 scale samples passed record/metadata and exact query-count verification.
No external network targets were scanned. Timing includes fixture and streaming verification overhead; see the [methodology](README.md).

## Throughput

Median addresses/second across three independent single-scan samples. Every throughput scan contains 256 addresses.

| Scenario | c32 | c64 | c128 | c256 |
| --- | ---: | ---: | ---: | ---: |
| fast | 42,593 | 40,497 | 46,708 | 53,266 |
| delayed | 10,867 | 19,399 | 27,898 | 17,929 |
| loss | 1,003 | 1,004 | 1,006 | 1,007 |
| duplicates | 40,436 | 45,828 | 45,180 | 36,637 |
| reordered | 7,017 | 12,133 | 17,851 | 23,499 |
| late | 1,002 | 1,003 | 1,006 | 1,008 |
| negative | 43,091 | 48,813 | 47,710 | 48,885 |
| truncated | 18,211 | 16,717 | 18,542 | 18,205 |
| forward | 29,924 | 32,984 | 31,555 | 30,850 |
| asn-cold | 45,072 | 48,077 | 37,979 | 29,767 |
| asn-warm | 49,848 | 48,045 | 50,538 | 54,352 |

## Scaling

Concurrency 32, fixed 2ms reply delay. Values below are medians; memory/goroutine values are observed process samples, not engine-only bounds.

| Addresses | Time (ms) | Addresses/s | Allocated bytes/address | Peak heap delta (MiB) | Peak goroutines | Peak DNS handlers |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 93.4 | 10,966 | 5,309 | 2.88 | 71 | 32 |
| 4,096 | 372.0 | 11,011 | 5,275 | 2.82 | 71 | 32 |
| 16,384 | 1,482.6 | 11,051 | 5,273 | 2.68 | 71 | 33 |

## Interpretation

These results establish comparison points, not proposed defaults. The synthetic loss/late workloads are dominated by the fixed 250ms retry timeout; additional concurrency cannot remove that delay. Delay-sensitive workloads can benefit from additional concurrent work, while immediate loopback replies are sensitive to scheduling noise.

Compare complete sample distributions, query counts, and correctness before claiming improvement. The scale measurements expose observed memory and concurrency behavior across a 16x address-count increase; fixture state, garbage collection, and sampled peaks prevent treating them as proof of a strict engine memory bound.

Reports were captured sequentially, with no other validation/benchmark command deliberately running alongside them. They do not establish representative recursive DNS performance over the internet.
