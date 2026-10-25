# Performance Comparison

Baseline (commit `e646f5d`) against the current PR branch, measured **back to back in one session**. Raw data: [`evidence/bench-ab.json`](evidence/bench-ab.json), [`evidence/memory-growth-ab-baseline.json`](evidence/memory-growth-ab-baseline.json), [`evidence/memory-growth-ab-current.json`](evidence/memory-growth-ab-current.json).

## Why this run replaces the earlier comparison

The first "after" benchmark ran about an hour after the baseline and showed 22–27% lower proxy throughput. The direct-to-upstream control, which no change here touches, dropped about 26% in the same run, so most of that gap was the machine, not the code. This run removes that effect:

- Baseline, current, and current-with-intel run inside every round, one after the other.
- Their order rotates each round, so none of them always runs first or last.
- The upstream alone is measured each round as a drift control.
- Five rounds; each figure is the median of the five 10-second runs.

Command:

```bash
python3 tests/bench/ab_bench.py --baseline-bin <openshield built from e646f5d> --rounds 5 --duration 10 --tag ab
```

Setup: Apple M4 (10 cores), macOS 26.5, `oha` with 64 connections, 4 proxy workers. Proxy, upstream and load generator share the machine, so these are relative figures, not capacity.

## Throughput and latency

| Scenario | Baseline req/s | Current req/s | Current vs baseline | Current + intel req/s | Intel cost | p99 ms (base / cur / intel) | Max RSS MB (base / cur / intel) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Proxy, no rules | 38,810 | 39,374 | +1.5% | 27,094 | -31.2% | 6.41 / 5.83 / 9.28 | 38 / 32 / 194 |
| Rules, benign GET | 32,493 | 32,280 | -0.7% | 23,353 | -27.7% | 6.76 / 6.61 / 9.95 | 39 / 33 / 163 |
| Rules, SQLi GET (blocked) | 52,487 | 54,320 | +3.5% | 34,353 | -36.8% | 4.26 / 4.20 / 8.20 | 35 / 31 / 361 |
| Rules, 0.6 KB form POST | 23,099 | 24,030 | +4.0% | 17,982 | -25.2% | 8.49 / 8.52 / 12.17 | 41 / 38 / 96 |

Drift control: upstream alone, median 142,826 req/s, range 118,491–149,090 across the five rounds.

**Findings**

1. **The security fixes cost no measurable throughput.** Current is between −0.7% and +4.0% of baseline. Per-round ranges overlap fully, for example benign GET 28,244–32,905 for baseline and 27,839–33,809 for current.
2. **The intelligence layer costs 25–37% throughput and adds 3–4 ms at p99** in these scenarios. The likely causes, not yet profiled, are event building, redaction and the batched SQLite writes on the intel runtime, all competing with the proxy for the same CPU cores. Peak RSS rises to 96–361 MB; the in-memory recent-event ring (20,000 events) and simulation snapshots (2,000 requests) are the likely main holders.
3. **What was not measured:** the intel layer with AI analysis on. Every AI call is asynchronous and bounded by the queue, so it should not add request latency, but that has not been benchmarked.

**Tuning if the intel cost matters:** lower `intel.events.recent_capacity` and `snapshot_capacity`, or set `intel.store.store_all_events: false` to store only notable events. Statistics still count every request. These settings have not been benchmarked yet.

## Memory under unique rate-limit keys

300,000 requests, each with a new key for a per-path rate-limit rule (`tests/bench/memory_growth.py`), both builds in the same session:

| Unique keys | Baseline RSS MB | Current RSS MB |
| --- | --- | --- |
| 0 | 26.2 | 25.6 |
| 100,000 | 39.7 | 33.2 |
| 200,000 | 51.8 | 20.7 |
| 300,000 | 70.0 | 20.7 |

Baseline grows by about 44 MB and never frees it. Current stays flat because the mitigation table is capped and expired entries are swept.
