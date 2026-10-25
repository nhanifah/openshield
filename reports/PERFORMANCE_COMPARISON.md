# Performance Comparison

Baseline (commit `e646f5d`) against the current `main`, measured **back to back in one session**. Raw data: [`evidence/bench-ab-optimized.json`](evidence/bench-ab-optimized.json), [`evidence/memory-growth-ab-optimized-baseline.json`](evidence/memory-growth-ab-optimized-baseline.json), [`evidence/memory-growth-ab-optimized-current.json`](evidence/memory-growth-ab-optimized-current.json).

## Method

Four variants run inside every round, one after the other, in an order that rotates each round, so they share the same machine state:

1. **baseline**: commit `e646f5d`.
2. **current**: `main`, with intel off.
3. **current + intel**: `main` with the intelligence layer on, default settings.
4. **current + intel, store all**: as 3, but `store_all_events: true` and `per_client_per_sec: 0`, so every request is written to SQLite.

The upstream alone is measured every round as a drift control. There are five rounds, and each figure is the median of five 10-second runs.

```bash
python3 tests/bench/ab_bench.py --baseline-bin <openshield built from e646f5d> --rounds 5 --duration 10 --with-store-all --tag ab-optimized
```

Setup: Apple M4 (10 cores), macOS 26.5, `oha` with 64 connections, 4 proxy workers. Proxy, upstream and load generator share the machine, so compare variants within this run only.

**Machine state moves a lot between sessions.** The upstream alone ran at a median of 191,337 req/s in this run but 142,826 in the earlier one. Absolute numbers from different runs are not comparable, which is why every comparison here is within one run.

## Results

Requests per second (median). Percentages are against **baseline** for *current*, and against **current** for the two intel variants.

| Scenario | Baseline | Current | Current + intel | Intel, store all | p99 ms (base / cur / intel / all) | Max RSS MB (base / cur / intel / all) |
| --- | --- | --- | --- | --- | --- | --- |
| Proxy, no rules | 55,087 | 65,322 (+18.6%) | 60,407 (-7.5%) | 52,883 (-19.0%) | 2.30 / 2.01 / 2.22 / 2.64 | 37 / 38 / 67 / 99 |
| Rules, benign GET | 45,868 | 57,738 (+25.9%) | 52,323 (-9.4%) | 45,481 (-21.2%) | 2.69 / 2.29 / 2.56 / 2.97 | 36 / 38 / 68 / 101 |
| Rules, SQLi GET (blocked) | 64,488 | 111,313 (+72.6%) | 91,616 (-17.7%) | 81,332 (-26.9%) | 2.02 / 1.30 / 1.71 / 1.83 | 32 / 36 / 85 / 129 |
| Rules, 0.6 KB form POST | 31,789 | 34,412 (+8.2%) | 30,987 (-10.0%) | 27,618 (-19.7%) | 3.98 / 3.67 / 4.26 / 4.64 | 40 / 40 / 67 / 69 |

Drift control: upstream alone, median 191,337 req/s, range 180,525–191,640.

**Findings**

1. **Current is faster than baseline: +8.2% to +72.6%.** The profile points to two fixes to bugs that were already in baseline: the access log lock, and a stderr warning Pingora wrote on every request. The gain is largest for blocked attacks, where baseline also logged an `info!` line for every block. Each fix's share of the gain was not measured separately.
2. **The intelligence layer now costs 7.5–17.7% of throughput** against current with intel off; before the optimizations it cost 25–37%. With intel on, the proxy ranges from 2.5% slower (form POST) to 42.1% faster (blocked attacks) than baseline.
3. **Storing every request costs 19.0–26.9%** against current. Use `store_all_events: true` only when full retention is needed.
4. **Intel memory is now 67–85 MB peak with default settings**, against 96–361 MB before the optimizations.
5. **Not measured:** intel with AI analysis on. AI calls are asynchronous and bounded by their queue, so they should not add request latency, but that has not been benchmarked.

## What profiling found and what changed

Profile taken with macOS `sample` (12 s) on a symbolized release build, with intel on, at 64 connections.

| Cost found | Share | Change |
| --- | --- | --- |
| Access/audit log: one global lock held across a `write` syscall per request | ~12% of each worker's samples waiting on the lock | 64 KiB buffered writers flushed every 200 ms; formatting stays outside the lock |
| Pingora wrote "Upstream body is already finished" to stderr on every bodyless request when request-body rules exist (the request-body filter sent an empty chunk after the body ended) | `env_logger` lock and writes per request | Filter leaves the body as `None` |
| `getentropy` per request id | 461 samples | `uuid` with `fast-rng` |
| SQLite writer saturated: half its time in WAL checkpoints and `fsync` | writer thread 98% busy | Less frequent checkpoints, plus storage defaults below |
| Every event deep-copied into the in-memory ring; request data cloned on the proxy thread | `SecurityEvent::clone`, `String::clone` | Events shared as `Arc`; request data moved out of the finished transaction |
| A single flooding client made every request "notable", and all were stored | writer queue holding up to 256,000 events | Per-client storage budget (50/s), 1% sample of ordinary traffic, and a 16-batch writer queue |

Under the profiling load with intel on, throughput went from 17.5k to 26.5k req/s and RSS from 191 MB to 55 MB. That figure is from the profiling run; the table above is the controlled measurement.

## Memory under unique rate-limit keys

300,000 requests, each with a new key for a per-path rate-limit rule (`tests/bench/memory_growth.py`), both builds in the same session:

| Unique keys | Baseline RSS MB | Current RSS MB |
| --- | --- | --- |
| 0 | 25.7 | 24.9 |
| 100,000 | 38.1 | 31.8 |
| 200,000 | 51.0 | 32.9 |
| 300,000 | 72.8 | 33.0 |

Baseline grows linearly (+47 MB) and never frees the memory. Current rises a few MB until the mitigation table reaches its 100,000-key cap, then stays flat.

## Earlier run, before the optimizations (different session)

From [`evidence/bench-ab.json`](evidence/bench-ab.json), kept for the record. It used the same method, but its absolute numbers are not comparable with the run above.

| Scenario | Intel cost vs current | Intel max RSS |
| --- | --- | --- |
| Proxy, no rules | -31.2% | 194 MB |
| Rules, benign GET | -27.7% | 163 MB |
| Rules, SQLi GET (blocked) | -36.8% | 361 MB |
| Rules, 0.6 KB form POST | -25.2% | 96 MB |
