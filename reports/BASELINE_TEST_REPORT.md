# Baseline Test Report

Snapshot of OpenShield **v0.2.0 at commit `e646f5d`** (branch `main`) before any change in this work. Every number below was measured on that commit. Raw outputs are in [`reports/evidence/`](evidence/).

## 1. Environment

| Item | Value |
| --- | --- |
| Machine | Apple M4, 10 cores, 16 GB RAM, macOS 26.5 (arm64) |
| Toolchain | rustc 1.97.1, cargo 1.97.1 |
| Load generator | `oha` 1.16.0, running on the same machine as the proxy |
| Upstream | `echo-upstream` (hyper 1, added in `crates/openshield-testkit`) |
| Proxy workers | 4 (`workers: 4`) |

**Build prerequisite found:** a release build fails without `cmake` (needed by `libz-ng-sys`, pulled in by Pingora). The README does not list it. Installed with `brew install cmake`.

## 2. Methodology

| Area | How it was tested | Command |
| --- | --- | --- |
| Unit and integration tests | Existing Rust test suite | `cargo test --workspace` |
| Lint | Clippy, all targets | `cargo clippy --workspace --all-targets` |
| Format | rustfmt | `cargo fmt --check` |
| Dependencies | RustSec advisory DB | `cargo audit` |
| Functional and security (black box) | 29 tests over raw TCP sockets against a running proxy and the echo upstream. Two proxy instances: JSON logging (`:18080`) and text logging (`:18081`). | `python3 tests/e2e/run_e2e.py --tag baseline` |
| Throughput and latency | `oha`, 64 connections, 10 s per run, 3 runs per scenario after a 2 s warm-up; median reported. CPU and RSS sampled with `ps` every 0.5 s. | `python3 tests/bench/run_bench.py --tag baseline` |
| Memory growth | 300,000 requests with unique paths against a per-path rate-limit rule | `python3 tests/bench/memory_growth.py --tag baseline` |
| Code review | Manual reading of the request path: `proxy/mod.rs`, `transaction.rs`, `engine.rs`, `ratelimit.rs`, `challenge.rs`, `logging/` | — |

Each e2e test encodes the **secure** expectation, so a failure is a finding.

## 3. Results

### 3.1 Build, unit tests, lint

| Check | Result |
| --- | --- |
| `cargo build --release` | Pass (after installing cmake) |
| `cargo test --workspace` | **604 passed**, 0 failed (`openshield-core` 181, `openshield-openapi` 418, `openshield-pingora` 5) — [evidence](evidence/unit-tests-baseline.txt) |
| `cargo clippy` | 0 errors, 13 style warnings (collapsible `if`, missing `Default`, `map_or`) |
| `cargo fmt --check` | Pass |
| CI | Only a release workflow on tags. **No CI runs tests, lint, or audit on pushes or PRs.** |

### 3.2 Dependency audit

`cargo audit`: **16 vulnerabilities** and 9 warnings across 434 crates — [full output](evidence/cargo-audit-baseline.txt).

| Crate | Advisories | Highest severity | Fix |
| --- | --- | --- | --- |
| quinn-proto 0.11.14 | 5 (incl. RUSTSEC-2026-0185 remote memory exhaustion, RUSTSEC-2026-0340 panic) | 7.5 high | ≥ 0.11.18 |
| rustls 0.23.37 | 4 (incl. RUSTSEC-2026-0285 handshake boundary) | 5.3 medium | ≥ 0.23.46 |
| rustls-webpki 0.103.9 | 5 (incl. CRL parsing panic) | — | upgrade |
| ctutils 0.4.2 | Non-constant-time comparisons | — | ≥ 0.4.4 |
| tokio, rand, chacha20, spin, others | 1 each, or unmaintained warnings | — | upgrade |

### 3.3 Functional and security tests (e2e)

**22 of 29 passed** — [evidence](evidence/e2e-baseline.json).

| ID | Test | Result | Observed |
| --- | --- | --- | --- |
| F01 | Benign GET proxied | Pass | 200 |
| F02 | SQLi in query blocked | Pass | 403 |
| F03 | XSS in query blocked | Pass | 403 |
| F04 | SQLi in form body blocked | Pass | 403 |
| F05 | `/admin` path rule | Pass | 403 |
| F06 | Rate limit (5 per 10 s) | Pass | 200×5, then 429 |
| F07 | Response body redaction | Pass | `[redacted]` |
| F08 | X-Forwarded-For / X-Real-IP | Pass | appended correctly |
| **F09** | **Body over `max_request_body_buffer` with `reject` gets 413** | **Fail** | **200, full 70 KB body forwarded** |
| F10 | Malformed request line | Pass | 400 |
| F11 | SQLi in multipart field | Pass | 403 |
| F12 | 200 concurrent requests | Pass | 0 errors |
| F13 | Upstream status passthrough | Pass | 503 |
| F14 | JSON access log with request ID | Pass | — |
| F15 | Audit log names the rule | Pass | — |
| **S01** | **Non-ASCII header value hides SQLi from header rules** | **Fail (high)** | ASCII payload 403; same payload after a `0xE9` byte **200** |
| **S02** | **Path variants bypass a path rule** | **Fail (medium)** | `/%61dmin`, `//admin`, `/./admin`, `/admin/`, `/foo/../admin` all 200 |
| S03 | CL.TE smuggling | Pass | Single response, nothing smuggled |
| S04 | Conflicting duplicate Content-Length | Pass | 400 |
| S05 | Obfuscated Transfer-Encoding | Pass | 400 |
| **S06** | **Secrets in audit log** | **Fail (medium)** | `Authorization` and `Cookie` values written verbatim |
| **S07** | **Text audit log, multi-byte char at byte 500** | **Fail (high)** | **Worker panic** (`byte index 500 is not a char boundary`), audit entry lost |
| **S08** | **Log line forgery in text audit log** | **Fail (medium)** | Body newline produced a forged `[AUDIT]` line |
| S09 | Spoofed X-Forwarded-For vs rate limit | Pass | still 429 |
| **S10** | **Oversized header block** | **Fail (low)** | 200 KB header accepted and forwarded |
| S11 | Absolute-form URI | Pass | 400 |
| S12 | Null byte before SQLi | Pass | 403 |
| S13 | Burst of malformed connections | Pass | still serving |
| S14 | Slowloris half-open connection | Pass | closed after 60 s |

### 3.4 Performance

Median of 3 × 10 s runs, 64 connections, 4 workers — [evidence](evidence/bench-baseline.json).

| Scenario | req/s | p50 ms | p95 ms | p99 ms | Proxy CPU (avg) | Proxy RSS (max) |
| --- | --- | --- | --- | --- | --- | --- |
| Upstream direct (reference, no proxy) | 155,156 | 0.29 | 0.97 | 2.62 | — | — |
| Proxy, no rules | 33,071 | 1.69 | 3.66 | 5.95 | 248% | 34.4 MB |
| Proxy, 7 rules, benign GET | 36,312 | 1.54 | 3.29 | 5.49 | 277% | 34.5 MB |
| Proxy, 7 rules, SQLi GET (all blocked) | 52,728 | 1.09 | 2.32 | 3.81 | 258% | 29.8 MB |
| Proxy, 7 rules, 0.6 KB form POST | 24,340 | 2.34 | 4.87 | 7.75 | 307% | 38.7 MB |

Notes:

- Run-to-run spread was up to ±10% through the proxy and up to 20% for the direct upstream (124k–156k). Differences under about 10% are noise.
- Proxy-with-rules was not slower than proxy-without-rules. Rule evaluation is cheap next to proxying cost. Blocked requests are faster because no upstream hop happens.
- All three processes share one machine, so these are lower bounds, not capacity figures.

### 3.5 Memory growth

300,000 unique keys against a per-path rate-limit rule — [evidence](evidence/memory-growth-baseline.json):

| Unique keys | RSS |
| --- | --- |
| 0 | 26.1 MB |
| 100,000 | 29.1 MB |
| 200,000 | 43.4 MB |
| 300,000 | 59.0 MB |

About **115 bytes per key, never freed**: the rate limiter's mitigation table (`RuleLimiter::mitigated`) only removes a key when that same key returns after its timeout. An attacker who controls a key characteristic (path, user agent, or IPv6 source) can grow memory without bound.

## 4. Findings from code review

These were found by reading the code. Where a test was possible, it is listed above.

| # | Finding | Location | Severity |
| --- | --- | --- | --- |
| R1 | **Open redirect**: after a successful Turnstile check the proxy redirects to the `redirect` form field without validation, so a link can send users to any external site | `proxy/mod.rs` `handle_challenge_verify` | Medium |
| R2 | Turnstile verification builds a new HTTP client per call **with no timeout**. A slow Cloudflare API holds the request open indefinitely | `challenge.rs` `verify_turnstile` | Medium |
| R3 | Request-body size limit check runs only when `!end_of_stream`. When the over-limit bytes arrive in the final chunk, `reject` is skipped and the uninspected tail is forwarded (confirmed by F09) | `transaction.rs` `request_body_chunk` | **High** |
| R4 | Header values that are not visible ASCII become `""` for the rules but reach the upstream unchanged (confirmed by S01) | `proxy/mod.rs` `header_pairs` | **High** |
| R5 | Each block logs an `info!` line through `env_logger` (global lock and stderr write) on the hot path. A flood of attacks also floods stderr | `engine.rs` `evaluate` | Low |
| R6 | Response-header block verdicts are evaluated but ignored. This is documented in a code comment, not in the user docs | `proxy/mod.rs` `upstream_response_filter` | Low |
| R7 | `parse_upstream` panics on an invalid port and mishandles bracketed IPv6 literals | `main.rs` | Low |
| R8 | No trusted-proxy setting, so behind a load balancer every client shares one `ip.src` (rate limits and IP rules then act on the balancer) | `proxy/mod.rs` `client_ip` | Info |
| R9 | Audit headers are collected into a `HashMap`, so repeated headers lose all but one value | `transaction.rs` `finish` | Low |
| R10 | Only one metric dimension: totals for requests, bytes and connections. No per-decision, per-rule, or latency metrics, and no health endpoint | `proxy/metrics.rs` | Info |
| R11 | No AI, anomaly detection, dashboard, admin API, or event store exists in the code | whole repo | Info (feature gap) |

## 5. Summary of problems to fix

| Priority | Item |
| --- | --- |
| High | R3/F09 body-limit bypass · R4/S01 header bypass · S07 logging panic · 16 dependency advisories |
| Medium | S02 no normalized path · S06 secrets in audit log · S08 log forgery · R1 open redirect · R2 missing timeout · unbounded mitigation table |
| Low | S10 header size limit · R5 hot-path logging · R7 upstream parsing · R9 duplicate headers |
| Process | No CI for tests, lint, audit, or secret scanning · cmake missing from build docs |
