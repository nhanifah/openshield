# Test execution report

Every number here was measured in this session. Nothing is estimated.

## Environment

- macOS (Darwin 25.5), release build of this working tree (uncommitted changes).
- Live stack: `python3 tests/dashboard/live_stack.py --port-offset 100`, dashboard on `http://127.0.0.1:19290` (and `http://localhost:19290` for passkeys), proxy on 18190, synthetic traffic at 20 req/s.
- Browser: Claude's built-in browser (Chromium) with viewport emulation. Widths below 768 px also emulate a mobile user agent and touch.
- Test tokens were generated per run by `live_stack.py` into a 0600 file in the session scratchpad; they are not recorded here.

## Commands

```bash
cargo build --release --workspace
cargo test --workspace
python3 tests/dashboard/live_stack.py --port-offset 100 --token-file <scratchpad>/tokens.json
python3 tests/dashboard/inject_audit.py      # script pasted into the browser per width
node --check crates/openshield-intel/assets/app.js
node --check tests/dashboard/ui_audit.js
wc -c crates/openshield-intel/assets/{app.js,app.css,index.html}
```

## Results

| Suite | Result | Evidence |
|---|---|---|
| Release build | OK, no warnings shown | – |
| `cargo test --workspace` | **727 passed, 0 failed, 0 ignored** (10 test binaries) | `reports/evidence/ui-audit/unit-tests.txt` |
| JS syntax (`node --check`) | OK for `app.js` and `ui_audit.js` | – |
| Asset size budget (about 210 KB) | 209,994 bytes (was 206,010) | – |
| `ui_audit.js` sweep, final build | **336 audits, total 0** (14 routes × 2 themes × 12 widths) | `reports/evidence/ui-audit/ui-sweep-final.json` |
| `ui_audit.js` sweep, original build | 308 audits (11 widths); 2 real hits at 320 px (uneven KPI, both themes) + 1 false positive at 1024 px (T-01) | this report |
| Audit self-test (T-02) | UX-01 re-created in the page: `offscreenFocusable` = 10; fixed build: 0 | this report |
| `tests/e2e/run_e2e.py --tag ui-audit` (full, slow tests included) | **29/29 passed** | `reports/evidence/e2e-ui-audit.json` |
| `tests/e2e/run_intel_e2e.py --tag ui-audit` | **27/27 passed** (covers the summary `model` field change, dashboard CSP and no-cache headers, passkeys) | `reports/evidence/e2e-intel-ui-audit.json` |
| Browser task flows | 10 of 10 pass on the final build (see `USABILITY_TEST_REPORT.md`) | screenshots |
| Console | No script exceptions. Network errors traced to the test stack restarts and deliberate bad-token tests | – |
| Lab performance | CLS 0 on Overview load; DOMContentLoaded 20 ms (localhost); LCP and INP not recorded (background pane) | this report |

Widths: 1920, 1600, 1440, 1282, 1280, 1024, 768, 412, 390, 375, 360, 320 px. Heights varied (640–1080 px).

## Not run

| Suite | Why | How to run |
|---|---|---|
| Benchmarks | Not affected by UI changes; `CLAUDE.md` says not to run them alongside other work | – |
| axe-core / Lighthouse | No Node tooling in the repo; CSP blocks CDN scripts in the page | – |
| Screen reader, real devices, Safari/Firefox | Not available in this environment | – |

## E2E run notes

Both suites bind fixed ports, so the `live_stack.py --setup` instance was stopped first, at your request, and restarted afterwards with the same command (data in `.openshield-local` kept).

The first intel run reported 1/27: between the two suites, another Claude Code session on this machine relaunched `live_stack.py --setup`, so the suite's proxy could not bind 19190 ("Address already in use") and the tests hit the setup instance instead. That instance was stopped again and the suite rerun at once: 27/27, with nothing else on the ports. The evidence file holds the clean run.

## Regressions found and resolved during the pass

- The Events Time column was still clipped by 2 px after the switch to tabular digits; widened to 104 px, with the Request minimum reduced to keep the 1040 px total.
- The first version of the new `offscreenFocusable` check missed UX-01: the menu scrolls vertically, so it counts as a sideways scroller too. The check now skips a control only when its scroller is itself on screen. Re-tested: 10 hits with the bug, 0 without.
- After controls were removed, focus fell back to the view; it now goes to the card's own control ("Add block…").
- Asset size went over budget twice during fixes; it was brought back under by shortening comments, removing unused CSS and deduplicating two strings. No features were removed.
