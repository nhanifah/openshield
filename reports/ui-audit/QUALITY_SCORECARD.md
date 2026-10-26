# Quality scorecard

Scores are judgements based on the evidence in this folder, not measurements. Each category starts at 100. Points are taken off for **open** findings, by severity, and for gaps in verification (things not tested lower confidence and the score):

- −15 per open high finding
- −6 per open medium finding
- −2 per open low finding
- −5 to −15 for an untested area, depending on its weight

No category gets 100: every one has at least one verification gap. UX-O2 (asset size budget spent) is a maintainability risk and is not scored here.

| Category | Score | Open findings / gaps that cost points | Confidence |
|---|---|---|---|
| Visual consistency | 93 | 336 audits at 0; eyeballed every view. Gap: Safari/Firefox not rendered (−5); "elev" abbreviation (−2) | High |
| Component quality | 88 | Tables lack density option (UX-O1, −6); modal errors not field-bound (UX-O5, −2); passkey registration not re-run (−4) | Medium-high |
| Responsive design | 90 | 12 widths, no page sideways scroll. Gap: emulation only, no real device, virtual keyboard or landscape phone (−10) | Medium |
| Interaction reliability | 89 | All 10 flows pass with real key presses. Gap: Apply, rollback, settings save and dataset export not exercised (−8); stale-401 race found late, so similar races may exist (−3) | Medium |
| Navigation and information architecture | 92 | Status-first Overview, drill-down links, role-aware nav. Phone menu does not trap Tab (UX-O7, −2); duplicate alert fetches (−2); gap: no IA test with users (−4) | Medium-high |
| Usability | 84 | Simulated tasks only, no human participants (−10); density (−6) | Low-medium |
| Accessibility | 80 | Focus, contrast and labels verified. Gap: no screen reader, no axe, no 200 % zoom (−15); UX-O5 and UX-O7 (−4); "Admin token" label (−1) | Medium |
| Perceived performance | 82 | CLS 0, skeleton loading. Uncompressed, uncached 200 KB per load (UX-O3, −2); LCP/INP not measured (−10); duplicate requests (−2); no throttled-network test (−4) | Low-medium |
| Error handling | 90 | Validation, locked states, expiry vs sign-out fixed. Gap: network-failure and slow-network paths seen only during restarts, not tested on purpose (−8); UX-O5 (−2) | Medium |
| Regression test confidence | 92 | 727 unit tests, e2e 29/29 and 27/27 pass; audit extended and self-tested. No pixel baseline (−4); the audit runs by hand-pasting, not in CI (−4) | Medium-high |

## Overall: 88 / 100 (weighted)

Weights follow what operators depend on most in an incident: being able to act, and act correctly.

| Category | Weight | Weighted |
|---|---|---|
| Interaction reliability | 15 % | 13.4 |
| Accessibility | 15 % | 12.0 |
| Usability | 12 % | 10.1 |
| Error handling | 10 % | 9.0 |
| Navigation and IA | 10 % | 9.2 |
| Responsive design | 10 % | 9.0 |
| Visual consistency | 8 % | 7.4 |
| Component quality | 8 % | 7.0 |
| Regression test confidence | 7 % | 6.4 |
| Perceived performance | 5 % | 4.1 |
| **Total** | 100 % | **87.65** (rows shown rounded) |

The fastest ways to raise it:

1. Do a screen-reader pass.
2. Measure LCP/INP with the pane in the foreground or with Lighthouse.
3. Decide the size budget so the density toggle can land.
