# Dashboard UI/UX audit

Date: 2026-10-25. Scope: the OpenShield operations console (`crates/openshield-intel/assets/`: `index.html`, `app.css`, `app.js`), the only user interface in the repository. The proxy, validator and test kit have no UI.

## Summary

The console was already in good shape: an earlier pass (commit `efe098a`) fixed most visual defects and added `tests/dashboard/ui_audit.js`. That audit reported almost no problems before this pass (1 real hit at 320 px, 1 false positive), but inspecting and using the app in the browser found **21 defects** the audit could not see. Most were keyboard focus and interaction problems, not layout.

All 21 are fixed and verified in the built-in browser. Three gaps in the audit tooling were fixed as well, so two classes of these defects are now caught automatically. Seven findings are documented but not fixed (see "Unresolved").

Most important fixes:

- **Keyboard focus survives live updates.** Alerts re-rendered on every stream message, and Overview and Controls every 30 s, which threw a keyboard user back to the top of the page. Busy buttons were disabled while focused, which did the same.
- **One Enter no longer blocks a client.** The Block dialog opened with focus in a pre-filled IP field. High-impact dialogs now open on Cancel, or on the first empty field.
- **The closed phone menu no longer holds 10 invisible tab stops.**
- **Row actions are always reachable.** At 1181–1560 px, Overview's Block buttons sat behind a sideways scroll.
- **Sign-out says "Signed out."** It used to say the session had expired, because of a race with a pending background request.

## Method

1. Read `CLAUDE.md` (the dashboard UI rules are the design system), the three asset files, the admin API and the existing test tools.
2. Ran a live stack (`tests/dashboard/live_stack.py --port-offset 100`: real proxy, echo upstream, mock Gemini, synthetic traffic with attacks, floods and scanners) and drove it in Claude's built-in browser.
3. Ran `ui_audit.js` on 14 routes (9 views and 5 Settings tabs) × 2 themes × 12 widths (1920, 1600, 1440, 1282, 1280, 1024, 768, 412, 390, 375, 360 and 320 px) before and after the fixes.
4. Inspected screenshots of every view, and measured columns, overflow and focus with DOM queries.
5. Ran task flows (see `USABILITY_TEST_REPORT.md`) with real key presses as admin and viewer, on `127.0.0.1` and on `localhost` (passkey origin).
6. Fixed each defect at its root, rebuilt, restarted, and checked it again in the browser.

## Design system findings

The established identity is a dark-first operations console: grey surfaces with a slight blue bias, one accent, fixed status colours with a glyph per status, and no external assets. The fixes keep to it: no new colours, fonts, gradients, glass, shadows or animation. Rules from `CLAUDE.md` that the app was breaking before this pass:

| Rule | Violation found | Status |
|---|---|---|
| Red only for blocks and critical/high | Every "open" alert status was red | Fixed (neutral; severity carries urgency) |
| Destructive actions default focus on Cancel | Block dialog focused a pre-filled field | Fixed |
| Live updates must not steal focus | Alerts, Overview and Controls re-renders | Fixed |
| Loading uses skeleton rows, not spinners | All loading states used a spinner | Fixed (long user-started simulation keeps a spinner) |
| Empty states explain how to get data | Several said only "No X." | Fixed |
| AI output shows confidence, model and review status | Alert summaries showed none | Fixed (model and review status; free text has no confidence, and the label says so) |
| Grid of N tiles divides N at every breakpoint | AI view: 13 tiles in an auto-fill grid | Fixed (12 tiles, 6/4/3/2) |
| Fixed columns sized for their widest value | Events Status/Method/Action/Client/Time, Live Time | Fixed |
| Compact density option for tables | Not present | **Not fixed** (size budget) |

## Route coverage

| Route | Admin | Viewer | Themes | Widths | Interactions exercised |
|---|---|---|---|---|---|
| Sign-in | yes | yes | both | all | empty and wrong token, reveal button, valid sign-in, sign-out message |
| Overview | yes | yes | both | all | range, refresh, IP filter links, Block dialog (cancel), focus over refresh |
| Live | yes | – | both | all | chips, pause, row opens drawer |
| Events | yes | – | both | all | keyboard row open, drawer focus trap, Escape and focus return |
| Alerts | yes | yes | both | all | Ack, AI summary, re-render focus, status and severity filters |
| Controls | yes | yes | both | all | Add block validation, block, remove, focus after each |
| Policy | yes | – | both | all | Validate, Simulate (dry run). Apply and rollback not run (state-changing, needs a second admin) |
| Labels & datasets | yes | – | both | all | Viewed. Export not run (file download) |
| AI | yes | – | both | all | tiles, refresh |
| Audit | yes | locked | both | all | viewed, filter field |
| Settings (5 tabs) | yes | locked | both | all | AI Test connection. Save not run (would change the test stack's settings) |
| Account / passkeys dialog | yes | – | dark | 1282 | both origins. Real passkey registration not run (`soft_passkey.js` covers it, see the passkey commit) |

## Component coverage

See `UI_COMPONENT_TEST_MATRIX.md`: 34 components, 33 pass, 1 partial (tables: no density option).

## Visual findings

Visual defects: Block buttons hidden at 1181–1560 px (UX-04), Events headers and badges clipped (UX-06), Live times clipped (UX-07), red overuse (UX-08), orphan AI tiles (UX-13), uneven KPI tiles at 320 px (UX-17). Screenshots before and after are in `reports/evidence/ui-audit/screenshots/`.

## Responsive findings

- After the fixes, there is no page-level sideways scroll at any of the 12 widths, on any route, in either theme.
- Wide data tables (Live, Events, Overview top clients on phones) scroll sideways inside their card, as `CLAUDE.md` allows.
- Touch targets measure at least 40 px below 760 px wide (audit check 8).
- Tested in Chromium viewport emulation only; no real device was used.

## Usability findings

See `USABILITY_TEST_REPORT.md`. Ten simulated task flows by an agent, not human participants.

## Accessibility findings (WCAG 2.2 AA, partial)

Fixed in this pass:

- 2.4.3 focus order: hidden menu links were tab stops.
- 2.4.3 and 3.2 focus loss: re-renders, closing the drawer, busy buttons.
- 3.3.1 error identification: the token field now gets `aria-invalid`.

Already in place and verified:

- Text contrast is at least 4.5:1 everywhere, measured on 336 audits after fixing the audit's colour parser.
- Visible focus rings.
- The drawer and dialogs trap focus, close on Escape and return focus.
- `prefers-reduced-motion` is respected.
- Status never relies on colour alone: each has a glyph and text.

Not done: a screen-reader pass (VoiceOver/NVDA), an axe-core run (no Node tooling in the repo; the CSP blocks CDN scripts), and 200 % zoom testing. Automated checks cannot establish WCAG conformance.

## Performance findings (lab, localhost, emulated)

- CLS was 0 over a full Overview load, measured with a buffered `layout-shift` observer.
- LCP and INP could not be measured: the browser pane ran as a background page, which does not record LCP.
- DOMContentLoaded at 20 ms on localhost.
- The three assets are about 200 KB uncompressed (`app.js` 162 KB), served with `cache-control: no-store` and no compression, so every load downloads them again (UX-O3).
- Right after load, `/api/alerts?status=open` was requested 4 times within a few seconds (UX-O4).

## Resolved issues

UX-01 to UX-21 and T-01 to T-04. See `BUG_FIX_CHANGELOG.md`.

## Unresolved issues

| ID | Severity | Issue | Why not fixed |
|---|---|---|---|
| UX-O1 | Medium | No compact table density option (a `CLAUDE.md` rule) | The size budget is spent (209,994 of about 210,000 bytes); needs a budget decision |
| UX-O2 | Medium | The three asset files are at the size ceiling | Any further UI work must trim or raise the budget |
| UX-O3 | Low | Assets uncompressed and `no-store` (about 200 KB per load) | Server change (compression and ETag); outside a UI pass, and may be a deliberate security choice |
| UX-O4 | Low | Duplicate `/api/alerts?status=open` requests on load | Harmless; needs request coalescing |
| UX-O5 | Low | Modal validation errors are not tied to the specific field | The `modal()` action returns a message without a field |
| UX-O6 | Low | Copy: "elev" abbreviation; "Admin token" label shown to every role | Column-width and e2e-text impact not checked |
| UX-O7 | Low | The phone menu overlay does not trap Tab | Escape and scrim close it; low impact |

## Known limitations of this audit

- The e2e suites ran after the setup stack was stopped: proxy 29/29, intel 27/27 (see `TEST_EXECUTION_REPORT.md`).
- Chromium emulation only: no Safari, Firefox, real phones, virtual keyboards or safe areas.
- No screen reader, no axe-core, no human participants, no field (real-user) metrics.
- No Playwright suite was added. The repository has no Node test tooling; the existing regression mechanism (`ui_audit.js`) was extended instead, plus `ui_sweep.js` and `inject_audit.py`.

## Scorecard

88 / 100 weighted. The rubric and per-category evidence are in `QUALITY_SCORECARD.md`. The biggest deductions are no screen-reader pass, simulated rather than human usability testing, and emulation-only responsive testing.

## Recommendations

1. Decide the asset budget: either raise it to fit a density toggle, or add gzip on the admin server, which would cut transfer about 4× and makes the byte budget less critical.
2. Add a screen-reader pass for the Events virtual table and the drawer.
3. Keep using `inject_audit.py` per width; it now catches hidden focusable controls and clipped headers.
