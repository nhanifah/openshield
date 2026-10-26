# Component test matrix

Each component was checked in Claude's built-in browser against the live stack (Chromium emulation).

- **Widths "all"** means 1920, 1600, 1440, 1282, 1280, 1024, 768, 412, 390, 375, 360 and 320 px, in dark and light, through `ui_audit.js`, plus screenshots at the widths named.
- **Keyboard** means real key presses (Enter, Tab, Shift+Tab, Escape) sent by the browser tool.
- **Status**: Pass = verified working after fixes. Partial = works, with a documented gap.

| # | Component | Location | States tested | Widths | Interaction result | Accessibility result | Visual | Defects | Status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Sign-in form | `#login` | empty, wrong token, valid, signed out, session expired | all | Errors inline, focus kept, value selected | `role=alert` message, `aria-invalid` set and cleared | ok | UX-09, UX-19 | Pass |
| 2 | Token reveal button | `#login-reveal` | default, pressed | 1282 | toggles | `aria-pressed` | ok | – | Pass |
| 3 | Passkey sign-in button | `#login-passkey-block` | 127.0.0.1 (hint), localhost | 1282 | hint explains host name | – | ok | – | Pass |
| 4 | Top bar (brand, conn, rps, user, theme, sign out) | `.topbar` | live, reconnecting (on restarts) | all | theme toggle persists, aria-label flips | labelled icon buttons | ok | – | Pass |
| 5 | Side navigation (desktop) | `#sidenav` | current page, alert count | ≥861 | links route, `aria-current` | count has aria-label | ok | – | Pass |
| 6 | Side navigation (phone overlay) | `#sidenav.open` | closed, open, Escape, link chosen | 320–768 | focus in on open, out on close | hidden when closed (no tab stops) | ok | UX-01 | Pass |
| 7 | Status strip | Overview | needs attention, counts | all | links to Alerts | text and glyph | ok | UX-20 | Pass |
| 8 | KPI tiles | `.kpis` | 6 tiles, 6/3/2 columns | all | – | – | equal heights at 320 | UX-17 | Pass |
| 9 | Segmented control (time range, filters) | `.seg` | selected, scrolls on phone | all | changes range | `aria-pressed` | one row | – | Pass |
| 10 | Traffic chart and legend toggles | `.chart-wrap`, `.legend` | series on/off | all | toggles series | role=img + arrow keys, `aria-pressed` | ok | – | Pass |
| 11 | Top lists (clients, paths, rules) | `.tops-grid` | 3-up ≥1561, 2-up, 1-up | all | IP links filter Events; Block opens dialog | focus kept over 30 s refresh | Block always visible | UX-02, UX-04, UX-21 | Pass |
| 12 | Bar lists (status, methods, countries) | Overview | data, empty (GeoIP off) | all | – | – | ok | – | Pass |
| 13 | AI analysis card | Overview | ok | all | Details link | "advisory" hint | ok | – | Pass |
| 14 | Live stream table | Live | streaming, paused, filtered | all | row opens drawer | rows focusable | fixed columns fit | UX-07 | Pass |
| 15 | Filter chips | Live | on/off, suspicious only | all | filter stream | `aria-pressed`, no strike-through | ok | – | Pass |
| 16 | Events filter form | Events | apply, reset | all | – | labels on all fields | ok | – | Pass |
| 17 | Events virtual table | Events | scroll, keyboard rows | all | Enter opens drawer, arrows move | role=table/row/cell, focus restored | headers and badges fit | UX-05, UX-06 | Pass |
| 18 | Event drawer | `#drawer` | loading, loaded, AI verdict, labels | 1282, 390 | Escape closes, Tab trapped | focus returns to the opener row | ok | UX-05, UX-16 | Pass |
| 19 | Alerts table | Alerts | open, ack, summary, filters | all | Ack / Resolve / AI summary | focus kept through re-renders and actions | neutral "open" | UX-02, UX-08 | Pass |
| 20 | AI summary callout | Alerts | after summarize | 1282 | – | "AI summary (advisory)", model, unreviewed | ok | UX-12 | Pass |
| 21 | Alert toast | `#toasts` | burst of alerts | 1282 | 6 s, then quiet 60 s; not on Alerts | `role=status` | no longer parks over content | UX-11 | Pass |
| 22 | Action toasts | `#toasts` | ok, warn, error | 1282 | exact outcome text ("Block of … applied.") | `role=status` / `alert` | ok | – | Pass |
| 23 | Controls lists | Controls | empty, one block, countdown | all | add, remove | focus to card button after removal | ok | UX-02, UX-15 | Pass |
| 24 | Block / allow dialog | `#modal` | pre-filled, empty, invalid IP, missing reason | 1282 | validation messages, applied toast | starts on Cancel or first empty field | ok | UX-03, UX-O5 | Pass |
| 25 | Confirm dialogs (remove, revoke, apply, rollback) | `#modal` | danger | 1282 | Remove tested | starts on Cancel | ok | UX-03 | Pass |
| 26 | Policy editor and actions | Policy | validate, simulate | all | results inline | – | ok | – | Pass |
| 27 | Simulation result | Policy | dry run | 1282 | stats and table | progress spinner while running | ok | UX-14 | Pass |
| 28 | Labels review queue and datasets | Labels | empty | all | – | – | ok | UX-15 | Pass (export not run) |
| 29 | AI stats tiles | AI | 12 tiles | all | refresh | – | 6/4/3/2, no orphans | UX-13 | Pass |
| 30 | Audit log | Audit | empty, filter | all | – | locked state for non-admins | ok | UX-15 | Pass |
| 31 | Settings tabs and forms | Settings | 5 tabs, Test connection | all | inline result, busy state | locked state for non-admins | ok | UX-10 | Pass (save not run) |
| 32 | Account / passkeys dialog | `#user-chip` | 127.0.0.1, localhost | 1282 | add disabled off-origin | focus on Close when nothing to type | ok | UX-18 | Pass |
| 33 | Loading states | all views | skeleton rows | all | – | `role=status`, `aria-busy`, sr text | ok | UX-14 | Pass |
| 34 | Tables (shared) | all | comfortable | all | – | sticky headers, tabular numbers | ok | UX-O1 | Partial (no density option) |
