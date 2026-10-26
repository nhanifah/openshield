# Bug fix changelog

Severity: **High** = blocks or endangers a core task for some users. **Medium** = clear defect or guideline breach with a workaround. **Low** = polish.

"Verified" means reproduced before the fix and checked after it in Claude's built-in browser against a rebuilt, restarted instance.

## Dashboard

| ID | Severity | Route / component | Reproduction | Root cause | Fix | Verified |
|---|---|---|---|---|---|---|
| UX-01 | High | Phone menu (`#sidenav`, ≤860 px) | At 320 px, focus the first menu link while the menu is closed: it receives focus at x=-232 | Closed menu only translated off-screen; links stayed in the tab order | `visibility: hidden` after the slide-out; on open, focus the current link; on close, return focus to the menu button (Escape) or the view (navigation) | `offscreenFocusable` 10 → 0; key-press test |
| UX-02 | High | Alerts, Overview top lists, Controls | Focus "Resolve alert 7", wait for an alert update: focus goes to `<body>` | Whole table re-rendered (`replaceChildren`) on stream messages and 30 s polls; `act()` also disabled the focused button | `captureFocus`/`restoreFocus`/`keepFocus` keep focus on the same control of the same row (`data-key`, else position, else the card's control); `act()` uses `aria-disabled` + `aria-busy` with a re-entry guard; Alerts reloads keep the table until data arrives | Focus kept across a re-render; after Ack, moves to the next alert's Ack |
| UX-03 | High | Block dialog (Overview, drawer) and all danger dialogs | Overview → Block → press Enter: the client is blocked | `modal()` focused the first field, which was pre-filled | Danger dialogs focus the first empty text field, else Cancel | Pre-filled dialog opens on Cancel; Enter cancels; focus returns to the Block button |
| UX-04 | Medium | Overview top clients, 1181–1560 px | 1282 px: table 545 px wide in a 434 px card, Block buttons hidden | Three-column grid too narrow for the client table | Three columns only from 1561 px; below that, clients take the full row | No sideways scroll at 1282/1440/1600/1920 |
| UX-05 | Medium | Event drawer from Events | Enter on a row, Escape: focus on `<body>` | Virtual list replaced the opener row while the drawer was open | `closeDrawer` finds the row by `data-idx`, else focuses the view | Focus back on the same row |
| UX-06 | Medium | Events table, 1282 px | Headers "STAT…", "METH…"; challenge badge clipped 10 px; IPv4 clipped | Column widths below their widest values | Columns 104/104/64/72/≥152/≥128… (the minimum total is unchanged, 1040 px) | No clipped headers, badges or times |
| UX-07 | Low | Live table | Some times shown as "18:19:45.6…" | Proportional digits in a 96 px column | `.reltime` uses tabular numbers; Time column 104 px | No clipped cells except the free-text columns |
| UX-08 | Medium | Alerts status badge | Every open alert shows a red "open" | `.st-open` mapped to the block colour | `.st-open` is neutral; "Blocked now" in the drawer uses the block badge; an open AI breaker stays red | Screenshot |
| UX-09 | Medium | Sign out | Sign out: "Your session is no longer valid." | A pending request fired without a token, got 401 and called `logout()` with the expiry message | `api()` and the stream refuse to send without a token and end the session only on a 401 for the current token | "Signed out." (info style) |
| UX-10 | Medium | Settings as viewer | Open `#/settings` as viewer: tab bar plus "requires role admin" | No role check in the view | Locked state, as on Audit | Text check |
| UX-11 | Medium | Alert toast | During an attack burst, the toast stays over the bottom-right (including Block buttons) | 6 s timer reset on every alert; also shown on Alerts | Fixed 6 s, then 60 s quiet (the nav badge keeps counting); not shown on Alerts | Two new attack bursts 12 s apart: toast visible 6 s for the first, none for the second |
| UX-12 | Medium | Alert AI summary | Summary shows no model or review status | API returned only text; UI had no meta line | API adds `model`; UI shows model, "free text, no confidence score", "unreviewed" | Text check and screenshot |
| UX-13 | Low | AI view tiles | 13 tiles in 5 columns: orphan row of 3 | auto-fill grid; duplicate Breaker tile | 12 tiles, explicit 6/4/3/2 columns | Screenshot |
| UX-14 | Low | All loading states | Spinners | `stateBox('loading')` drew a spinner | Skeleton rows with screen-reader text; `'progress'` keeps the spinner for the long simulation | Audit and screenshots |
| UX-15 | Low | Empty states (Alerts, Controls, Labels, Audit) | "No active dynamic blocks." etc. | Copy | Explains how data appears; role-aware on Controls | Text check |
| UX-16 | Low | Drawer absolute times | "06:22:24 PM" next to tables' "18:22:24" | `toLocaleString` default hour cycle | `hourCycle: 'h23'` | Code |
| UX-17 | Low | KPI tiles, 320 px | Heights 86/103 | Label and window wrapped in some tiles only | Below 400 px the window note always takes its own line | Audit 0 at 320 |
| UX-18 | Low | Passkey dialog, non-passkey origin | Focus in an editable name field; Add disabled | Only the button was disabled | Field disabled too; focus on Close | DOM check on 127.0.0.1 and localhost |
| UX-19 | Low | Sign-in field | No `aria-invalid` on error | Missing | Set on error, cleared on success | DOM check |
| UX-20 | Low | Overview status line | "3 high alerts open" next to a nav badge of 16 | Lower severities omitted | "3 high alerts open, 12 lower" | Screenshot |
| UX-21 | Low | Tables for viewers | "—" in the empty action column | `tableRow` filled empty cells with "—" | Empty action cells stay empty | DOM check |

## Tooling

| ID | Component | Problem | Fix | Verified |
|---|---|---|---|---|
| T-01 | `ui_audit.js` contrast | Mid-animation colours reported as `oklab(...)` were misread (minus signs dropped): false 2.5:1 failures on Live | Colours resolved by painting on a canvas | False positive gone; real contrast unchanged |
| T-02 | `ui_audit.js` | Could not see hidden focusable controls or cut-off column headers | New checks `offscreenFocusable` and `clippedHeaders` | Re-creating UX-01 in the page gives 10 hits; the fix gives 0 |
| T-03 | `live_stack.py` | Could not run beside an existing stack; SIGTERM left the proxy holding ports | `--port-offset N`; shutdown waits 5 s, then kills | Several restarts on port 19290, ports freed within seconds |
| T-04 | New `ui_sweep.js`, `inject_audit.py` | Running the audit on 14 routes × 2 themes by hand per width | One script per width returns all failures | Used for all sweeps |

## Files changed

- `crates/openshield-intel/assets/app.js`, `app.css`: the UX fixes. Total asset size is 209,994 bytes, inside the about-210 KB budget after shortening section-divider comments and removing three unused CSS rules.
- `crates/openshield-intel/src/ai/supervisor.rs` (`model()`), `src/admin/mod.rs` (summary response carries `model`).
- `tests/dashboard/ui_audit.js`, `ui_sweep.js` (new), `inject_audit.py` (new), `live_stack.py`.
- `CLAUDE.md`: visual-check steps mention the new helpers and checks.
