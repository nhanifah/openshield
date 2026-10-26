# OpenShield

Rust reverse proxy and WAF on Pingora and Wirefilter. Crates:

- `crates/openshield-core`: the WAF engine (config, rules, transactions, redaction).
- `crates/openshield-pingora`: the `openshield` proxy binary.
- `crates/openshield-openapi`: standalone OpenAPI request validator.
- `crates/openshield-intel`: optional intelligence layer (events, anomaly detection, AI supervision, policy management, admin API, dashboard in `assets/`).
- `crates/openshield-testkit`: `echo-upstream` and `mock-gemini` (a test double, not a model).

## Build and test

- A release build needs `cmake` (pingora's zlib-ng).
- `cargo test --workspace` for unit tests; `cargo build --release --workspace` before any script below.
- `python3 tests/e2e/run_e2e.py --tag <tag>`: proxy end-to-end suite (`--skip-slow` skips the two 10 s+ tests).
- `python3 tests/e2e/run_intel_e2e.py --tag <tag>`: intelligence layer, admin API and dashboard headers.
- `python3 tests/rulesets/check_recommended.py`: runs `examples/rulesets/recommended.yaml` in a real proxy, one attack and normal requests per rule. Run it after any change to that file. In rule regexes (`matches "..."`) backslashes are passed through as written: write `\.`, not `\\.`.
- `docker build -t openshield:local .` builds the Linux image; `deploy/kartukenangan/` is a live deployment (read its README before changing it).
- `python3 tests/bench/run_bench.py --tag <tag>` and `tests/bench/memory_growth.py`: performance. Do not run other heavy work at the same time; it skews the numbers.
- Evidence goes to `reports/evidence/`. Never report a number that was not measured.

## Dependency pins (do not loosen without re-running the e2e suites)

- `wirefilter-engine` is pinned to a git `rev`; a moving branch pulled breaking changes.
- `tokio` is `>=1.53.3, <1.54`: 1.54 panics on `BufStream::with_capacity(0, 0)`, which pingora 0.9 calls for every connection. Unit tests do not catch this; the e2e suite does.

## Security rules for code here

- Everything from a request (paths, headers, bodies) and everything an AI model returns is untrusted. Redact with `openshield_core::redact::Redactor` before it is logged, stored or sent anywhere.
- AI verdicts are advisory. Nothing in the request path may depend on them.
- Every admin API state change is role-checked and written to the admin audit log.
- Geo rules compile to `geo:<id>` WAF rules (`GeoRule::expression`); `GeoRule::matches` must decide exactly the same, a core test checks both. Unknown locations never match, and IP allows always win. Geo tests use `tests/fixtures/geo/` (documentation ranges only; regenerate with `make_geo_mmdb.py`), never real addresses.
- Error pages (`openshield_core::error_page`) HTML-escape every value and are served with a no-script CSP; keep both when changing templates.
- Passkey checks live in `webauthn.rs` (no WebAuthn crate: a strict, depth-limited CBOR decoder and aws-lc-rs signatures). Keep user verification required and challenges single use. Test passkey UI with `tests/dashboard/soft_passkey.js`, never a real operator's key.
- Secrets saved from the dashboard go through `vault::Vault` (AES-256-GCM, value name as associated data) and are never returned by the API; admin tokens are stored as SHA-256 digests only. A new kind of secret must follow the same path.

## Dashboard UI guidelines (`crates/openshield-intel/assets/`)

The dashboard is an operational security console: operators open it to decide what needs attention now, then drill into evidence. These rules keep changes consistent. They come from the sources listed at the end; where sources disagree, the rule notes the choice made.

### Constraints of the platform

- Exactly three files: `index.html`, `app.css`, `app.js`, embedded with `include_str!`. No build step, no frameworks, no CDN, no web fonts.
- CSP is `default-src 'self'; script-src 'self'; style-src 'self'`: no inline `<script>`, no `on…=` attributes, no `style="…"` in markup or via `setAttribute('style')` (setting `el.style.prop` from JS is allowed).
- Render every API string with `textContent` or text nodes. The `h()` helper refuses `innerHTML`; keep it that way.
- Keep the three files under about 235 KB in total (230 KB with Settings, passkeys and geo).

### Information hierarchy

1. The top of every view answers "is anything wrong right now?": a status line (open critical/high alerts, AI and pipeline health, monitoring-only mode) before any chart. (Carbon, Vectra, aufaitux)
2. Order content general to specific: summary, then trend, then lists, then detail in a drawer. Detail is a drill-down, never crammed into the overview. (Grafana, Skins Factory)
3. At most 5 to 7 visual modules in the first screen of a view. Put the most important at the top left and give it the most area and contrast. (Carbon, NN/g, SlideShare deck)
4. One time range applies to the whole view and is always visible; every card states its window ("Last 1 h"). Use the same range across cards. (Humio/LogScale, design-defaults)
5. Every number answers a question or leads to an action. Clicking an IP, path or rule filters the Events view; alerts link to their events.

### Color and status

- Color is reserved for meaning. Neutral UI chrome is grey with a slight blue bias; the accent is used only for focus, selection and primary actions.
- Status colors are fixed and never reused for decoration: pass/ok = green, challenge = amber, block/critical = red, suspicious = violet, allow = blue. Red only for blocks and critical or high severity. If everything is red, nothing is. (Skins Factory)
- Never rely on color alone: every status also has a text label and an icon or shape. (NN/g, Carbon, WCAG 1.4.1)
- Don't encode magnitude with color hue; use length or position. (NN/g)
- Contrast: body text at least 4.5:1, large text and UI components at least 3:1, measured on the lightest surface the text sits on, not the page background. Secondary text uses a solid token, never opacity. (WCAG AA, Carbon, dark-mode sources)

### Dark and light themes

- Dark is the default for an operations console; light must be equally finished. Respect `prefers-color-scheme` on first visit; the user's toggle wins after that.
- Dark base is a dark grey (around `#0f1318`), never pure black; text is off-white, not `#fff`.
- In dark mode, elevation is shown by lighter surfaces (page < panel < raised < overlay), not by shadows. Modals and drawers use the lightest surface so they don't merge with the page.
- Desaturate status colors slightly in dark mode so they meet contrast without glowing.

### Charts

- Bars for comparing categories (sorted), lines or areas for trends over time. No pies, donuts, gauges, radial or 3D charts. (NN/g)
- Show traffic as lines per decision on a shared axis, or a stacked area only when the total matters; the traffic chart keeps blocked traffic readable even when it is small (toggle series, or plot it on its own row).
- Charts have a faint grid, labeled axes with units, a tooltip that stays inside the card, and a legend that doubles as series toggles.
- Live updates must not move the layout or steal focus.

### Tables and lists

- Sticky header, tabular numbers, right-aligned numeric columns, left-aligned text.
- Row height: comfortable by default with a compact density option for analysts scanning long lists. (SaaSUI)
- Row actions sit at the far right, at most three, always visible on touch devices.
- Empty states explain what will appear and how to get it (e.g. "No alerts in the last hour. Alerts appear when anomaly detection or AI analysis flags traffic."). Loading uses skeleton rows, not spinners. (SaaSUI)
- Long attacker-controlled strings truncate with an ellipsis in tables and are shown in full (monospace, wrapped) in the detail drawer.

### Interaction and accessibility

- Every control is reachable by keyboard with a visible focus ring; dialogs trap focus and return it on close; Escape closes drawers and dialogs.
- Destructive or high-impact actions (block, apply policy, rollback) use a confirmation that states the effect, and default focus on Cancel.
- Show results of actions inline (toast or status line) with the exact outcome, including "pending approval".
- Touch targets at least 40 px tall on narrow screens; no horizontal page scroll at 390 px wide.
- Respect `prefers-reduced-motion`.

### Layout consistency

- Cards side by side in one grid row share a height (`align-items: stretch`); a grid of N tiles uses a column count that divides N at every breakpoint (KPIs: 6 / 3 / 2), so no row ends with an orphan.
- One component, one look: toggle chips are `.chip-toggle` everywhere, stat tiles match `.kpi`, a pill never sits inside another pill, and nothing uses strike-through to mean "off" (use `aria-pressed` with a dimmed marker).
- Fixed-width table columns are sized for the widest value they can hold (for example "suspicious 100%"), not for today's data. The free-text column (request path, comment) absorbs the slack and truncates.
- A wide data table may scroll sideways inside its card on narrow screens; the page itself never does. Segmented controls stay on one row and scroll, keeping the selected option in view.

### Visual check before shipping (mandatory)

Every UI change is checked in the built-in browser against a running instance (`python3 tests/dashboard/live_stack.py`; add `--port-offset 100` to run beside a stack that is already up), not judged from the diff:

1. Rebuild (`cargo build --release --workspace`; the assets are embedded), restart the instance, sign in.
2. Inject `tests/dashboard/ui_audit.js` and run it on every view and every Settings tab, in dark and light, at 1600, 1282, 1024 and 375 px wide. `python3 tests/dashboard/inject_audit.py` prints one script that does this per width (it runs `ui_sweep.js`). It reports strike-through, nested pills, uneven control rows, overflow, badges or buttons clipped by a cell, cut-off column headers, uneven card rows, mixed container styles, WCAG contrast, small touch targets, focusable controls hidden beside the viewport, and cards that stop short of the view's full width. The result must be `total: 0` everywhere; `scrollsX` entries are informational.
3. Look at screenshots of each view as well. The audit cannot see everything (a misleading label, a cramped layout), and an anomaly seen by eye is fixed even when the audit passes. When the audit missed it, add a check for it.

### Copy

- Sentence case. Name things the way operators do: "Blocked", "Challenged", "Client", not internal field names.
- AI output is always labeled "AI (advisory)" and shows its confidence, model and review status next to it; never present it as a decision. (Skins Factory: show confidence with its inputs)

### Sources

- Nielsen Norman Group, "Dashboards: Making Charts and Graphs Easier to Understand": https://www.nngroup.com/articles/dashboards-preattentive/
- Grafana, "Dashboard best practices": https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/
- Carbon Design System, Dashboards: https://v10.carbondesignsystem.com/data-visualization/dashboards and color accessibility: https://v10.carbondesignsystem.com/guidelines/accessibility/color
- The Skins Factory, visual hierarchy in security operations software: https://www.theskinsfactory.com/uiux-design-questions-answers/why-does-visual-hierarchy-matter-in-security-operations-software
- Vectra AI, "Designing better security dashboards": https://www.vectra.ai/blog/how-to-design-better-security-dashboards
- Humio/LogScale dashboard design best practices: https://library.humio.com/kb/kb-dashboard-design-best-practices.html
- SaaSUI, data table UX patterns: https://saasui.design/blog/saas-data-table-ux-patterns
- Uxcel, elevation in dark UI: https://uxcel.com/blog/mastering-elevation-for-dark-ui-a-comprehensive-guide-342
