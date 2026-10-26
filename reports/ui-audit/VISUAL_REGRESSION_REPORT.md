# Visual regression report

Screenshots are in `reports/evidence/ui-audit/screenshots/`. They were captured with Claude's built-in browser (Chromium, viewport emulation) against the live test stack.

- Viewports larger than the browser pane are scaled down in the image (for example, 1440 px shows as 800 px wide).
- Traffic is synthetic and random, so numbers differ between shots. Compare layout, not values.

## Before / after

| Defect | Before | After | Expected difference |
|---|---|---|---|
| UX-04: Block buttons hidden at 1181–1560 px | `before-1440-overview-block-hidden.jpg` (Block cut to "B") | `after-1440-overview-block-visible.jpg` | Top clients takes the full row up to 1560 px; paths and rules sit side by side below it |
| UX-07: Live times clipped | `before-1282-live-time-clipped.jpg` ("18:19:45.6…") | `after-1282-live-full-times.jpg` | Time column 104 px, tabular digits |
| UX-06: Events headers and badges clipped | `before-1282-events-headers-clipped.jpg` ("STAT…", "METH…") | `after-1282-events-columns.jpg` | Action 104, Status 64, Method 72, Client ≥128, Time 104; Request absorbs the slack |
| UX-08: Red "open" on every alert | `before-1282-alerts-red-open.jpg` | `after-1282-alerts-neutral-open-summary-meta.jpg` | "open" is neutral grey; severity badges unchanged |
| UX-12: AI summary without model | `before-1282-ai-summary-no-model.jpg` | same "after" alerts image | Adds "Model mock-model · free text, no confidence score · unreviewed" |
| UX-13: AI tiles orphan row | `before-1282-ai-orphan-tiles.jpg` (5/5/3) | `after-1282-ai-12-tiles.jpg` (4/4/4) | Breaker tile removed (its state is in the callout) |
| UX-17: KPI tiles uneven at 320 px | (audit: heights 86/103) | `after-320-overview-kpis.jpg` | "last 1h" on its own line in every tile below 400 px |
| UX-01: Phone menu | `before-320-nav-mid-slide.jpg` | `after-390-menu-open-focus.jpg` | Same look; focus ring on the current section when opened |
| UX-03: Block dialog focus | `before-1282-block-dialog-focus-in-field.jpg` | DOM check: focus on Cancel | Focus ring moves from the IP field to Cancel |
| UX-10: Viewer on Settings | `before-viewer-settings-raw-error.jpg` | DOM check: "Settings are for admins only." | Tab bar and red error replaced by the standard locked state |
| UX-18: Passkey dialog off-origin | `before-passkey-dead-end-field.jpg` | DOM check: field disabled, focus on Close | Name field greyed out |

Reference shots after the fixes: `after-1282-controls-block-applied.jpg` (toast and focus on "Add block…"), `after-1282-block-dialog-validation.jpg`, `login-error.jpg` and `drawer-1282.jpg`.

## Unchanged by design

Colour tokens, typography, radii, spacing scale, shadows, icons, the chart, the drawer layout and the login page look. The only token-level change is that `.st-open` now uses the neutral colour.

## Unexpected differences

None found. After every round of fixes, `ui_audit.js` was re-run on all 14 routes × 2 themes. The final run covered 12 widths, 336 audits, and every total was 0 (`reports/evidence/ui-audit/ui-sweep-final.json`).

## Responsive notes

- No page-level sideways scroll at any tested width.
- Wide tables scroll inside their card on phones, as `CLAUDE.md` allows.
- Segmented controls stay on one row.
- 40 px touch targets below 760 px.

## Baselines

There is no pixel-diff baseline: random live traffic makes pixel comparison noisy, and the repository has no image-diff tooling. The structural audit (`ui_audit.js` through `ui_sweep.js`) is the regression baseline: total 0 on every route, theme and width.
