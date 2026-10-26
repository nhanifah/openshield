# Usability test report

**These are simulated tests.** An AI agent (Claude) ran the tasks in a browser against a live test stack, as an expert heuristic evaluation. No human participants took part and no analytics were available. Treat this as an expert review, not user research.

## Roles assumed

| Persona | Role | Goal |
|---|---|---|
| On-call operator | admin (`alice`) | See what is wrong now, contain an attacking client, confirm it worked |
| Analyst | analyst | Triage alerts, read evidence, label events |
| Stakeholder | viewer (`val`) | Watch traffic and alerts without changing anything |
| Keyboard user | any | Do all of the above without a mouse |

## Tasks

Steps count user actions (key presses or clicks). "Before" friction was observed on the original build. Every flow passes on the final build.

| # | Task | Start | Expected | Actual (final) | Steps | Friction found (before) |
|---|---|---|---|---|---|---|
| 1 | Sign in | Sign-in page | Errors are clear; valid token opens Overview | Empty: "Enter your admin token." Wrong: "That token was not accepted." Valid: Overview | 3 | Field not marked invalid (UX-19); label says "Admin token" to viewers (UX-O6) |
| 2 | Is anything wrong right now? | Overview | Status line answers it | "Needs attention: 3 high alerts open, 12 lower" | 0 | "3 high alerts open" next to a nav badge of 16 read as a mismatch (UX-20) |
| 3 | Triage an alert | Alerts | Ack, summarize, keep my place | Focus stays on the same alert; after Ack it moves to the next alert's Ack | 2 per alert | Focus thrown to the page top on every incoming alert and after each action (UX-02); every row red (UX-08); summary without model or review status (UX-12) |
| 4 | Investigate an event | Events | Open details, read, return to the list | Enter opens the drawer; Escape returns to the same row | 2 | Focus lost to the page body on close (UX-05); headers and badges clipped (UX-06) |
| 5 | Contain an attacker from Overview | Overview top clients | Block dialog states the effect and needs a deliberate confirm | Dialog opens on Cancel; Tab to Block, Enter | 3 | One Enter blocked the client (UX-03); at 1282–1560 px the Block button was off-screen (UX-04) |
| 6 | Add and remove a manual block | Controls | Validation, then a toast with the exact outcome | "Enter a valid IPv4…", "Block of 203.0.113.250 applied.", "Removal … applied." | 6 | Focus fell to the page body after removal (UX-02) |
| 7 | Navigate on a phone | 390 px Overview | Open the menu, choose a section | Menu opens with focus on the current section; the choice moves focus to the view | 3 | 10 invisible tab stops when closed (UX-01) |
| 8 | Viewer explores | viewer, all views | Sees data, no dead controls | Audit and Settings hidden; direct Settings URL shows a locked state | – | Raw "requires role admin" error (UX-10); empty state told viewers to block clients (UX-15); "—" in empty action column (UX-21) |
| 9 | Add a passkey | account menu | Clear whether this works here | Off-origin: note, disabled field, focus on Close | 1 | Focused an editable field beside a disabled button (UX-18) |
| 10 | Sign out | top bar | "Signed out." | "Signed out." | 1 | Said "Your session is no longer valid" (UX-09) |

Also run: policy Validate and Simulate (dry run), AI settings Test connection, the theme toggle (persists in `localStorage`), and Live pause and filters.

## Heuristic violations (Nielsen), all fixed unless noted

| Heuristic | Finding |
|---|---|
| 1 Visibility of system status | Alert toast parked on screen through bursts (UX-11); sign-out message wrong (UX-09) |
| 3 User control and freedom | Focus loss after actions forced keyboard users to start over (UX-02, UX-05) |
| 4 Consistency and standards | 12 h vs 24 h times (UX-16); red used for a non-severity state (UX-08); spinners instead of skeletons (UX-14) |
| 5 Error prevention | Single-Enter block (UX-03) |
| 6 Recognition rather than recall | Empty states that did not say how data arrives (UX-15) |
| 8 Aesthetic and minimalist design | Duplicate Breaker tile and orphan row on AI (UX-13) |
| 9 Help users recover from errors | Raw API error for viewers on Settings (UX-10); modal errors not tied to the field (UX-O5, open) |

## Cognitive load and efficiency

- The Overview answers the main question in the first line, and its top lists link straight to filtered Events. The information order is right: summary, trend, lists, drawer.
- Triage throughput was mostly limited by focus loss. With focus kept, a keyboard user can Ack a run of alerts with Enter, Tab, Enter… without leaving the table.
- Remaining friction: the "elev" abbreviation, and no compact density for long event lists (UX-O1).

## Recommended next improvements

1. Compact density toggle for Events and Live (needs a size budget decision).
2. Tie modal validation errors to their field (`aria-invalid` and `aria-describedby`).
3. Rename "Admin token" to "Access token" once e2e tests are checked for that text.
4. A short usability session with two or three real on-call operators to confirm the triage flow.
