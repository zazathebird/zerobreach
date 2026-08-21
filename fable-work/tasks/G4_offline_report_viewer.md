# G4 — an offline report viewer page

**Priority 4. Size: M. New files only, front-end.**

## The problem

A finished run is a JSON file. To look at it today you either start the server on the machine
that produced it, or you read the flat HTML table. A technician who has copied `audit_*.json`
off a client machine onto their own laptop has no good way to work with it.

## Deliverables

```
gui/viewer.html                       standalone page, opened from the filesystem
gui/static/js/viewer.js
gui/static/css/viewer.css
tools/tests/Test-ViewerAssets.ps1     asset + policy assertions
```

**Do not edit `gui/templates/index.html`.** That file is the running application and the main
session has it open. This is a separate page that happens to share the visual language.

## Behaviour

- Opens from `file://` with no server. A file input and a drop target accept one or more
  `audit_*.json` / `KrakenBaseline_*.json` files. Everything is parsed in the page.
- Reuse the existing look: `gui/static/css/main.css` variables and the existing theme tokens.
  Link them rather than copying values, and degrade gracefully if a theme file is absent.
- Views: summary; findings table with severity/group/text filters; a group-collapsed mode; and
  a side-by-side comparison when two files are loaded.
- Export the current filtered view to CSV, with each cell passed through the same
  formula-injection guard the rest of the product uses (leading `=`, `+`, `-`, `@`, tab or
  carriage return neutralised).
- Deep-linkable filter state in the URL fragment, so a technician can send a colleague a link to
  exactly what they are looking at. The fragment is untrusted input on the way back in — parse
  it defensively.

## Hard constraints

- **No remote origins at all.** No CDN script, no web font, no analytics, no image from a
  domain. Vendor anything you need under `gui/static/`. This is a fixed product rule, not a
  preference: the tool runs on machines whose network configuration it is itself auditing, so it
  must never generate traffic that could be intercepted or that could tell someone it ran.
- **Everything rendered goes through an HTML-escaping helper**, including finding IDs and phase
  labels. Some IDs originate in a data file rather than being generated, so "the engine
  sanitises those" is not true for all of them.
- Must stay responsive at 1,200 findings. Virtualise the table or paginate; do not build 1,200
  rows up front.
- Keyboard navigable, visible focus, and `prefers-reduced-motion` honoured.

## Tests

`Test-ViewerAssets.ps1` runs on Linux and asserts against the shipped files:

1. No absolute `http:` or `https:` URL appears in any of the three new files.
2. No `<script src>` or `<link href>` points outside `gui/static/`.
3. Every place the JS writes to `innerHTML` is fed by the escaping helper — assert on the
   helper's name appearing in the same expression, and add a deliberately failing case to prove
   the assertion is real.
4. The escaping helper covers `& < > " '` — all five. Four is the usual mistake.
5. The CSV cell guard neutralises each of the six dangerous leading characters.

Prove each fails on revert.

## Ask before you build

- Should the viewer be added to the release zip (`tools/Build-Release.ps1` stages a file list),
  or stay a repo-only tool? That file belongs to the main session, so the answer decides whether
  you write a note or a patch.
