# PACKAGING_STUDY — shipping Scythe as a single application

**G8 deliverable. Study first, prototype second. Supersedes the F8 draft.**

Written 2026-08-20, against the constraints documented in `BLUEPRINT.md` and the G8 brief.
Prices and vendor terms are stated as ranges current to early 2026 — re-verify before any
purchase; the analysis does not change if a number moves 30%.

---

## The recommendation, up front

**Keep the zip-plus-launcher. Spend the packaging budget on code signing instead, and harden
the zip into a single verified build artifact (the prototype). Revisit a real host
application only after a signing identity exists and has accumulated reputation.**

Three findings force this:

1. **Every "single executable" route makes the reputation problem worse, not better.** The
   product's runtime behaviour — enumerate processes, read autoruns, walk the registry,
   modify configuration under an elevated token — is the behavioural fingerprint every
   endpoint product is built to isolate. Today that behaviour arrives in signed host
   binaries (`powershell.exe`) running visible script text. Repackaged into a brand-new
   unsigned PE, the same behaviour arrives with zero reputation and no inspectable content:
   strictly worse on every axis an EDR scores.
2. **The data-file boundary disqualifies the convenient tools.** The engine keeps its rule
   content in `data/*.json` precisely because rule text embedded in script bodies has
   previously had the whole engine blocked at load, before one line of output — and the
   failure is silent (the tool "runs" and finds nothing). Script-to-exe converters embed
   everything by design. Disqualified, not worked around (details in §3).
3. **The zip is not the problem the goal thinks it is.** The stated goal is "one thing the
   technician runs". The technician experience of the current package is: copy one file,
   right-click → Extract All, double-click `Launch-GUI.bat`. The prototype reduces that to
   one deterministic, verified artifact with a manifest; signing reduces the scary prompts.
   Neither requires changing what executes.

A recommendation to change nothing structural **is** the analysis outcome here, per the
brief's explicit allowance. What does change: the build becomes a verified single artifact,
and the signing work starts now because it has the longest lead time and gates every future
option.

---

## 1. Reputation — the dominant risk, costed

### What the tool looks like to endpoint protection

A Scythe run, viewed from an EDR's telemetry: an elevated process enumerates running
processes and loaded modules, reads autorun and service configuration across the registry,
walks scheduled tasks and WMI subscriptions, reads event logs, hashes files in user-writable
paths, and (in remediation) kills processes and deletes files. That is the canonical
"security tool or malware — flip a coin" profile. The only things that push the coin toward
"tool" are: a known signer, accumulated reputation for that signer and that binary, human-
readable script content, and prior allowlisting at the site.

### The signing ladder, costed

| Option | Cost (order of magnitude) | Validation lead time | What it buys |
|---|---|---|---|
| Nothing (today) | $0 | — | SmartScreen "unknown publisher" on the zip's mark-of-the-web; per-site allowlisting by hash is the de-facto process |
| OV code-signing certificate | ~$100–400/yr + HSM/token requirement (CA/Browser Forum rules since mid-2023: keys must live on hardware) | days to ~2 weeks of org validation | A stable publisher identity. SmartScreen reputation still accrues **per file and per publisher over time** — a fresh OV-signed binary still warns until installs accumulate |
| EV code-signing certificate | ~$250–700/yr, hardware token or cloud HSM | 1–4 weeks (stricter org vetting) | Historically near-immediate SmartScreen pass; since ~2023 that fast-pass is weaker but still materially better than OV on day one |
| Azure Trusted Signing (cloud signing service) | ~$10/month tier + Azure account; org validation inside the service | days, once the org has an Azure tenant and a 3+ year verifiable business history | Short-lived certs, HSM handled for you, good SmartScreen standing; the cheapest credible route for an MSP with an existing Microsoft relationship |

What reputation accrual actually requires, regardless of certificate: a **stable signer
identity** used consistently, **binary stability** (every new file hash restarts per-file
reputation; publisher reputation persists — this is a load-bearing argument for §5's
"data outside the binary"), install volume over weeks-to-months, and no incidents. There is
no purchasable shortcut to the volume-and-time part.

### The interim experience (and why it argues for the zip)

Until reputation exists, a new **unsigned exe** at a client site should be *expected* to be
quarantined on arrival or blocked at first run by SmartScreen, Defender heuristics, or the
site's EDR — with the MSP's technician standing at the desk looking unprofessional. The
current zip has a *known* interim experience: mark-of-the-web prompt, existing per-client
allowlist entries, script content every EDR can inspect and that support staff can read over
the phone. Switching containers resets that accumulated operational knowledge to zero.

**Immediately actionable regardless of packaging:** Authenticode-sign the `.ps1` files and
the launcher inside the existing zip as soon as any certificate exists. Signed scripts
improve the AMSI/EDR posture and per-site `AllSigned` policies become available, with zero
repackaging risk. This is the first concrete step of the recommendation.

---

## 2. Path resolution under a packed layout

The tree resolves data files, modules and output relative to the script root, funnelled
through a single project-root global (the choke point the brief names). Packed layouts break
the assumptions behind it in three distinct ways:

- **There is no script root.** Script-to-exe hosts run the script from memory or from a
  temporary extraction directory; `$PSScriptRoot` is empty or points somewhere that will not
  exist after the process exits. Every path expression that bypasses the root global is a
  latent bug that only fires in the packed build — which is why the contract test (`tools/
  tests/Test-PackagingContract.ps1`, property 1) asserts the launcher-role scripts contain
  **no** `$PSScriptRoot`/script-root expression outside the one bootstrap assignment that
  seeds the root global.
- **The output directory must survive the process.** `reports/` resolved against an
  extraction folder lands the client-facing report in `%TEMP%\<random>\reports`, deleted on
  exit. Whatever the package, the rule is: output resolves through the root global to a
  location the technician can find — next to the entry point, or an explicit
  `%USERPROFILE%\Documents\Scythe` — never relative to "wherever the code happens to be".
- **Working directory is not script root.** Double-click, "Run as administrator", scheduled
  task and `runas` all start with different working directories (elevation famously lands in
  `C:\Windows\System32`). Only the root global, seeded once from the real entry-point
  location, behaves identically in all of them.

The audit the brief asks for is mechanised rather than performed once: the prototype build
**fails** (exit 3, naming file and line) on any path expression in a launcher-role script
that does not resolve through the root global. The audit therefore re-runs on every build,
including after the merge, against the real launcher.

> The root global's *name* is not documented in `BLUEPRINT.md`, and the real launcher is
> off-limits to this work package. The prototype and test take the name as a parameter
> (`-ProjectRootVariable`, fixture default `ScytheRoot`). **Owner: supply the real name; one
> command-line argument, no code change.**

## 3. The data-file boundary — the disqualifier

The platform's script-scanning interface (AMSI) inspects script content at load time.
Scythe's rule data — malware family names, suspicious registry paths, LOLBin lists,
attack-technique keywords — is, byte for byte, the most heuristic-triggering text the
product contains. Inline in a script body it has already, historically, caused the engine to
be blocked before producing output, and the failure mode is the worst one in the product:
**silent**. The tool appears to run and finds nothing; a technician hands a client a clean
report that means "the scanner was dead", and nobody knows.

So the boundary is a hard requirement, and the test is binary: **does the candidate keep
`data/*.json` as separate, non-script files on disk at runtime?**

| Candidate | Data files at runtime | Verdict |
|---|---|---|
| Zip + launcher (today) | Real files in `data\` | Survives |
| Script-to-exe (PS2EXE-style), fully embedded | Inside the script body / PE resources, materialised through script memory | **Disqualified** |
| Script-to-exe, data left outside | Real files — but the package is no longer single-file, keeping only the exe's downsides | Survives §3, fails its own premise |
| Self-extracting archive | Real files, but in a temp extraction dir | Survives §3 letter, fails §2 (disappearing output/paths) |
| Host application + installer (MSI) | Real files installed under `Program Files`/`ProgramData` | Survives |

Per the brief: the embedded routes are **disqualified, not worked around**. Any workaround
(obfuscating the data, decoding at runtime) is indistinguishable from what malware does to
hide its configuration and makes the reputation problem catastrophically worse.

The prototype enforces the boundary at build time: every staged data file must exist as a
separate file, and no staged script may contain a data file's content (checked by content
sampling, property 2 of the contract test) — so the boundary cannot regress quietly.

## 4. Elevation and the console

Two agreements currently hold the live view together:

- **Process creation and redirect.** The launcher self-elevates (UAC); the server spawns the
  engine and reads its stdout line by line, pushing each line to the browser over SSE. Exe
  hosts commonly offer a "no console window" build flavour that changes the subsystem from
  console to GUI — which changes how (and whether) child stdout handles attach. A broken
  redirect makes a healthy run look dead: the scan proceeds, the UI never moves again.
- **Encoding.** Both ends pin the text encoding of that pipe. A packed host that detaches
  the console can silently change the default stream encoding to the OEM code page, at which
  point every box-drawing character in the UI renders as mojibake (the exact failure
  BLUEPRINT §8 warns about) and, worse, the `TIMING:`/severity-tag parsing can mis-read.

Both are process-boundary contracts, so both are asserted structurally by the contract test
(property 4): **the encoding declaration must be present on both sides** — the server
(reader) and the engine (writer) — and must agree. On elevation: whatever the package, the
entry point carries the elevation request (today the launcher's `runas`; in an exe it would
be a `requireAdministrator` manifest), and the server/engine never re-elevate mid-pipeline —
re-elevation spawns a *new* console and orphans the redirect.

What cannot be proven from Linux is the runtime half: that a UAC-elevated, double-clicked
run on a real Windows box still streams correctly. That is on the Windows checklist at the
end, spelled out step by step.

## 5. Update path

Decision, as the brief anticipates: **rule data stays outside whatever the binary/entry
artifact is.**

- A content update (new signatures, new technique mappings, tuned budgets) is a drop of
  `data\*.json` — no re-sign, no reputation reset, no new binary hash at any client site.
- A code update replaces the signed artifact — rarer, deliberate, and each one restarts
  per-file reputation (§1), which is exactly why the two cadences must not be coupled.
- This is also the §3 requirement wearing its operational hat: the same separation that
  keeps AMSI calm is the one that makes updates cheap. Any design that fuses data into the
  binary buys both problems at once.

The prototype's manifest records every staged file with its SHA-256, so a data-only update is
diffable and verifiable at the client site ("which rule files changed since the last visit"
is one manifest diff).

## 6. Candidates, side by side

| | Reputation impact | §3 data boundary | Build complexity | Update story | Technician's first run |
|---|---|---|---|---|---|
| **Zip + launcher (recommended)** | Known quantity today; improves with script signing | Survives | Lowest (prototype: one deterministic builder + contract checks) | Replace zip; or drop-in `data\` update | Extract All → double-click launcher → UAC prompt (known scripts) |
| **Script-to-exe conversion** | Worst: new unsigned PE with security-tool behaviour; converter stubs are themselves widely flagged | **Disqualified** when embedded; if data kept outside, no longer single-file | Low tooling, high debugging (console, encoding, `$PSScriptRoot`, AMSI all shift) | Whole binary per change; reputation resets every release | UAC prompt from an unknown exe; realistic chance of quarantine before first pixel |
| **Self-extracting archive** | SFX stubs carry poor reputation; contents extract to temp | Survives in letter, fails §2 (temp paths, vanishing output) | Low | Whole archive | Double-click → extraction → often blocked; output written into temp if paths unaudited |
| **Host application (+ MSI)** | Best *eventually* — but only signed and only after accrual; unsigned it is the exe row | Survives (installed data files) | Highest: a real .NET host embedding the PowerShell runtime, installer, servicing | Clean: MSI for code, data channel for content | Proper installed app; the experience the product goal actually describes |

**Sequencing that follows:** zip now → signing identity now (§1, longest lead time) → sign
scripts in the zip (first visible improvement, near-zero risk) → accumulate publisher
reputation → *then* the host-application row stops being the exe row and becomes viable.
The host app is the right end state and the wrong next step.

---

## The prototype: `tools/prototype/Build-SingleFile.ps1`

For the recommended option, "single file" means **one verified build artifact**: the
prototype assembles a standalone zip from a tree, and refuses to build a package that
violates the constraints this study identified. It:

1. Stages exactly the runtime file set (launcher, server, engine entry, `engine\*.ps1`,
   `data\*.json`, `gui\**`) into a clean directory — nothing else rides along.
2. Runs the four contract checks (below) against the staged files and **fails the build**
   (exit 3, each violation named with file and line) on any hit.
3. Writes `manifest.json` — every staged file with size and SHA-256 — into the package.
4. Produces one zip. Same tree in, same file list and hashes out.

It never modifies the input tree, and it is a parallel experiment: `tools/Build-Release.ps1`
is untouched and remains the shipping path until the owner promotes any of this.

Contract checks (enforced in the builder, asserted by `tools/tests/Test-PackagingContract.ps1`,
each proven to fail on revert):

1. **Root-global discipline** — launcher-role scripts contain no script-root expression
   outside the single bootstrap assignment into the project-root global.
2. **Data boundary** — every `data\*.json` is staged as a separate file, and no staged
   script embeds any data file's content.
3. **Completeness** — every file the launcher and server reference (extracted from their
   own source, not restated in the test) is present in the staged set; finding *zero*
   references is itself a failure (a vacuous pass would hide a broken extractor).
4. **Encoding agreement** — the UTF-8 declaration is present on both sides of the process
   boundary (server reader, engine writer).

Because the real launcher/server are off-limits here, the builder and test run against
fixture scripts reproducing the documented shapes, with the fixture-convention names
supplied as parameters — the same pattern as G5/G6. The checks themselves are the real,
shipping logic.

## What to verify on Windows (main session, after merge)

The owner's checklist — each step says what "pass" looks like:

1. **Build against the real tree:**
   `tools\prototype\Build-SingleFile.ps1 -Root . -ProjectRootVariable <real global name> -OutPath dist\Scythe-Standalone.zip`
   Pass: exit 0, every contract check green. An exit 3 naming real launcher lines is the
   §2 audit doing its job — fix the named lines or report them, do not suppress.
2. **Contract test against the real tree:**
   `powershell -File tools\tests\Test-PackagingContract.ps1 -Root <tree> -ProjectRootVariable <name>`
   Pass: exit 0.
3. **Extraction + first run as a technician would:** copy the zip to a clean VM (so
   mark-of-the-web is present), Extract All to `C:\Scythe`, double-click the launcher.
   Pass: UAC prompt appears, GUI opens, a QUICK scan streams live lines with box-drawing
   characters and glyphs rendered correctly (mojibake here = §4 encoding regression).
4. **Output location:** after the scan, `reports\audit_<stamp>.json` and friends exist under
   `C:\Scythe\reports` — not under `%TEMP%`, not under `System32`.
5. **Elevated-start working directory:** launch once via right-click → Run as administrator
   (working directory becomes `System32`). Pass: output still lands in step 4's location.
6. **Manifest audit:** `manifest.json` in the zip lists every file that the extracted tree
   contains, hashes matching (`Get-FileHash`), nothing extra.
7. **When a certificate exists:** sign the `.ps1` files and rebuild; confirm the zip's
   scripts carry valid signatures (`Get-AuthenticodeSignature`) and the launcher still runs
   under an `AllSigned` execution policy.
