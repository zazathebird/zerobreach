# RESUME HANDOFF — updated 2026-07-26 (sessions 13-15: WS7-9, native Tauri shell, sandbox malware testing)

> ## ▶ START HERE after /clear — SESSIONS 13-15 (2026-07-25/26)
> **Everything below this block is older than the current state. In particular, every earlier block
> that says "the only USER-driven items are the browser click-through and the USB field test" is
> STALE** — three more sessions have shipped since, and the acceptance list is longer now.
>
> **Branch: `session12/review-remediation-ws6`. NOT merged to `main`.** The working tree also
> carries **uncommitted** changes to `ZeroBreach-V23.ps1`, `engine/Phases-1/2/3.ps1`,
> `data/mitre_mapping.json` and `native-app/src-tauri/{Cargo.toml,src/main.rs}` — run
> `git status` / `git diff` first and decide what to do with them before starting anything new.
>
> **Session 13 (2026-07-25) — architecture pivot + WS4/WS5.** Decided: the PS engine and server
> stay as they are; a **native Tauri shell** wraps them, and a brand-new Three.js 3D GUI eventually
> replaces `gui/static/js`. (A full C rewrite, a re-monolith and kernel-mode driver work were all
> explicitly **rejected**.) Shipped `c578c25`: WS4 Authenticode/signature caching + real registry
> key times, WS5 executive summary / trend / baseline-compare.
>
> **Session 14 (2026-07-26) — WS7/WS8/WS9 + the native `.exe`.** 18 further MITRE techniques as
> fractional phases (0 new auto-destructive findings from any of them); tri-state
> gone/present/unknown remediation verification in **both** paths; a tamper-evident hash-chained
> `reports/remediation_audit_*.jsonl`; **6 RunCmd command-injection fixes** (unescaped single quote,
> two on auto-selected CRITICAL paths); rule-#1 auto-kill FP fixes and self-allowlist anchoring;
> and **`native-app/` — a real Tauri v2 `.exe`**, screenshot-verified rendering the actual GUI, with
> its child server tied to a Windows **Job Object** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, verified
> against a real force-kill). Five independent audit rounds drove most of those fixes.
> **User's stated priority: the native standalone, not further PS-portable GUI work.**
>
> **Session 15 (2026-07-26) — Windows Sandbox infection testing.** Stage A (FULL, tripwires +
> EICAR): 80/80 phases contiguous, 0 recovered errors, all 5 documented tripwires detected at their
> documented severities. Stage B (DEEP × 2, **5 real theZoo malware families** incl. KRBanker):
> 115/115 phases contiguous, 0 recovered errors, auto-destructive set == the known tripwires plus
> the 2 legacy hardening posture items. **EICAR is not detected — that is expected**, ZeroBreach
> matches families/behaviour, not AV test strings.
> **A real bug was found and fixed:** the native shell hung *completely silently* on a box with no
> WebView2 Runtime (no window, no dialog, no debug log, no exit). `main.rs` now logs as its very
> first statement and runs a `fatal_if_webview2_missing()` preflight (message box + exit code 3)
> before any webview is built. **Built and staged, but NOT committed.**
>
> **Open / unverified — do not claim any of these are done:**
> - **Stage C** (detonate KRBanker offline → DEEP rescan → two properly sequenced `/api/remediate`
>   calls) and **Stage D** (confirm the WebView2 fix on a WebView2-less box): both harnesses are
>   written, neither has completed a run.
> - The **browser click-through** (runbook further down) — now also inside the native shell.
> - The **USB foreign-box field test**.
> - The **NSIS installer** (`ZeroBreach_0.1.0_x64-setup.exe` is built; it has never been installed).
> - `data/coverage_matrix.json` (regenerated 2026-07-25 at 130 phases — behind the engine).
> - `tools/Build-Release.ps1` has **no `native-app` awareness**.
> - The Three.js 3D GUI has not been started.
>
> **Hard-won process lessons from these sessions are now CLAUDE.md rules** — read
> "Test harnesses, sandboxes and headless validation" before writing any harness: a BOM-less `.ps1`
> with an em dash fails to *parse* on PS 5.1 (zero statements run, looks exactly like a hang);
> Windows Sandbox does not reap its VM, so the next launch silently never boots; theZoo archives are
> password-protected and `tar` silently writes 0-byte files; `/api/remediate` replies
> `{"status":"started"}` and proves nothing.

> ## ▶ (session 12) START HERE reference — 2026-07-22
> **Session 12 applied the whole `REVIEW_FINDINGS_2026-07-22.md` fix list (all 56 findings), the
> 10 GUI/UX proposals, and a new detection expansion (WS6).** Nothing is left half-done; the
> review document can now be treated as closed. Highlights:
>
> **CRITICAL fixes.** (1) `engine/Summary.ps1` and `engine/FixMode.ps1` were missing their
> mandatory top-level `trap` — the exact "hung `-Auto`" failure mode the engine-split rules exist
> to prevent, in the two files CLAUDE.md names explicitly. (2) The PS server sent
> `Access-Control-Allow-Origin: *` with a permissive OPTIONS preflight, so **any page in the
> operator's browser could POST `/api/remediate` and drive real destructive remediation, bypassing
> the typed-PURGE modal**. Now: no wildcard ACAO anywhere, preflight answered only for our own
> origin, an Origin/Referer lock plus a per-process CSRF token (`GET /api/csrf`, `X-ZB-Token`)
> enforced on every POST ahead of the route table. **Verified live** — cross-origin POST, missing
> token and wrong token all 403; same-origin+token and non-browser (no Origin) both 200.
>
> **The anchored-path cluster (#4/#5/#6/#7).** Bare `"AppData|Temp"` substring matches were
> gating auto-selected `KillProcess` (P36, P69, P83), a `sc.exe delete` (P28) and a task
> unregister (P29). All now anchored to path COMPONENTS via `$global:USER_PATH_RE`, WindowsApps
> excluded, and — where the action is destructive — the Authenticode verdict, not the path,
> decides whether it is auto-actionable. P29 on this box went from 3× CRITICAL+RunCmd to
> 2 POSSIBLE/Info + 1 HIGH/RunCmd.
>
> **Rollback actually works now.** `FixMode.ps1`'s snapshot was missing the
> `Windows Registry Editor Version 5.00` magic, so `regedit /S` imported nothing — the safety net
> was decorative. Fixed, and **GUI-driven remediation now takes a snapshot too** (it previously
> took none at all; honours the launchpad's "Create Rollback Snapshot" checkbox).
>
> **WS6 — 9 new fractional phases** (17.5 timestomp · 21.5 SilentProcessExit/EDR-blinding IFEO/COM
> TypeLib · 22.5 AppCert/netsh/Winsock LSP · 42.5 hidden & shadow admin · 44.5 credential-access
> artifacts · 45.5 RDP exposure + hardening set · 68.5 ClickFix/fake-CAPTCHA RunMRU residue ·
> 82.5 RMM abuse · 100.5 cloud/session token theft). All signatures are DATA
> (`data/detection_signatures.json`, 31 new keys), all MITRE-mapped. **Every new hardening/lockdown
> action is Info/POSSIBLE + RunCmd — operator-only, never auto-selected** (user decision, rule #1);
> the GUI's new **🛡 SELECT HARDENING** button is the deliberate opt-in. Fractional numbering was
> chosen so the QUICK/FULL/DEEP plan ceilings and the server's 1..30 QUICK index are untouched —
> **every new phase sits inside a `if (-not $global:QUICK_MODE)` block.**
>
> **UX pass.** Severity pills are real filters; findings search + GROUP BY (threat/severity/MITRE
> tactic/phase) + per-group select-all; the PURGE modal now previews the exact targets grouped by
> fix action and demands `PURGE <count>` for batches ≥10; full keyboard access (skip link, roles,
> focus rings, focus-trapped modals); severity encoded by SHAPE as well as colour; responsive
> breakpoints; a real `@media print` stylesheet; MITRE tactic rollup + persisted remediation
> summary on the Report view; client-facing export with internal fields stripped; SSE-drop toast;
> background-tab notification. GSAP + Chart.js are **vendored locally** (`gui/static/vendor/`) —
> no CDN dependency on an incident host.
>
> **Two bugs found by validating, not by the review:** the server's phase counter walked
> *backwards* at end-of-scan because `Summary.ps1`'s "10 SLOWEST" table prints `PHASE N — …` lines
> that the phase regex matched (a finished DEEP reported 89/115); the counter is now monotonic in
> both servers. And `rerenderLog()` called `appendLogLine()`, which also *pushes* into the buffer,
> so every log filter change duplicated the entire log.
>
> **ROUND 2 — three independent audit agents were run against that commit and found real defects,
> several introduced by it.** All fixed and re-validated; see the "Round 2" section of the
> 2026-07-22 CHANGELOG entry. The ones worth carrying forward:
> - A **malformed operator CIDR matched every connection** → CRITICAL + KillProcess on every
>   connected process from one typo in an IOC file. The hit flag was raised before the compare
>   loop instead of after it. New rule in CLAUDE.md: fail closed, and test malformed input.
> - **`/api/scan/abort` was reachable by GET**, so it skipped the CSRF gate entirely — a
>   cross-origin `<img>` could truncate a running IR scan and make the console report it complete.
>   The gate now covers every non-GET/HEAD method.
> - **The new phases broke the QUICK gate** (30 → 33) by landing just after the enclosing
>   `}   # end QUICK-skip block`. Always re-count after inserting a phase.
> - **The HTML report was broken for any finding containing an apostrophe** — `-replace "'","\\'"`
>   emits `\\'`, which terminates the JS string. Pre-existing; missed on the first pass.
> - **`/api/schedule`** failed on spaced install paths, was argument-injectable via SMTP fields,
>   blocked the single-threaded accept loop, and double-encoded its GET response.
> - Frontend: the SSE pump **replayed its whole batch forever** if any handler threw; SELECT ALL
>   ignored the active filter and replaced the selection; SELECT HARDENING skipped the
>   `vendor_trusted` exclusion and could not reach the INFO-severity ASR set at all.
>
> **KNOWN LIMITATION, deliberately left in:** Phase 39's "installed in the last 30 days" escalation
> is **inert**. It needs a registry key's `LastWriteTime`, which PowerShell's provider does not
> expose (`Microsoft.Win32.RegistryKey` has no such property) — it wants a `RegQueryInfoKey`
> P/Invoke. The branch is correct and will switch on when that is added. Until then Phase 39
> cannot catch a rogue root CA that names itself after a well-known CA, and the code says so.
>
> **Still the only USER-driven items** (unchanged): the browser click-through (BLUEPRINT §7 "Now")
> and the USB foreign-box field test (§7.6). The click-through should now also exercise the CSRF
> handshake, the three previously-inert launchpad toggles, the new findings filters, and the new
> HARDENING pill + SELECT HARDENING button.

> ## ▶ (session 11) START HERE reference
> **WS4 `Get-ProcSnapshot` — Win32_Process snapshot memo (DONE, pushed as `22e582a`).** Seven
> phases each ran their own full `Win32_Process` WMI enumeration. Added a 90-second-TTL memo
> (`$global:PROC_SNAP_CACHE`) shared by phases 3/4/44/99/99.5/102, on the same `ZB_NOCACHE`
> kill-switch as the file cache. **Phase 56 deliberately does NOT use it** — its WMI-vs-Get-Process
> rootkit delta needs both enumerations captured at the same instant, or a snapshot even seconds
> stale fabricates CRITICAL rootkit discrepancies. Validated QUICK + DEEP, 0 recovered errors.


> ## ▶ (session 10) START HERE reference
> **Session 10 = full review of the session-9 (Opus) work + hardening.** Two agent audits found
> **no shipped bug** in the WS4 cache or P82 (all 18 call sites read-only, stealth safe,
> TimeScoped cutoff constant). Hardened 3 latent cache hazards anyway: (1) deadline-truncated
> walks are NOT cached anymore (load-dependent partial sets no longer poison later identical
> calls; MaxFiles-capped walks still cache — deterministic); (2) cache writes gated on the
> `ZB_NOCACHE` kill-switch (A/B runs truly cache-free; switch is PRESENCE-based — any value,
> even "0", disables); (3) cache key keeps caller root ORDER (truncation makes order decide
> which files make the cut — guards future call sites, zero hits lost today). **Also closed the
> PuTTY-suite gap:** pscp/psftp/pageant added to `tunneling_tools` + `tunneling_tools_dualuse`
> → whole suite surfaces at POSSIBLE (never auto-selected; same grade as the signed-off
> putty/plink). Fixed the stale Phase-82 row in `coverage_matrix.json`. See CHANGELOG 2026-07-11.
>
> **Still the only USER-driven items:** the browser click-through (BLUEPRINT §7 "Now") and the
> USB foreign-box field test (§7.6).

> ## ▶ (session 9) START HERE reference
> **All working-tree work is now COMMITTED + PUSHED to origin/main** (P82 dual-use downgrade
> from 2026-07-04 + the WS4 `Get-ScanFiles` memo below + the TIME_LOG reports). `git status`
> should be clean; HEAD == origin/main.
>
> **WS4 (partial) — `Get-ScanFiles` per-scan enumeration memo (DONE, validated live):** the 18
> call sites re-walked the filesystem with zero caching. Added a full-param-tuple memo
> (`$global:SCAN_FILE_CACHE`, `ZB_NOCACHE` env kill-switch, `ZB_CACHE_DEBUG` stats line). A/B on
> live 5.1 DEEP `-Hours 1`: **18/41 walks served from cache, DEEP ~21% faster (503s→397s),
> CRITICAL 5=5 / HIGH 8=8 identical** cache-on vs -off (auto-destructive set unchanged; the small
> POSSIBLE/INFO delta is time-window drift, not a cache bug). **True phase parallelism ruled out**
> (phases share one dot-sourced scope → would race). See CHANGELOG 2026-07-04. **Next WS4:** cache
> the repeated `Get-CimInstance` process/service lookups + per-file sig lookups → sub-2-min QUICK.
>
> **Still the only USER-driven items:** the browser click-through (BLUEPRINT §7 "Now") and the
> USB foreign-box field test (§7.6). All engine/server coding items in §7 remain DONE.

> ## ▶ (session 8) START HERE reference
> **§7 item 7 (wire 15 orphaned signature keys) is DONE + committed** — `bbc2d9d` on main,
> LOCAL/unpushed (now stacked on the session-5/6/7 commits; push the whole stack when you say).
> **§7 item 7 (wire 15 orphaned signature keys) is DONE + committed** — `bbc2d9d` on main,
> LOCAL/unpushed (now stacked on the session-5/6/7 commits; push the whole stack when you say).
> - All 15 keys wired: P67/82/89/98/106 externalize inline literal lists 1:1 (AMSI-liability
>   removal); P6 loader/banking proc IOCs; P34/36 C2 domain families; P55.5 cert-TBS confirm
>   (new `Get-CertTbsSha1` DER helper); P62 framework-name pipe pass; P68 +14 stealer families
>   + loader-drop/C2-config file rules; P100 full 31-path infostealer targets.
> - **A Fable review agent caught 2 rule-#1 auto-fire FPs before commit** (both fixed +
>   live-validated): broad `known_c2_domains` (github/ngrok/tailscale) was feeding P34's
>   DNS-cache HIGH+RunCmd path → split `$MALWARE_C2_DOMAINS` (P34) vs `$ALL_C2_DOMAINS` (P36
>   reverse-DNS only); generic stealer words (atomic/aurora/mystic) auto-killing legit procs →
>   P68 now auto-kills only unsigned + user-writable-path. Post-fix FULL run proved it:
>   `Mystic_Light_Service` (MSI RGB) correctly downgraded to POSSIBLE, not killed.
> - Validated: parse-clean 5.1.26100+7 (BOM intact); DEEP -Hours 1 (121 phases, 0 recovered
>   errors) pre-fix + FULL -Hours 1 (1-80, 0 err) post-fix; TBS helper vs System.Formats.Asn1
>   on 17 certs + malformed-cert OOM guard. See `CHANGELOG.md` (2026-07-02 late night).
>
> **§7 item 8 (make QUICK a real gate) is ALSO DONE + committed** — `e3c4998` on main, local/
> unpushed. QUICK now runs exactly 30 triage phases
> (`1,3,4,5,6,10,20,21,23,27,28,29,30,31,33,35,41,42,45,51,53,54,56,62,64,69,70,72,74.6,75`);
> the other 54 in 1–80 are wrapped `if (-not $global:QUICK_MODE) { trap {…}; body }`
> (contiguous-run blocks, inner trap each). Server reports a 1..30 `PhaseIdx` as `phase` in
> QUICK only (findings keep the true phase). FULL/DEEP/etc byte-identical. **Also fixed a latent
> Phase-56 rootkit bug** (`foreach ($pid …)` clobbered read-only `$PID` → hidden-process
> detection silently died whenever a discrepancy existed; renamed `$rkpid`). Three Fable agents
> assisted (design, cross-phase leak audit = 0 leaks, server progress-index). Validated: QUICK
> = exactly 30 phases / 0 recovered errors; FULL = all 84 steps / 0 errors; **live headless
> server QUICK scan → /api/state counter 1..30, ends 30/30, never overshoots**; parse-clean
> 5.1+7, BOMs intact. coverage_matrix mode_gate corrected. See CHANGELOG 2026-07-03.
>
> **NEXT: the roadmap's remaining items are the USER-driven ones** — (§7.6) USB portability
> field test on a non-dev box, and the browser click-through (destructive PURGE + protected
> HARD-block, exports, IOC save→rescan, STEALTH, the SCAN PROFILES picker, and now a QUICK
> scan showing the 1..30 counter). All engine/server coding items in §7 are DONE.
>
> ~~**Still open:** P82 putty/plink CRITICAL+DeleteFile~~ **SIGNED OFF + FIXED 2026-07-04:**
> user approved the downgrade — putty.exe/plink.exe now grade POSSIBLE via the new
> `tunneling_tools_dualuse` JSON key (shown, never auto-selected; other tunneling tools keep
> CRITICAL). Validated live 5.1 + decoy FULL run. See CHANGELOG 2026-07-04. **No FP sign-offs
> remain open.**

> ## ▶ (session 7) START HERE reference
> 0. **Session 7 (2026-07-02 night) closed BLUEPRINT §7 items 4+5** (commits `5e21683` + `fea1960`,
>    local, NOT pushed — now 4 commits ahead of origin):
>    - **Scan profiles shipped + live-verified**: `GET|POST /api/profiles` (4 read-only builtins +
>      user presets in `reports/scan_profiles.json`, fail-closed validation) + SCAN PROFILES picker
>      at the top of MISSION PARAMETERS. An 8-angle agent review before commit caught and fixed: the
>      PS 5.1 empty-pipeline `$null` (save→delete-all→save persisted a literal null that crashed the
>      picker), corrupt-file POST wiping all profiles, hours coerce-to-ALL-TIME, `[bool]'false'`
>      string flags, builtin `ioc_file:''` clobbering the IOC Manager's path, swallowed error toasts.
>    - **Server-wide bug found while verifying: malformed JSON in ANY POST body hung the browser
>      forever** (PS 5.1 `ConvertFrom-Json` throws terminating; route died with no response). Fixed:
>      `Read-JsonBody` helper + accept-loop 500 net; `/api/scan/start` now 400s on a garbled config
>      instead of silently starting a default-scope scan. New rule in CLAUDE.md → HTTP routes.
>    - **WS0 coverage re-audit done by agent, validated, committed**: `data/coverage_matrix.json`
>      regenerated against main (121 phases, +55.5/+99.5). Gap list in `fea1960`'s message. Two
>      discoveries promoted to BLUEPRINT §7 items 7–8: **15 orphaned signature keys** (P67/68/82/89/98
>      use inline literals while the JSON keys sit unused) and **QUICK mode is a label, not a gate**
>      ($PhasePlan.Max is display-only → QUICK runs 1–80 like FULL while advertising 30 phases).
>    - **Browser click-through additions for the user's run:** exercise the SCAN PROFILES picker
>      (load a builtin, save/delete a custom one — expect toasts on errors) alongside the session-5
>      checklist below.
> 1. Read **`BLUEPRINT.md`** (product map + §7 roadmap) — it supersedes NEXT_STEPS/UPGRADE_PLAN.
> 2. **Session 6 (2026-07-02 evening, commit `fcb8199`) closed BLUEPRINT §7 items 1+2:** graded the
>    same-day live DEEP baseline `_143221` (39 auto-destructive vs the 52 reference; WS2 detections
>    clean), got user sign-off, and cleared EVERY healthy-box FP in the auto-destructive tail —
>    P20 OneDrive-RunOnce/LogiLDA, P31 (.lnk TARGET resolution — shortcuts are never signed),
>    P42→Info (was auto-disabling the box's real account), P47 (bare `Desktop` substring matched
>    `WhatsAppDesktop` under WindowsApps → component-anchored), P48/P94 package trees, P63 LGHUB,
>    P86→POSSIBLE, P90 renderer DLLs + scratchpad, P96 (catalog-signed printer DLLs — Get-AuthSig
>    can't see catalog sigs). 6 new `fp_allowlists` keys; all downgrade-or-Info, zero detections
>    deleted. A review subagent caught an **attacker-satisfiable allowlist pattern**
>    ("Uninstall OneDrive" name-prefix → self-allowlist) before commit → new CLAUDE.md rule:
>    value-allowlists must `^…$`-pin the exact benign shape. Validated: parse-clean 5.1.26100 + 7,
>    BOMs intact, 16-case regex regression on live 5.1, and a full headless DEEP re-run `_192913`
>    (853 findings, 0 recovered errors, every downgrade path fired). **Committed locally, NOT
>    pushed** (several sessions' commits stacked — push when the user says).
> 3. **THE open acceptance item is unchanged: the user's browser click-through** — runbook below
>    ("NEXT SESSION — live GUI end-to-end validation") + the session-5 additions (live ticker/
>    chips populate DURING the scan, severity-colored log lines + working CRIT/HIGH/POSSIBLE
>    filters, clean box-drawing banners, real completion-modal counts) + the session-7 addition
>    (SCAN PROFILES picker: load a builtin, save/delete a custom preset, expect error toasts).
> 4. ~~scan profiles / coverage-matrix re-audit~~ **both DONE in session 7** (see item 0). Next
>    CODING items per BLUEPRINT §7 are now **items 7–8 from the WS0 audit**: (7) wire the 15
>    orphaned signature keys — P67/68/82/89/98 still use inline literals while
>    `adware_pup_regs`/`infostealer_procs`/`tunneling_tools`/`stego_tools`/`leaked_cert_issuers`/
>    `cred_dump_tools`/`byovd_cert_tbs_hashes`/… sit unused in `detection_signatures.json`
>    (cheap, widens coverage, removes AMSI-liability literals); (8) make QUICK a real gate —
>    `$PhasePlan.Max` is display-only so QUICK runs phases 1–80 while advertising 30 (engine
>    change: decide the QUICK set, gate per the module-trap rules, keep `phase_total` honest).
>    Then the USB foreign-box field test (user-driven).

> ## Session 5 header (superseded pointers kept below for context)
> Session 5 fixed the dead live-finding pipeline + the `$SEV` classify shadow, created
> BLUEPRINT.md, and shipped the portable release build (`tools/Build-Release.ps1` + MotW
> self-unblock + README deploy guide) — all validated headless.
>
> ## Session 5b (2026-07-02) — portable distribution (user's core requirement)
> - **`tools/Build-Release.ps1`** — validated release-zip builder (parse+BOM+JSON gate, runtime
>   files only, SHA256 sidecar, `-OutDir`/`-IncludePython`). `dist/` gitignored.
> - **MotW self-unblock** at server startup (runtime tree only); README "Deploy to another
>   machine" section (zip → verify → Unblock → extract → Launch-GUI.bat).
> - **Proven:** extracted release in a spaced path boots, serves the GUI (HTTP 200), answers
>   `/api/state`; all packaged scripts parse clean from the extracted tree.

> ## Session 5 (2026-07-02) — the promised log analysis, and what it found
> Analyzed the 2026-07-01 live GUI DEEP run artifacts (`server_events_20260701_185058.log`,
> `audit_20260701_190044.json`, `KrakenConsole_20260701_185111.log`):
> - **✅ Phase-counter fix `c0477ae` VALIDATED** — `scan_state` events carry all 116 phase values
>   0→115 with no gaps; the counter can no longer skip fast phases. (231 scan_state events total.)
> - **🐞 FOUND + FIXED: the live finding stream was dead.** The whole DEEP run produced **0** SSE
>   `finding` events and all-1266-lines-INFO classification, while the engine recorded **288
>   findings** — the engine's stdout finding lines (`[RUN KEY] …`) carry no severity tags for the
>   server's `Classify` regexes. That's also why `audit_20260701_190044.json` has `findings: []`
>   (it snapshots the server's live findings — NOT an "expected summary shape"). **Fix:**
>   `Add-Finding` now emits one `[FINDING] {compact JSON}` line per registered finding
>   (NONINTERACTIVE, non-stealth); the server intercepts those as the authoritative live-finding
>   source (exact severity, canonical threat bucket, MITRE, `fix_action`/`target` added to the
>   event) and the old text-severity→finding path was retired (would double-count). Frontend
>   needs no changes (audited: chips/ticker/badge consume `finding` events; sounds throttled;
>   completion still replaces the list from `/api/report`).
> - **🐞 FOUND + FIXED: mojibake in the GUI log** — child PS 5.1 wrote redirected stdout in the
>   OEM codepage while the server read UTF-8. Loader now sets `[Console]::OutputEncoding` UTF-8
>   when stdout is redirected. Also: `Classify` CLEAN regex now tolerates the padded `[OK ]` tag.
> - **Also:** early `Import-Module Microsoft.PowerShell.Security` in the loader (pre-empts the
>   ACL TypeData collision degrading `Get-AuthenticodeSignature`); **`BLUEPRINT.md` created** —
>   product map + data contracts + prioritized roadmap (start there); CLAUDE.md/NEXT_STEPS/
>   UPGRADE_PLAN refreshed to match.
> - **Remediation/export/IOC/STEALTH were NOT exercised** in the 07-01 run (SSE log ends at
>   `scan_complete`; no `[FIX]` lines) — the browser click-through below remains THE open item,
>   now also covering: live finding ticker/chips populate during the scan, banners render clean
>   (no `�`), and the completion modal's live counts are real.
>
> ### Session 5 validation (all on live PS 5.1.26100; server + engine parse-clean 5.1+7, BOMs intact)
> 1. **Headless engine QUICK** (server-style UTF-8 redirect): exit 0, **218 `[FINDING]` lines**
>    (12 CRIT / 9 HIGH / 175 POSSIBLE / 22 INFO), 0 mojibake, box-drawing banners clean.
> 2. **End-to-end server scan #1** (real `/api/scan/start` → SSE log `_013641`): **217 finding
>    events streamed live** with exact severities + resolved MITRE (`fix_action`/`target` on each),
>    threat_counts populated, `audit_20260702_014027.json` findings **217** (was `[]`). But all
>    log_lines still INFO → dug in → **found the `$sev`/`$SEV` case-insensitive variable shadow**:
>    `Classify`'s local `$sev='INFO'` shadowed the `$SEV` regex dict (PS vars are case-insensitive),
>    so severity classification had NEVER worked, on any run, ever. Dict renamed **`$SEV_RX`**.
> 3. **End-to-end server scan #2** (post-fix, SSE log `_014742`): **229 finding events**
>    (12 CRIT / 22 HIGH / 195 POSSIBLE), log_line severities finally real (69 CLEAN / 57 HUNT /
>    13 POSSIBLE / 4 HIGH / 3 CRIT / rest INFO), `audit_20260702_015127.json` findings **229**,
>    0 mojibake, 202s elapsed, clean scan_complete. Test server stopped after.
>
> **For the next browser run, additionally verify:** live intel ticker + threat chips populate
> DURING the scan; log lines are severity-colored + the CRITICAL/HIGH/POSSIBLE log filters work;
> banners show clean box-drawing (no `�`); completion modal live counts are no longer ~0.

# (session 4 record) — updated 2026-07-01 (engine split + WS2 detection port)

> **THIS SESSION shipped a major architecture change** — read the 2026-07-01 `CHANGELOG.md` entry and
> CLAUDE.md's new "Engine is split" rules before touching the engine. The monolith
> `ZeroBreach-V23.ps1` is now a thin loader dot-sourcing `engine/Phases-1/2/3.ps1` + `Summary.ps1` +
> `FixMode.ps1`. We took the work-rig branch's split architecture (it was the better long-term
> approach — multiple detection agents can now edit separate modules) but rebuilt it on `main`'s
> live-validated engine and its FP tuning, then merged the WS1/WS2 detection data and ported 6
> new/upgraded detections (all `FixAction Info`, no new auto-destructive findings).
>
> **Commits this session (local, unpushed):** `efee013` docs · `dcf8793` split · `585fe57` data merge ·
> `1894fa1` detection port · `29f5a0e` **the dot-source trap fix** · `3715fd8` docs. Plus the earlier
> unpushed `f198420` (docs). **Push when ready** (all validated headless; the outer repo's remote is
> `github.com/zazathebird/zerobreach`).
>
> **Validated headless:** parse-clean PS 5.1.26100 + 7.6.3 (all 6 files, BOM intact); FULL `-Auto` ran
> phases 1-80 contiguous + fractional phases, clean self-exit, reports written. DEEP (1-115) run was
> finishing at handoff — confirm 115 + re-grade auto-destructive from its baseline (target still 52).
>
 > **UPDATE 2026-07-01 PM — the live GUI run HAPPENED and the engine side PASSED.** User launched
> `Launch-GUI.bat` as admin and ran a **DEEP** scan in the browser: all **115 phases contiguous, 0
> RECOVERED ERRORS**, new phases (55.5/69/99.5) fired, clean exit ~9.5 min on the real PS 5.1 server
> (`http://localhost:1183`). Logs saved in `reports/` (timestamps `*_20260701_185*` / `_190044`).
> **NEXT SESSION: analyze those logs** — especially `server_events_20260701_185058.log` for (a) the
> phase-counter cadence (validate server fix `c0477ae` — did scan_state step 1→115 without jumping),
> and (b) whether remediation/export/IOC-save/STEALTH were exercised. **Also check:** the server's
> `audit_20260701_190044.json` shows `findings: []` while `KrakenBaseline_20260701_185111.json` has the
> real findings — confirm that's an expected summary shape, not a server-summary wiring gap. If the SSE
> log shows the user didn't click remediate/export, ask them to exercise those next GUI run.
>
> **OPEN ITEM (narrowed): browser click-through of destructive remediation (PURGE + protected HARD
> BLOCK), export downloads, IOC save→re-scan, STEALTH.** The scan/engine path is now proven live; these
> UX paths still need a confirming look (headless/API already validated them). Prep done (tripwires
> laid, server + engine parse-clean) — see "NEXT SESSION" runbook below.
>
> ### Session 3 (2026-07-01) — prep RE-VERIFIED, no code changes; ready to launch
> Re-checked all prep before handing off for the browser run:
> - **All 5 `_DELETEME` tripwires still present** (TEMP `.bat`, Downloads `.cmd`, HKCU Run value,
>   Outlook-cache `.bat`, disabled scheduled task) — no need to re-lay.
> - **`ZeroBreach-Server.ps1` parse-clean on PS 5.1.26100 AND 7.6.3**, UTF-8 BOM intact.
> - **`app.js` `node --check` clean.**
> - Git: **1 local commit ahead of origin — `f198420` (docs-only:** CLAUDE.md/CHANGELOG
>   consolidation, no code). User said **push later** — safe to push anytime, no code impact.
> - Nothing else changed this session. The live GUI click-through (runbook below) is untouched and
>   is the sole remaining task; the `c0477ae` phase-counter fix still needs its first in-browser look.

## Session 2 (2026-06-28 PM) — phase-"skipping" diagnosed (NOT an engine bug) + 2 server fixes — `c0477ae`
User watched a live DEEP run and reported it "skipped MANY MANY phases (unless instant)." Investigated
the in-progress + finished console log (`KrakenConsole_20260628_152000.log`): **all 115 phases ran
contiguous, 0 RECOVERED ERRORs** — nothing skipped at the engine level. Root cause was **frontend
display cadence**: the visible phase counter/progress bar updates only on `scan_state` (app.js
`:205-211`), but the server emitted `scan_state` only every 12 log lines (`%12`). A sub-second phase
emits <12 lines, so several phases pass between emits and the counter jumps (e.g. 94→97) — the fast
phases *look* skipped. Many phases genuinely ran in 0–0.3s on this box.

Two server-only changes committed (`c0477ae`, engine `ZeroBreach-V23.ps1` untouched; parse-clean PS
5.1 + 7, all 3 here-strings, BOM intact):
1. **Phase-skip display fix** — also emit `scan_state` immediately whenever the phase number changes
   (in the scan-runspace parse loop, next to the `$PREX.Match` at `~:669`), in addition to the `%12`
   cadence. Counter can no longer skip a phase. **Not yet visually confirmed in-browser** (fold into
   the live-GUI validation below).
2. **Durable run logs** — `reports\server_console_*.log` (main-thread console via `Start-Transcript`,
   stopped in the accept-loop `finally`) + `reports\server_events_*.log` (the FULL SSE stream — every
   log_line/finding/[FIX] line + remediation_complete, teed by `Enqueue`/`REnqueue` since runspace
   output never hits the console). Path carried on `$script:State.EventLogFile`. These give the next
   live-GUI session real post-run artifacts to debug from.

Fresh full-scope re-grade of `KrakenBaseline_20260628_152000.json` (DEEP `-Hours 0`): **855 findings,
52 auto-destructive** (matches the `_143641` baseline), breakdown all by-design/known-FP tail (P10×34
TEMP execs + tripwires, P20/P29/P74.5 `_DELETEME` tripwires, P41/42/46 hardening, P31 AnyDesk/Ollama
`.lnk`, round-4-known 1-offs P48/53/63/90/94/96). **0** drive-root/`icacls /reset /T`/`vssadmin delete
shadows`/`/remove:g` FixParams — round 5 holds at full scope. **NOT pushed** (commit is local on main;
push when convenient).

Latest engine work: **FP-tune round 5** (2026-06-28). Engine `ZeroBreach-V23.ps1` touched ONLY for
FP severity/FixAction tuning — no scan-logic/coverage regression. See CLAUDE.md → "Round 5".
**Round 5 COMMITTED + PUSHED** as `b59a3e4` (2026-06-28) — parse-clean PS 5.1 (5.1.26100) + 7.6.3,
BOM intact. **Live `-Hours 0` re-grade DONE** (`KrakenBaseline_20260628_143641`, auto-destructive 52,
Phase-29 fix confirmed, 0 drive-root/`icacls /reset` ops).

## Round 5 (2026-06-28) — the Phase 108 `icacls C:\ /reset /T` catastrophe + ACL-cluster siblings
Driven by live `DEEP -Hours 1` runs (`_124244` before, `_132719` after). **Phase 108 offered a
recursive ACL reset of the ENTIRE C: drive (`icacls "C:\" /reset /T`) as a HIGH auto-remediation
that fires on every healthy box** — the exact system-damage rule #1 forbids. A `FixParam` sweep
found a sibling family. Cut live auto-destructive **21 → 7** (residual 7 all by-design: 2 `_DELETEME`
tripwires + 3 hardening posture items P41/P42/P46 + Logitech-via-rundll32 + a non-MS OneDC_Updater
task). All downgrade-or-skip; dangerous commands moved into finding *descriptions* (`FixAction Info`).
Fixed: **108/16/43/111/112/115** (ACL cluster → Info), **109/113** (skip non-PE `hosts`, status-split
UnknownError→POSSIBLE, SFC only on genuine tamper), **8** (browser ext), **17** (ADS SmartScreen),
**24** (COM needs Inproc+shadow), **20** (Run-key drop bare AppData), **26** (BHO → POSSIBLE), and
**29** (on-disk task-XML check now skips `\Tasks\Microsoft\` + downgraded to POSSIBLE — was flagging
legit Windows system tasks HIGH+DeleteFile, only visible at all-time `-Hours 0`).
Parse-clean PS 5.1 (5.1.26100) + 7.6.3, BOM intact.

Validated on THREE live runs: `-Hours 1` auto-destructive **21 → 7**; full `-Hours 0` all-time
**75 → 57** (`KrakenBaseline_20260628_133545`, before the Phase-29 fix — that removes ~4 more legit
`\Microsoft\` system-task DeleteFiles). **Sanity-confirmed: NO `icacls /reset /T`, NO `icacls "C:\`,
NO `/remove:g` in any destructive FixParam** at all-time scope (the only `vssadmin` hit is the INFO
opt-in VSS option). 0 recovered errors. The Phase-29 fix is parse-clean but post-dates the `_133545`
run, so a fresh `-Hours 0` re-grade would show ~53.

### Residual all-time auto-destructive (~53) — breakdown for the next session
- **By-design (leave):** ~34 **Phase-10 TEMP executables** (the user's own dev/analysis scripts +
  Claude scratchpad + `zb-vfx-profile` browser-temp + the `_DELETEME` tripwires — round-4 ruled
  "TEMP-exe = HIGH is intentional"); P20/P29/P74.5 `_DELETEME` tripwires; P41/P42/P46 security-posture
  hardening; AnyDesk/Ollama startup `.lnk` (P31, dual-use — worth surfacing); Logitech-via-rundll32
  + `OneDC_Updater` non-MS task (correct to surface).
- **Round-4-known 1-off FPs — NOT auto-tuned (each trades real detection coverage; need user sign-off):**
  P48/P94 Python `LocalCache`, P53 Sysinternals `readme.txt` (ransom-note heuristic), P63 LGHUB
  `config.json`, P90 claude-scratchpad `.ps1` (content-matched analysis scripts), P96
  `spool\drivers\…\PCL5URES.DLL` (legit printer driver — PrintNightmare heuristic, no signed-check).
  None is a flood; all are hard-protected where relevant. Ask the user before downgrading these.

### What's NOT done / next
- ~~COMMIT + PUSH round 5~~ DONE — `b59a3e4`, pushed to origin/main 2026-06-28.
- ~~Fresh `-Hours 0` re-grade to confirm the Phase-29 fix~~ DONE — live `DEEP -Hours 0` run under
  PS 5.1.26100 (`KrakenBaseline_20260628_143641.json`, exit 0): **auto-destructive 52** (952 total),
  matching the predicted ~53 and down from 75 at the pre-round-5 all-time baseline `_133545`. Verified
  **0** `\Tasks\Microsoft\` tasks in the auto set (Phase-29 fix confirmed) and **0**
  `icacls /reset /T` / `icacls "C:\` / drive-root ops (the only icacls/vssadmin RunCmd is Phase 43's
  VSS option at INFO — not auto-selected). Residual 52 is all by-design: 34× Phase-10 TEMP execs
  (own dev scripts + tripwires), `_DELETEME` tripwires (P20/P29/P74.5), Logitech-via-rundll32,
  OneDC_Updater non-MS task, AnyDesk/Ollama startup `.lnk` (P31), P41/42/46 hardening, and the
  round-4-known 1-off FPs (P48/53/63/90/94/96 — still need user sign-off before downgrading).
- **THE ONE REMAINING ITEM → live GUI end-to-end validation.** Round 5 was engine/findings only;
  the browser+admin path has never been exercised. Runbook below.

## NEXT SESSION — live GUI end-to-end validation (the only open item)

**Prep already done (2026-06-28, this session):** all 5 benign `_DELETEME` tripwires are freshly
laid down on the box (TEMP `.bat`, Downloads `.cmd`, HKCU Run value, Outlook-cache `.bat`, disabled
scheduled task — verified present); `ZeroBreach-Server.ps1` parses clean PS 5.1 (5.1.26100) + 7.6.3,
BOM intact; `app.js` `node --check` clean. So the launch is ready — nothing else to set up.

**Split (decided with user — saves tokens, no loss to debugging):**
- **USER runs the browser click-through** (eyes-on, can't be driven headlessly here). The model's
  debug ability depends on *artifacts*, not who launched — so when something's off, the user pastes
  the server console / browser-console error, points at the report JSON, or drops a screenshot.
- **MODEL can do the API/server layer headlessly** (no browser) if desired BEFORE handing off, or to
  reproduce a bug the user hits: start the PS server, then hit `/api/export/html`, `/api/export/csv`,
  `/api/ioc` GET+POST (verify the `.ioc` prefixed-text emit — `hash:`/`ip:`/`domain:`/`regex:`/`file:`),
  `/api/report?name=KrakenBaseline_…`, `/api/remediate {report,ids[]}` (id-filter + the protected
  HARD-block → `blocked` count), and STEALTH JSON parsing. These are server-driver logic, browser-free.

**User runbook (what to click + what to capture):**
1. `Launch-GUI.bat` as admin (self-elevates; pure-PS server, no Python). Browser auto-opens.
   - If blank/grey screen: it self-heals (reloads ≤2×). If it stays blank, capture
     `zerobreach_launch_error.log` (project root) + browser console.
2. Config → **DEEP**, **All time** → start scan. Wait for `scan_complete`.
3. **FINDINGS view** — confirm: MITRE badges render (clickable `.item-mitre`); the `🛡 PROTECTED`
   items show a green/shield badge and their checkbox is **disabled** (can't tick); vendor items show
   `✔ TRUSTED`. The 5 `_DELETEME` tripwires should be present + tickable.
4. **Force-test the hard block:** the protected items must stay un-tickable even via Select-All; the
   completion modal should report a non-zero `blocked` count if you somehow POST one.
5. **REMEDIATION** → select ONLY the `_DELETEME` tripwires → type `PURGE` → EXECUTE. Confirm:
   TEMP `.bat` + Downloads `.cmd` deleted (DeleteFile), HKCU Run value removed (DeleteReg), scheduled
   task unregistered (RunCmd), Outlook-cache `.bat` moved to `reports\quarantine\` with a `.quar.json`
   manifest (Quarantine). `remediation_complete` shows applied/failed/skipped/blocked.
6. **Exports:** HTML + CSV download buttons produce files. **IOC Manager:** save a set → confirm
   `reports\custom_iocs.ioc` written in prefixed-text format → rescan picks it up via `-IocFile`.
7. **(optional) STEALTH** scan → confirm findings still parse (engine emits JSON, server buffers+parses).

**Capture for the model:** the `KrakenConsole_*.log` / server console, the `remediation_complete`
payload, the `reports\quarantine\*.quar.json`, and a screenshot of the FINDINGS view (badges +
disabled checkboxes). Re-lay tripwires between runs with the create block in CLAUDE.md → "Remediation
test tripwires" (cleanup block there too).

---

## (historical) Round 4 and earlier

Everything below was committed to **`main`** and **PUSHED** to origin. Round 4 (`65782ce`):
Engine `ZeroBreach-V23.ps1` was touched ONLY for FP severity/allowlist tuning + one PS-5.1
runtime-bug fix — no scan-logic/coverage regression.

## Round 4 (2026-06-26) — VALIDATED ON FRESH LIVE RUNS (the big one)
Driven by **live admin `DEEP -Hours 0` runs** (not the stale 06-23 simulation). Cut auto-selected
**destructive** findings **319 → 75** (3 live runs: before `_022730`, after `_024320`/`_025617`).
The residual 75 are a healthy low-count tail (≤5 per phase, incl. deliberate tripwires) — no floods.
Highlights (full table in CLAUDE.md → "Round 4"):
- **PS-5.1 `Get-Sig` string-indexing bug** — `(Get-Sig X)[0]` indexed into the *unwrapped string*
  (→ first char `'h'`), so `-match 'h'` matched every https URL → Phase 31 flagged all 48 BITS jobs
  HIGH. Same bug broke the named-pipe regex. This silently broke the round-2/3 fixes **on the real
  5.1 runtime** (they were only simulated in PS 7). Fixed → `@(Get-Sig X)[0]`.
- Phase 32 (DLL-hijack), 66 (share-worm), 24 (COM), 15 (System32 sig), 19 (script assoc), 75
  (Defender excl) — all downgraded/skip-fixed so legit dev-tool DLLs, the user's own exes/scripts,
  Teams' per-user COM, catalog-signed System32 DLLs, Windows default assocs, and RMM exclusions are
  **never auto-selected for destructive remediation**. Every change is downgrade-or-skip only.
- All parse-clean PS 5.1 + 7 (0 errors), BOM intact, JSON valid; verified across 3 live runs.

### Residual 75 auto-destructive — triaged (NOT floods; your call on further tuning)
After round 4 the remaining destructive set is a low-count tail. Reviewed the live `_025617` report:
- **By-design / tripwires (leave):** P10 TEMP executables (×38 — incl. your own dev scripts
  `zbparse.ps1`/`transpile-check.js`/etc.; TEMP-exe=HIGH is intentional), the
  `ZeroBreach_TEST_DELETEME` Run-key/task/Outlook tripwires (P20/P29/P74.5), security-posture items
  (P41 RunAsPPL, P46 LmCompat, P42 Guest), AnyDesk/Ollama startup `.lnk` (P31 — dual-use, worth surfacing).
- **Minor 1-off FPs — judgment calls I deliberately did NOT auto-tune while you were AFK** (each trades
  detection coverage, so they want your sign-off):
  - **P20 Run-key (CRITICAL DeleteReg):** Discord / Teams / Logitech Download Assistant flagged
    because their `AppData\Local\…` Run value matches the `AppData|Temp|cmd|powershell` regex. Plain
    **AppData** is too broad a signal (every legit app autostarts from there). *Recommended:* drop the
    bare `AppData` term from the Run-key match (keep Temp/powershell/cmd/encoded) — the
    `..._DELETEME` tripwire still fires (it points at `%TEMP%`). I left it unchanged pending your OK.
  - 1-each CRITICAL/HIGH on legit files: Sysinternals `readme.txt` (P53 ransom-note heuristic),
    LGHUB `config.json` (P63), Python `LocalCache` (P48/P94), a few `\Microsoft\Windows\…` system
    tasks (P29 — System32\Tasks is hard-protected so never auto-acted), claude-scratchpad `.ps1` in
    TEMP (P90, content-matched my own analysis scripts). All low-volume; not worth coverage risk
    without your input.

None of the 75 is a flood and the safety guard hard-blocks the protected ones; the system-damage risk
the round addressed (mass auto-delete of System32 DLLs / dev tools / the user's own files) is gone.

## (historical) Rounds 1–3 context below

## Where we are

Today's work (all committed): MITRE tagging, IOC Manager, HTML/CSV export, STEALTH parsing,
**real GUI remediation**, benign test tripwires, a **system-damage safety guard (complete)**,
the trusted-vendor allowlist (Datto/CentraStage/Kaseya), and most recently **Cinematic FX
toggles + boot self-heal** (`b8a13de` — opt-in per-effect switches over the theme system; blank
/grey-screen-on-launch auto-reload; FX audit back to PASS 13/13). See CLAUDE.md → "Cinematic FX
toggles + boot self-heal".
The scan engine `ZeroBreach-V23.ps1` is deliberately untouched. See CLAUDE.md → "Feature wiring
completed 2026-06-23", "Remediation safety guard", and "Remediation test tripwires".

### Context: the live scan that drove the safety work
A real DEEP scan produced **1305 findings, ~772 auto-selected destructive — overwhelmingly FALSE
POSITIVES**, including dangerous ones (would delete 100 root CAs incl. Microsoft/Amazon, the user's
`.bashrc`/`.gitconfig`/`.claude.json`, IconCache, and KILL the running `claude` process). The
detection engine is NOT false-positive-tuned. **User's #1 priority: the tool must NEVER select or
apply anything that damages the system.**

## DONE & COMMITTED — system-damage safety guard (defense-in-depth, all 3 layers)
- `0cf6529` **Layers 1 + 3 (server):** `Test-ProtectedTarget` (main thread) tags every finding served
  to the GUI with `protected` + `protected_reason`; `Test-RProtected` (mirror in `$script:REMEDIATE_SCRIPT`)
  **hard-blocks** any fix on a protected resource regardless of selection, and reports a `blocked` count.
  Protects: certificate trust store, Windows/System32/SysWOW64/WinSxS, shell-system files
  (desktop.ini, IconCache.db, *.library-ms, ntuser.dat), user dotfiles (.bashrc/.gitconfig/.ssh/
  .claude.json/…), SafeBoot + core OS registry, and KillProcess of critical processes or the IR tool.
  Verified against the live report: blocks 285 destructive ops, still allows legit Temp/Downloads deletes.
- `127a765` **Layer 2 (frontend) + modal fix:** protected findings can never be ticked (checkbox
  disabled, excluded from auto-select / Select-All / the ids POSTed to `/api/remediate`); `🛡 PROTECTED`
  badge with reason tooltip; `onRemediationComplete` shows the blocked count. Completion modal now shows
  the engine report's real totals instead of the ~0 live SSE count.

Validation: server parses clean PS 5.1 + 7 (all here-strings); `node --check` clean; FX audit PASS 13/13.

## REMAINING TODO

### Detection false-positive tuning — round 1 DONE 2026-06-23 (engine)
The three highest-volume capped-at-100 over-matchers are now tuned (see CLAUDE.md → "Detection
false-positive tuning — engine, round 1"). Allowlists added to `data/detection_signatures.json`
`fp_allowlists` block (AMSI-safe), loaded via `Join-AllowRegex`. Simulated vs.
`KrakenBaseline_20260623_135347.json`:
- **Rogue Certificates** 101 CRITICAL → 98 INFO + ~2 POSSIBLE (well-known-root allowlist).
- **Cloaked/Hidden Files** 101 → ~3 (benign-name allowlist + payload-extension gate; skip data files).
- **Info-Stealer files** benign browser/app dictionaries suppressed; loose creds files → POSSIBLE.
- Already-fixed (no action): Phase 94 COM Scriptlet (`.sct/.wsc`-only), Phase 66 Share Worm (ext-filtered).
Engine parse-clean PS 5.1 + 7, BOM intact. **Not yet validated on a live admin run** (estimates simulated).

**Round 2 DONE** (`082106f`): SafeBoot Hijack (101→0), Named Pipe Backdoor (98→0), Prefetch (HIGH→
POSSIBLE). Event Log/MoTW verified already non-destructive.

**Round 3 DONE** (`b1b7252`): the last two destructive floods. *Hidden Scheduled Tasks* (Phase 104,
57 HIGH DeleteFile of legit Win/Google/MSI/.NET maintenance tasks → INFO/POSSIBLE + Info) and *BITS
jobs* (Phase 31, 49 HIGH RunCmd on normal OS/app-updater transfers → POSSIBLE + Info, escalate to
HIGH only on raw-IP remote or exec-to-userpath). See CLAUDE.md → "Round 3". Allowlists/regexes in
`data/detection_signatures.json`. **Verified stale-report claims hold in current source:** COM
Scriptlet (Phase 94) IS `.sct/.wsc`-only and Share Worm (Phase 66) IS ext-filtered — the report's
100/77 hits on IconCache/`.bashrc`/NTUSER.DAT are from a pre-fix build, not current code.

**FP tuning is now complete for every capped-100 + mid-volume (49–77) destructive flood in the saved
report.** Remaining destructive groups are small (≤27, e.g. User TEMP Executables — legit, that's
where the tripwires live). The big remaining item is the LIVE admin run below.

### Live end-to-end validation (still pending from before)
A real admin `Launch-GUI.bat` run exercising: scan → MITRE badges → HTML/CSV download → IOC save→scan
→ STEALTH scan → and **remediation on the benign tripwires** (verify the `🛡 PROTECTED` items are
un-tickable and that blocked count shows if you force one). Tripwires: see CLAUDE.md.

## Validation commands

Run the parse check on **real `powershell.exe` 5.1**, not `pwsh` — the PS-5.1-only failure modes
(single-element unwrap, `(try{}catch{})`, `,$arr`, Windows-1252 decoding of a BOM-less file) do not
reproduce on 7. No helper script needed:

```powershell
# Parse-check any .ps1 (prints nothing on success)
powershell.exe -NoProfile -Command "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('<abs path>.ps1',[ref]$t,[ref]$e);$e"

# BOM check — the first 3 bytes of every repo .ps1 must be EF BB BF
powershell.exe -NoProfile -Command "Get-Content '<abs path>.ps1' -Encoding Byte -TotalCount 3"
```

The server additionally needs its `@'...'@` here-strings extracted and `ParseInput`-checked
separately (they are runspace scripts — a syntax error in one is invisible to `ParseFile`).

```
node --check gui/static/js/app.js
node tools/check-visuals.mjs   # FX audit, expect PASS 13/13 (kill stray zb-vfx-profile browser first)
cd native-app && npx tauri build   # then actually LAUNCH the .exe — compiling is not running
```

Newest engine report analyzed: `reports/KrakenBaseline_20260623_135347.json`.
Test tripwires (still on the machine, named `ZeroBreach_TEST_DELETEME`): recreate/cleanup in CLAUDE.md.
