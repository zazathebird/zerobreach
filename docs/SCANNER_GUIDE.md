# Scanner implementation guide

Conventions for writing a new detection category or changing an existing one. All ten
categories in the spec's §3 list are implemented (`PersistenceScanner` … `EventLogScanner`);
read the nearest existing scanner alongside this guide — it is the working example of every
rule below.

Background: `_ENGINE_SPEC_FOR_REBUILD.md` §3 (your category), §4, §5, §6, and
`INSTRUCTIONS_AI.md` §2 (the contracts) and §5 (what each existing check does). The Core
contracts you code against:

- `ZeroBreach.Core/Scanning/IScanner.cs`, `ScanContext.cs`, `IFindingSink.cs`,
  `EnumerationBudget.cs`, `FindingCollector.cs`
- `ZeroBreach.Core/Model/Finding.cs`, `Severity.cs`, `FixAction.cs`, `CheckStatus.cs`
- `ZeroBreach.Core/Signatures/SignatureDb.cs`, `IndicatorEntry.cs`
- `ZeroBreach.Core/Profiles/UserProfile.cs`
- `ZeroBreach.Core/Util/FileHasher.cs`

## Hard rules (spec §6 — violations fail review)

1. **Scanners are read-only.** No file writes, deletes, kills, registry writes, service
   changes — nothing. You produce `Finding` objects; remediation is a different module.
2. **Never report clean when you didn't look.** Every failure mode — access denied, log
   source disabled, hive not mounted, budget exhausted, exception — must emit
   `sink.Inconclusive(...)` or `sink.Skipped(...)` with the scope in the detail. Wrap each
   independent check in its own try/catch; never let one crash kill your phase.
3. **Budgets are per-walk, per-profile** (`ctx.CreateBudget(...)` fresh for EACH profile you
   walk — never share one across profiles). End every budgeted walk with
   `sink.CompleteOrInconclusive(phase, check, budget, scope)`.
4. **Per-user checks iterate `ctx.Profiles`** — all of them. A profile with
   `OpenHiveRoot() == null` gets `sink.Skipped(phase, check, $"profile {p.UserName}: hive not
   mounted (run with --load-hives)")`. Filesystem locations under `p.ProfilePath` are
   walkable regardless of hive state.
5. **Severity discipline** (this feeds the auto-select gate, so err low):
   - `Critical` — hash-confirmed known-bad, or an unambiguous active compromise artifact.
   - `High` — high-confidence suspicious with corroboration (e.g. unsigned exe in a Run key
     pointing into %TEMP%; encoded-command persistence).
   - `Possible` — plausible but needs operator judgment; DEFAULT for single-indicator hits,
     for anything matched from `custom.*` IOC sets, and for all dual-use tooling
     (tunneling tools, RMM, nmap-class utilities: "flag but don't auto-act").
   - `Info` — context, hardening gaps, and every "run this command by hand" suggestion.
   - An indicator whose `NeedsCorroboration` is true can NEVER alone justify above Possible.
6. **FixAction discipline**:
   - `DeleteFile` only with `HashConfirmed = true` (SHA-256 matched a known-bad set);
     otherwise suggest `Quarantine`.
   - `KillProcess` → `FixParam = "<pid>:<processName>"`.
   - `DeleteRegistryValue` → `FixParam = @"HIVE\Key\Path::ValueName"` (HKLM/HKU form; for a
     per-user value in a mounted hive use `HKU\<HiveKeyName>\...`).
   - `RunCommand` is DISPLAY-ONLY (the engine refuses to execute it) — use it for things
     like "vssadmin list shadows" guidance, always with `Severity.Info`. Never emit a
     finding whose fix would delete shadow copies or similar irreversible ops.
   - When in doubt: `FixAction.None`. A finding without a fix is fine; a wrong fix is not.
7. **Finding IDs**: `Finding.ComputeId(group, target, discriminator)`. The discriminator
   must make the identity REAL and UNIQUE: include the profile SID for per-user artifacts,
   the value name for registry hits, the rule/set entry for signature hits. Two different
   users' identical artifacts must produce two findings (the original project had a bug
   collapsing them — don't reintroduce it).
8. **Time window**: where you iterate artifacts with timestamps, honor
   `ctx.WithinTimeWindow(utc)` — skip items outside it (persistence/config state checks that
   aren't timestamped ignore the filter).
9. **Vendor trust**: when path/name/signer matches `ctx.Signatures.IsVendorTrusted(...)`,
   set `VendorTrusted = true` on the finding. Badge only — never skip or downgrade to Info
   because of it.
10. **Signatures external**: NO indicator strings/paths-of-badness inline in C# beyond
    structural constants (registry locations you enumerate are fine). Pattern lists, known
    names, hashes, family strings go in your category's
    `ZeroBreach.Scanners/Signatures/<category>.json` (embedded automatically), read via
    `ctx.Signatures.Set("<category>.<set_name>")`. JSON shape:

    ```json
    {
      "sets": {
        "persistence.startup_suspect_ext": [
          { "pattern": "*.vbs", "kind": "glob", "severity": "high",
            "technique": "T1547.001", "techniqueName": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence", "note": "script in startup folder" }
        ]
      }
    }
    ```
    `kind`: `literal` (exact; add `"substring": true` for contains), `glob`, `regex`,
    `sha256`. `severity`: `info|possible|high|critical`. Content-string indicators that
    could hit documentation/research must carry `"needsCorroboration": true`.
11. **MITRE**: map each check via `new MitreRef("T....", "name", "tactic")` or the
    indicator's `.Mitre`.
12. **Custom IOCs**: check the relevant `custom.hashes` / `custom.ips` / `custom.domains` /
    `custom.filenames` sets where they apply to your category; hits are `Possible`,
    `FixAction.None` (or `Quarantine` for a file hit at most), never Delete/Kill.
13. **Depth gating**: your phase has a `MinDepth`; additionally gate expensive sub-checks
    with `if (ctx.Depth >= ScanDepth.Deep)` etc. QUICK must stay fast: registry reads and
    small fixed file sets only. Use `ctx.Cancel.ThrowIfCancellationRequested()` inside long
    loops (PhaseRunner handles it).
14. **Event Log access**: `System.Diagnostics.Eventing.Reader.EventLogReader`. A channel
    that is disabled/unreadable → `Inconclusive`, mentioning the channel. Distinguish
    "log empty/no matches" (Completed) from "log unreadable" (Inconclusive).
15. **Distinguish "unsigned" from "signature could not be checked"** in descriptions when
    you use Authenticode state as evidence (WinVerifyTrust or
    `System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile` —
    catch and report the difference).

## Class shape

```csharp
namespace ZeroBreach.Scanners;

public sealed class <Name>Scanner : IScanner
{
    public int Phase => <N>;
    public string Name => "<Banner Name>";
    public string Group => "<Group>";
    public ScanDepth MinDepth => ScanDepth.<X>;

    public void Run(ScanContext ctx, IFindingSink sink)
    {
        Check1(ctx, sink);   // each check: own try/catch → Inconclusive on crash
        Check2(ctx, sink);
        ...
    }
}
```

One file: `ZeroBreach.Scanners/<Name>Scanner.cs` (helpers as private methods or a nested
static class in the same file). Signature data:
`ZeroBreach.Scanners/Signatures/<category>.json`. A detection change should not need to touch
another category's files, and must never need to touch `ZeroBreach.Remediation`.

## Definition of done

- `dotnet build` succeeds with zero new warnings, and `dotnet test` stays green —
  including `ScannerReadOnlyAuditTests`, which fails if a scanner gains a destructive call.
- Every check path ends in exactly one of: findings + Completed, Inconclusive, or Skipped.
- New or changed checks are reflected in the `INSTRUCTIONS_AI.md` §5 catalog, and a new
  category is added to the list in `CliOptions.Usage` (`zbscan categories` reads the live
  scanner list, so it needs no edit).
