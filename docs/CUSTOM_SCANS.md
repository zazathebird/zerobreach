# Custom scans

Beyond the QUICK / FULL / DEEP / STEALTH presets, the engine supports operator-defined
custom scans: pick categories inline, or save the whole definition as a reusable profile.

## Inline category selection

```
scythescan --mode FULL --only Persistence,C2,Ransomware
scythescan --mode DEEP --skip EventLog,ContentScan
```

Valid categories (scanner group names): `Persistence`, `DefenseEvasion`, `C2`,
`CredentialAccess`, `Ransomware`, `EmailResidue`, `RootkitBoot`, `AclIntegrity`,
`ContentScan`, `EventLog`. Names are case-insensitive and validated — a typo is a hard
error, never a silently different scan. `--only` and `--skip` cannot be combined.

Excluded phases appear in the report and end-of-run summary as **skipped / unchecked**
(spec §6.7): a narrowed scan is never mistakable for a full one, and a run that found
nothing but excluded categories exits 3 ("coverage gaps"), not 0 ("clean").

## Scan profiles

Save the current command line as a profile, then reuse it:

```
scythescan --mode FULL --since-hours 48 --only Persistence,C2 --ioc-file iocs.txt --save-profile dc-triage.json
scythescan --profile dc-triage.json
scythescan --profile dc-triage.json --mode DEEP     # typed flags override the profile
```

Profile shape (JSON; unknown properties are rejected so a misspelling can't silently
change scan scope):

```json
{
  "name": "dc-triage",
  "description": "48h triage for domain controllers",
  "mode": "FULL",
  "sinceHours": 48,
  "only": ["Persistence", "C2"],
  "iocFile": "iocs.txt",
  "rulesFile": "extra-rules.json",
  "html": true
}
```

`iocFile` / `rulesFile` relative paths resolve against the profile file's own directory,
so a profile can travel with its IOC list. `only`/`skip` are mutually exclusive.

## What a profile can never do

By design (spec §4/§6), a profile has no way to express:

- `--load-hives` — mounting logged-off users' registry hives is an explicit **per-run**
  opt-in, never something a config file switches on;
- `--interactive` and any remediation behavior — the §6 safety model (severity gate,
  protected targets, typed confirmation, action log) is untouched by profiles;
- baseline paths (`--baseline` / `--save-baseline`) — per-run decisions.

These stay command-line-only, and `--save-profile` never writes them into the file.
