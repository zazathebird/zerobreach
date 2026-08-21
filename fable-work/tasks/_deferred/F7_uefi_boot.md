# F7 — Phase 159: UEFI / ESP integrity

**Priority 7.** `ADVERSARY_ANALYSIS.md` §B8. Size: S.

Phase 58 covers MBR; phase 80 covers Secure Boot / TPM *status*. Nothing looks at the EFI System
Partition, which is where a modern bootkit lives.

## Detect

- **Mount the ESP read-only** (`mountvol` to a free letter, or the `\\?\GLOBALROOT` path) and
  inventory `\EFI\`. Anything outside `\EFI\Microsoft\`, `\EFI\Boot\` and the OEM vendor directory
  is a finding. Unmount in a `finally` — **leave nothing behind on a client machine** is a
  standing rule here (audit M5/M9/M10).
- **Hash `bootmgfw.efi`, `bootmgr.efi`, `winload.efi`** and compare against the copies in
  `%WINDIR%\Boot\EFI\`. A mismatch between the ESP copy and the servicing copy is the signal.
- **Secure Boot `dbx` currency.** BlackLotus depends on an un-updated revocation list. Read the
  `dbx` UEFI variable, compare its size/timestamp against the known-current baseline shipped in
  the signature DB, and report an out-of-date `dbx` as a real, actionable finding —
  `Get-SecureBootUEFI dbx`.
- **Secure Boot disabled while BitLocker is on** — a specific and meaningful combination.
- **`bcdedit` flags**: `testsigning`, `nointegritychecks`, `disableelamdrivers`,
  `flightsigning`. Phase 40 touches the BCD store; make sure you are not duplicating it —
  read phase 40 first and only add what is missing.

## Notes

- All of this needs elevation, which the engine already has, and **all of it must degrade
  silently on a legacy BIOS/MBR machine.** Check firmware type first
  (`$env:firmware_type`, or `Confirm-SecureBootUEFI` throwing) and skip the whole phase cleanly.
- `Confirm-SecureBootUEFI` **throws** on a non-UEFI machine rather than returning false. Wrap it.
- Everything here is `FixAction "Info"`. There is no safe automated remediation for a boot chain,
  and getting it wrong bricks the machine.

## Deliverables

Phase 159, keys (`esp_expected_paths`, `dbx_current_baseline`, `bcd_unsafe_flags`), tests
including a proof of clean skip on non-UEFI.
