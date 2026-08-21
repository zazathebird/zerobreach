# F2 — Phases 148-152: lateral movement, AD, credential dumping

**Priority 2.** `ADVERSARY_ANALYSIS.md` §B4. Size: L. Five phases.

This matters more than usual for this project: the tool is being validated on a **private lab
network of deliberately infected peers**, so lateral-movement evidence is the thing the test rig
is actually built to produce.

Present today: phase 66 (share worm), 88 (domain trust), 76/77 (RDP/WinRM status). Missing:
everything about what was *done to* this host from the network, and what this host can be used to
do to the rest of it.

---

## Phase 148 — Remote execution evidence (inbound lateral)

- **PsExec-class service install/remove.** System log **7045** (service installed) where the
  service was removed again within minutes, or an image path under `ADMIN$` / `\\127.0.0.1\`.
  `PSEXESVC` is the classic name but every framework renames it — detect the *pattern*
  (short-lived service, binary in a share path, random 8-char name), not the name.
- **WMI remote exec.** A process whose parent is `WmiPrvSE.exe` and which is a shell or script
  host. Use `Get-ProcSnapshot`, and remember phase 136 exists to tell you whether the recorded
  parent is trustworthy.
- **WinRM remote exec.** Children of `wsmprovhost.exe`.
- **DCOM lateral.** `mmc.exe`/`excel.exe` spawning a shell; `ShellWindows`/`MMC20.Application`
  in a command line.
- **Scheduled-task-at-a-distance.** Task created with a `\\server\` action or by a remote user.

Use `Get-WinEventSafe` — never raw `Get-WinEvent -FilterHashtable`, which throws a terminating
error that `-EA SilentlyContinue` does not suppress.

## Phase 149 — Credential dumping artifacts

- **Any `.dmp` whose name or path references lsass**, anywhere, plus any `.dmp` over ~20 MB in a
  user-writable directory.
- **`comsvcs.dll MiniDump`** in a command line or in execution evidence. This is the
  no-tools-required lsass dump and it is extremely common.
- **Hive copies**: `SAM`, `SYSTEM`, `SECURITY`, `ntds.dit` found anywhere outside
  `%WINDIR%\System32\config` and `%WINDIR%\NTDS`.
- **VSS created and deleted inside the same window** — the standard way to copy a locked
  `ntds.dit` or SAM. Correlate `vssadmin`/`wmic shadowcopy` command lines with event 8222.
- **`reg save hklm\sam`** style command lines.
- **Registry**: `DisableRestrictedAdmin`, `UseLogonCredential=1` under WDigest (forces plaintext
  credentials back into memory — phase 41 checks LSA generally; this is the specific attacker
  write and it deserves its own finding).

## Phase 150 — Kerberos & NTLM abuse

Readable from a domain-joined workstation with no special rights:

- **`klist` anomalies**: a TGT with a lifetime measured in years (golden ticket), a service ticket
  with an encryption type of RC4 (`0x17`) on a domain that has moved to AES (Kerberoasting), or a
  ticket for a service the machine has no reason to hold.
- **AS-REP roastable accounts** — `DONT_REQ_PREAUTH` in `userAccountControl`.
- **Unconstrained delegation** on any computer object, **RBCD**
  (`msDS-AllowedToActOnBehalfOfOtherIdentity` populated), and `AdminSDHolder` drift.
- **ADCS misconfiguration** (ESC1/ESC8): templates allowing requester-supplied SAN, or an
  enrolment endpoint reachable over HTTP.
- **NTLM relay exposure**: SMB signing not required, and the **WebClient service running on a
  workstation** — that is the WebDAV coercion primitive and it has essentially no desktop use.

All of this is **read-only LDAP/`klist`** and must degrade silently and completely on a
non-domain-joined machine. Guard every branch with a domain-membership check first.

## Phase 151 — Outbound lateral capability

What patient zero can reach: cached RDP connections (`Terminal Server Client\Servers`), saved
credentials (`cmdkey /list`), mapped drives and their persistence, PowerShell remoting trust
(`TrustedHosts` = `*` is a finding), and stored session managers (PuTTY/WinSCP/mRemoteNG profiles
with saved passwords).

## Phase 152 — Session & logon anomalies

Event **4624** type 3 (network) and type 10 (RemoteInteractive) from unexpected sources; logons
outside business hours; a local account used across the network (the classic pass-the-hash
signature — local accounts do not normally authenticate to other machines); **4625** spray
patterns (many accounts, one source, short window); **4720/4732** (account created, added to
Administrators) correlated with a recent logon.

## Deliverables

- Phases 148-152 in `engine/Phases-6.ps1`.
- Signature keys for every list, including the benign-service-name allowlists that will otherwise
  make 148 unusable on an RMM-managed fleet — **remember Datto/CentraStage/Kaseya are legitimate
  partner tooling** (CLAUDE.md rule #2) and they install and remove services constantly.
- Tests, including a proof that every branch is skipped cleanly on a non-domain-joined host.
