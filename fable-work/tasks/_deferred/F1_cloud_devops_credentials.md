# F1 — Phase 147: cloud identity & DevOps credential theft

**Priority 1.** `ADVERSARY_ANALYSIS.md` §B3. Size: M.

## Why this is first

I grepped the whole tree. `.aws`, `.azure`, kubeconfig, `.ssh`, `.git-credentials`, `.npmrc`,
`.docker/config.json` appear **nowhere** in the signature DB or in 133 phases of engine. Coverage
stops at browser password stores, FileZilla, WinSCP and PuTTY — a 2015 threat model.

On a managed endpoint in 2026 the crown jewels are not the local SAM. For an MSP this is
existential: one stolen `.azure` token cache on one technician's laptop is every client tenant,
and it survives a password reset because the token is the credential.

## What to detect

Two questions, and **both matter**:

1. **Do these secrets exist on this box, unprotected?** (exposure — INFO/POSSIBLE)
2. **Has anything read or copied them?** (theft in progress — HIGH)

### Target inventory

Put the paths in `cloud_cred_paths_raw` as `$env:`-prefixed strings.

| Family | Paths |
|---|---|
| AWS | `$env:USERPROFILE\.aws\credentials`, `\.aws\config` |
| Azure CLI | `$env:USERPROFILE\.azure\msal_token_cache.bin`, `accessTokens.json`, `azureProfile.json` |
| Entra / PRT | `$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache`, `$env:APPDATA\Microsoft\Windows\SystemCertificates\Ngc` (existence + ACL only — never read) |
| GCP | `$env:APPDATA\gcloud\credentials.db`, `access_tokens.db`, `application_default_credentials.json` |
| Kubernetes | `$env:USERPROFILE\.kube\config` |
| Docker | `$env:USERPROFILE\.docker\config.json` |
| SSH | `$env:USERPROFILE\.ssh\id_rsa`, `id_ed25519`, `id_ecdsa`, `known_hosts` |
| Git | `$env:USERPROFILE\.git-credentials`, `$env:USERPROFILE\.gitconfig` |
| Package registries | `$env:USERPROFILE\.npmrc`, `.pypirc`, `$env:APPDATA\NuGet\NuGet.Config` |
| Generic | `$env:USERPROFILE\.netrc`, `_netrc` |
| Terraform | `$env:APPDATA\terraform.d\credentials.tfrc.json`, plus `*.tfstate` in user dirs |
| DPAPI | `$env:APPDATA\Microsoft\Protect\<SID>\` (**existence and ACL only**) |
| Credential Manager | `$env:APPDATA\Microsoft\Credentials\`, `$env:LOCALAPPDATA\Microsoft\Credentials\` |

### Detection logic, in order of value

**(a) Plaintext secret material — HIGH.** For the *text* formats only (`.aws/credentials`,
`.npmrc`, `.git-credentials`, `.netrc`, `.pypirc`, `.tfstate`, `kube/config`, `docker/config.json`)
read the file and match against **content rules** in the signature DB — an AWS access key ID
shape, a bearer/PAT shape, a `password=` or `_authToken=` assignment. Use the existing
`Test-ContentRules` helper; do **not** write the matched secret into the finding description.

> Put the **shape** in the DB, never a real key. `AKIA[0-9A-Z]{16}` is a format, not a secret.
> Cap the read (these are small files; refuse anything over ~1 MB) and skip binaries.

**(b) World-readable secrets — POSSIBLE.** `Get-WeakAces` (already in the loader) against each
existing target. A `.ssh\id_rsa` readable by `Users` or `Everyone` is a real finding on its own.

**(c) Staged for exfiltration — HIGH.** A **copy** of any of these outside its normal home:
`credentials`, `id_rsa`, `msal_token_cache.bin`, `config.json` found under `Temp`, `Downloads`,
`Public`, `ProgramData`, or inside an archive. Scope with `Get-ScanFiles` over the usual roots —
never a raw `Get-ChildItem -Recurse`.

**(d) Access evidence — HIGH.** Cross-reference the process command lines from `Get-ProcSnapshot`
for reads of these paths, and check phase-123-style execution evidence for tools whose only job is
this: `az account get-access-token`, `aws sts`, `kubectl config view --raw`, `SharpCloud`,
`TokenTactics`, `ROADtools`, `AADInternals`, `Get-AzAccessToken`.

## False positives you must handle

- A developer workstation legitimately has all of these. **Existence alone is INFO, not a threat.**
  Severity comes from *plaintext secret* + *weak ACL* + *copy in a staging directory*.
- `node_modules`, `site-packages`, `.git` and vendored SDK trees contain example and test
  credential files by the thousand. Allowlist by **path component**.
- CI agents and Terraform runners legitimately write `.tfstate` with secrets in it. Flag as
  exposure, describe the fix (remote state + encryption), do not call it malware.

## Deliverables

- Phase 147 in `engine/Phases-6.ps1`.
- Keys: `cloud_cred_paths_raw`, `cloud_cred_content_rules`, `cloud_cred_staging_dirs`,
  `cloud_cred_access_tools`, allowlist `cloud_cred_benign_paths`.
- Tests: every path expands; every content rule compiles and survives backtracking bait under a
  150 ms timeout; the allowlist does not swallow the staging-directory branch (an allowlist that
  makes its own detection branch unreachable has shipped here before — phase 130's `discord`
  entry killed its own client-core branch).
