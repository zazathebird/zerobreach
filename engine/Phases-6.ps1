# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

trap { Write-RecoveredError $_; continue }   # module-level resilience (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  HUNT BAND — PHASES 146-159
#
#  147 and 157-159 ARE BUILT (2026-08-30) — tasks F1, F4, F5 and F7:
#    147      cloud identity + DevOps credential theft             (task F1)
#    157      remaining persistence surface                        (task F4)
#    158      supply chain + developer tooling                     (task F5)
#    159      UEFI / ESP integrity                                 (task F7)
#
#  Still a parallel work package (see fable-work/tasks/_deferred/):
#    146      PE structural analysis + rule engine                 (task F3)
#    148-152  lateral movement, AD, credential dumping             (task F2)
#
#  Phase 159 narrows its brief the same way 153-156 narrowed F6, and for the same
#  reason: it DOES NOT MOUNT the EFI System Partition and no switch is provided to
#  make it. The full reasoning is in the phase's own banner.
#
#  153-156 ARE BUILT (2026-08-22). They are the network-exposure band, and they are
#  HOST-SIDE ONLY: every check is a registry / WMI / CIM read of THIS machine's own
#  posture. They send no packets and they do not enumerate the LAN.
#
#  That is a deliberate narrowing of the original F6 scope ("LAN band, opt-in, requires
#  -ScanLan"). Reasons, recorded so nobody widens it back by accident:
#    * Scythe runs on client networks under an MSP contract. A tool that probes the
#      customer's LAN can trip the customer's own IDS and is indistinguishable, on the
#      wire, from the activity it exists to detect.
#    * Every finding below is answerable from the host's own configuration. Probing the
#      network adds no detection the registry cannot already supply.
#    * No -ScanLan switch is therefore needed and none is introduced; these run whenever
#      HUNT runs.
#
#  Band rule (CLAUDE.md): everything in 134-162 is FixAction "Info". Severity may still
#  be HIGH — HIGH + Info is never auto-selected, because auto-select requires a
#  DESTRUCTIVE FixAction. Several of these settings brick file sharing or logon if
#  written blind, so the remediation is operator-run and the exact command is in the
#  finding description.
# ══════════════════════════════════════════════════════════════════════════════
# ── Helpers for phases 147/157/158/159 ───────────────────────────────────────
# Defined unconditionally, before the $PhasePlan gate, so the AST tests can find them
# whatever mode the engine is in — same convention as the rest of the band.

function Test-ScytheNameRule {
    # True when $Name matches ANY regex in $Rules. Every match runs under the same 150 ms
    # budget Join-AllowRegex uses: these patterns come from data/detection_signatures.json
    # and are applied to attacker-authored text (file names, command lines, ESP paths), so
    # a catastrophic-backtracking pattern edited into the DB would otherwise be a denial of
    # service on the scan itself. A pattern that will not compile is skipped, not fatal.
    param([string]$Name, $Rules)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    foreach ($r in @($Rules)) {
        if ([string]::IsNullOrWhiteSpace("$r")) { continue }
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex("$r",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [TimeSpan]::FromMilliseconds(150))
            if ($rx.IsMatch($Name)) { return $true }
        } catch { continue }
    }
    return $false
}

function Test-ScytheTextRules {
    # Test-ContentRules reads a FILE. These phases also need the same {Name,Pattern,Severity}
    # rule shape applied to text that never touches disk — a registry value, bcdedit output,
    # a process command line, a package.json already in memory. Returns the highest-severity
    # matching rule, or $null. Same per-pattern 150 ms budget and the same fail-soft skip.
    param([string]$Text, $Rules)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $ruleRank = @{ "CRITICAL" = 3; "HIGH" = 2; "POSSIBLE" = 1 }
    $bestRule = $null
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        if ([string]::IsNullOrWhiteSpace("$($r.Pattern)")) { continue }
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex("$($r.Pattern)",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [TimeSpan]::FromMilliseconds(150))
            if (-not $rx.IsMatch($Text)) { continue }
        } catch { continue }
        if ($null -eq $bestRule -or [int]$ruleRank["$($r.Severity)"] -gt [int]$ruleRank["$($bestRule.Severity)"]) {
            $bestRule = $r
        }
    }
    return $bestRule
}

function Resolve-ScytheModulePath {
    # Registry persistence values name their module in every shape Windows accepts: quoted,
    # bare, %SystemRoot%-relative, with an export or ordinal after a comma, or a leaf name
    # that only resolves against System32. Normalise to a full path. Uses $global:SCYTHE_SYS32
    # rather than the literal System32 path, because a 32-bit engine is redirected to
    # SysWOW64 and would verify the wrong copy of the DLL (CLAUDE.md WOW64 rule).
    param([string]$Value)
    $v = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return "" }
    $v = $v.Trim('"').Trim()
    # rundll32-style "path,Export" / "path,#1" — keep the path half only.
    if ($v -match '^(?<p>[^,]+),[^\\/]*$') { $v = "$($Matches['p'])".Trim().Trim('"') }
    try { $v = [System.Environment]::ExpandEnvironmentVariables($v) } catch { }
    if ($v -match '^[A-Za-z]:[\\/]' -or $v -match '^\\\\') { return $v }
    if ([string]::IsNullOrWhiteSpace($global:SCYTHE_SYS32)) { return $v }
    return (Join-Path $global:SCYTHE_SYS32 $v)
}

function Test-ScytheUntrustedModule {
    # True when the module at $Path is missing, unresolvable, or not validly signed.
    # The MECHANISM existing is usually normal — Windows and several vendors register
    # netsh helpers, print monitors, time providers and LSPs legitimately. What makes one
    # a finding is the module behind it, so the signature verdict carries the weight here
    # and the path allowlist is kept deliberately small.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    if ($Path -match $PERSIST_DLL_BENIGN_RE) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    $verdict = Get-SignatureVerdict $Path
    if ("$($verdict.Status)" -eq 'Valid') { return $false }
    return $true
}

function Get-ScytheRepoRoots {
    # Local repository roots, found from a FIXED SHALLOW list of the directories developers
    # actually keep code in, two levels deep, with no -Recurse anywhere. Deliberately not a
    # profile walk: a developer's profile holds hundreds of thousands of files under
    # node_modules and .venv, walking it blows the phase's wall-clock budget, and it finds
    # nothing the targeted roots do not. Capped so a machine with a very large number of
    # clones cannot stall the phase.
    $names = @('source','source\repos','repos','git','Projects','projects','dev','src','code','work','Documents','Desktop','Downloads')
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($n in $names) {
        if ($found.Count -ge 60) { break }
        $base = Join-Path $env:USERPROFILE $n
        if (-not (Test-Path -LiteralPath $base)) { continue }
        if (Test-Path -LiteralPath (Join-Path $base '.git')) { $found.Add($base) }
        $level1 = @()
        try { $level1 = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop) } catch { $level1 = @() }
        foreach ($d1 in $level1) {
            if ($found.Count -ge 60) { break }
            $p1 = "$($d1.FullName)"
            if ($p1 -match $DEVTOOL_BENIGN_RE) { continue }
            if (Test-Path -LiteralPath (Join-Path $p1 '.git')) { $found.Add($p1); continue }
            $level2 = @()
            try { $level2 = @(Get-ChildItem -LiteralPath $p1 -Directory -ErrorAction Stop) } catch { $level2 = @() }
            foreach ($d2 in $level2) {
                if ($found.Count -ge 60) { break }
                $p2 = "$($d2.FullName)"
                if ($p2 -match $DEVTOOL_BENIGN_RE) { continue }
                if (Test-Path -LiteralPath (Join-Path $p2 '.git')) { $found.Add($p2) }
            }
        }
    }
    return ,($found.ToArray())
}

function Get-ScytheEspRoot {
    # An ALREADY-REACHABLE path to the EFI System Partition, or '' if it has none.
    # This function deliberately mounts NOTHING. Assigning a system partition an access
    # path is a live change to a client machine's boot volume state, and "leave nothing
    # behind" is a standing rule for this product (audit M5/M9/M10). If the operator has
    # mounted the ESP themselves, the phase uses it; otherwise it reports that the
    # contents were not inventoried and hands over the exact commands.
    $accessPaths = @()
    try {
        foreach ($part in @(Get-Partition -ErrorAction Stop)) {
            if ("$($part.GptType)" -ne '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}') { continue }
            foreach ($ap in @($part.AccessPaths)) { if ("$ap") { $accessPaths += "$ap" } }
        }
    } catch { return "" }
    # Prefer a drive letter or a mounted folder; a raw \\?\Volume{...} GUID path is not
    # reachable through the FileSystem provider on every build, so it is only a fallback.
    foreach ($ap in $accessPaths) {
        if ($ap -notmatch '^[A-Za-z]:') { continue }
        if (Test-Path -LiteralPath $ap) { return $ap }
    }
    foreach ($ap in $accessPaths) {
        $ok = $false
        try { $ok = [bool](Test-Path -LiteralPath $ap -ErrorAction Stop) } catch { $ok = $false }
        if ($ok) { return $ap }
    }
    return ""
}

if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group

    # ── PHASE 147: CLOUD IDENTITY AND DEVOPS CREDENTIAL EXPOSURE ──────────────
    # Coverage before this phase stopped at browser password stores, FileZilla, WinSCP
    # and PuTTY — a 2015 threat model. On a managed endpoint the crown jewels are cloud
    # tokens: one stolen .azure token cache on one technician's laptop is every client
    # tenant, and it survives a password reset, because the token IS the credential.
    #
    # Two questions, and both matter: do these secrets exist here unprotected, and has
    # anything read or copied them. Existence alone is INFO — a developer workstation
    # legitimately has every one of these files. Severity comes from plaintext secret
    # material, a weak ACL, or a COPY sitting in a staging directory.
    Show-PhaseHeader "PHASE 147" "CLOUD TOKEN CACHES, SSH KEYS AND DEVOPS CREDENTIALS" "CREDENTIAL ACCESS"
    Out-Typewriter "INVENTORYING CLOUD AND DEVOPS CREDENTIAL MATERIAL..." "HUNT"

    $credPresent = New-Object System.Collections.Generic.List[string]
    foreach ($cp in $CLOUD_CRED_PATHS) {
        if ([string]::IsNullOrWhiteSpace($cp)) { continue }
        if ($cp -match $CLOUD_CRED_BENIGN_RE) { continue }
        if (-not (Test-Path -LiteralPath $cp)) { continue }
        $credPresent.Add($cp)
    }

    if ($credPresent.Count -eq 0) {
        Out-Typewriter "  -> NO CLOUD OR DEVOPS CREDENTIAL STORES FOUND." "OK"
    } else {
        Out-Typewriter "  -> $($credPresent.Count) CREDENTIAL STORE(S) PRESENT ON THIS HOST." "INFO"
        $credList = (@($credPresent) | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique) -join ', '
        Add-Finding -ID "CLOUD147_INVENTORY" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "This host holds $($credPresent.Count) cloud or DevOps credential store(s): $credList. This is INVENTORY, not a defect — a developer or technician workstation legitimately has all of these, and the finding exists so that an operator responding to a compromise on this machine knows immediately which tenants, registries and repositories to treat as exposed. If this box is confirmed compromised, the correct response is to rotate rather than to delete: revoke the Azure/Entra refresh tokens (Revoke-AzureADUserAllRefreshToken or the equivalent Graph call), rotate the AWS access keys, regenerate the SSH keys and any package-registry tokens, and force a re-login of every CLI listed. A password reset alone does NOT invalidate a stolen token cache. The checks below look for the three things that turn this inventory into a finding: plaintext secret material, a permissive ACL, and a copy staged somewhere it does not belong." `
            -Target "CloudCredentialInventory" -FixAction "Info" -Group "Credential Exposure"
    }

    # (a) Plaintext secret material. Text formats only, and never the opaque token
    #     caches — reading a TokenBroker cache or an NGC key container makes this tool
    #     the credential-theft primitive it is looking for, and can invalidate the
    #     user's live session as a side effect.
    foreach ($cp in $credPresent) {
        if (Test-ScytheNameRule -Name $cp -Rules $CLOUD_CRED_NEVER_READ) { continue }
        $leaf = Split-Path $cp -Leaf
        if (-not (Test-ScytheNameRule -Name $leaf -Rules $CLOUD_CRED_TEXT_FORMATS)) { continue }
        $hit = Test-ContentRules -FilePath $cp -Rules $CLOUD_CRED_CONTENT_RULES -MaxBytes 1048576
        if (-not $hit.Hit) { continue }
        $credSev = if ("$($hit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
        Out-Typewriter "  -> PLAINTEXT SECRET MATERIAL IN: $cp ($($hit.Name))" "CRIT"
        Add-Finding -ID "CLOUD147_PLAIN_$([Math]::Abs($cp.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $credSev `
            -Description "'$cp' contains material matching the secret format '$($hit.Name)'. The matched text is deliberately NOT reproduced here — a finding that quotes the credential turns the client report into a second copy of it. What this means: the secret is on disk in plaintext, so anything running as this user reads it without a prompt, without touching LSASS, and without tripping a credential-access detection. Read the file yourself to confirm before acting. The honest false-positive cases: a placeholder or example value, a revoked key left in a config, and — for the PrivateKeyBlock rule — an ordinary passphrase-protected SSH key, which is exactly where a private key is supposed to be and is not a finding on its own. If it is live, rotate it at the provider rather than merely deleting the file, and move the secret to the platform's own store (aws configure sso, az login, git config --global credential.helper manager, npm login --auth-type=web)." `
            -Target $cp -FixAction "Info" -Group "Credential Exposure"
    }

    # (b) World-readable secrets. READ is the right-that-matters here, not write —
    #     the attacker does not need to modify an SSH key to use it.
    foreach ($cp in $credPresent) {
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $cp -ErrorAction Stop } catch { $acl = $null }
        if ($null -eq $acl) { continue }
        $weak = @(Get-WeakAces -Acl $acl -WeakIds @('Everyone','BUILTIN\Users','Authenticated Users','NT AUTHORITY\ANONYMOUS LOGON','Guests') -RightsRegex 'Read|Modify|FullControl')
        if ($weak.Count -eq 0) { continue }
        $who = (@($weak) | ForEach-Object { "$($_.IdentityReference)" } | Sort-Object -Unique) -join ', '
        Out-Typewriter "  -> CREDENTIAL STORE READABLE BY $who : $cp" "WARN"
        Add-Finding -ID "CLOUD147_ACL_$([Math]::Abs($cp.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_POSSIBLE `
            -Description "'$cp' grants read access to: $who. Credential material in a user profile should be readable by that user and administrators only. A broad ACE here means any other local account — including a low-privilege service account, or a second user on a shared technician machine — can take the credential without any privilege escalation at all. Benign causes are common and worth checking first: a file copied from another machine or an archive carries the source ACL, and a profile relocated between disks can inherit the destination's permissions. Inspect with: Get-Acl '$cp' | Format-List. Tighten with: icacls '$cp' /inheritance:r /grant:r <owner>:(R,W) /grant:r Administrators:(F) /grant:r SYSTEM:(F)   — replacing <owner> with the account that owns the profile, not necessarily the account running this scan — and rotate the secret, because you cannot know whether it was already read." `
            -Target $cp -FixAction "Info" -Group "Credential Exposure"
    }

    # (c) Staged for exfiltration. No cloud CLI ever writes its token cache to Downloads.
    #     This is the branch that turns "a developer box has secrets" into "someone
    #     staged the secrets for collection", so the allowlist must never cover a
    #     staging directory (see the _comment on cloud_cred_benign_paths).
    $stagingRoots = @(@($CLOUD_CRED_STAGING_DIRS) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($stagingRoots.Count -gt 0) {
        $stagedFiles = @(Get-ScanFiles -Path $stagingRoots -MaxFiles 8000 -DeadlineSecs 15)
        foreach ($sf in $stagedFiles) {
            $sfPath = "$($sf.FullName)"
            if ($sfPath -match $CLOUD_CRED_BENIGN_RE) { continue }
            if (-not (Test-ScytheNameRule -Name "$($sf.Name)" -Rules $CLOUD_CRED_STAGED_NAMES)) { continue }
            Out-Typewriter "  -> CREDENTIAL MATERIAL STAGED OUTSIDE ITS HOME: $sfPath" "CRIT"
            Add-Finding -ID "CLOUD147_STAGED_$([Math]::Abs($sfPath.ToLower().GetHashCode()))" -Phase "PHASE 147" `
                -ThreatType "Collection / Exfiltration" -Severity $SEV_HIGH `
                -Description "'$sfPath' is a file named like cloud or DevOps credential material, sitting in a staging directory rather than in the location its own tool uses. No cloud CLI writes its credential store to Temp, Downloads, Desktop, Public or ProgramData — the AWS CLI writes to .aws, the Azure CLI to .azure, git to .git-credentials. A copy here was made by something else, and collection-into-a-staging-directory immediately before archive-and-upload is the standard shape of the exfiltration step (MITRE T1074.001, T1552.001). Check who made it and when: Get-Item '$sfPath' | Format-List CreationTime, LastWriteTime, Length. The benign cases are real and worth ruling out first — a technician manually backing up a config before a rebuild, a support bundle, or an unpacked archive. If it is not explained, treat the credentials named in the file as compromised and rotate them, then preserve the file as evidence before deleting it." `
                -Target $sfPath -FixAction "Info" -Group "Credential Exposure"
        }
    }

    # (d) Access evidence. az/aws/kubectl/gcloud are legitimate administration tools, so
    #     the rules anchor on the specific token-minting subcommand rather than the
    #     binary name; the named offensive tools are matched whole-word.
    $credProcs = @(Get-ProcSnapshot)
    foreach ($pr in $credProcs) {
        $cl = "$($pr.CommandLine)"
        if ([string]::IsNullOrWhiteSpace($cl)) { continue }
        if (-not (Test-ScytheNameRule -Name $cl -Rules $CLOUD_CRED_ACCESS_TOOLS)) { continue }
        $pname = "$($pr.Name)"; $ppid = "$($pr.ProcessId)"
        Out-Typewriter "  -> TOKEN-EXTRACTION COMMAND RUNNING: $pname (PID $ppid)" "CRIT"
        Add-Finding -ID "CLOUD147_ACCESS_$($ppid)_$([Math]::Abs($pname.ToLower().GetHashCode()))" -Phase "PHASE 147" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "Process '$pname' (PID $ppid) is running a command line that mints or lifts a cloud access token. The command line is recorded in the scan log rather than here, because it frequently contains the token or the tenant identifier. Why this matters: a token obtained this way is bearer credential — it works from anywhere, needs no password and no second factor, and stays valid until it expires or is explicitly revoked. Why it is very often benign: this is also exactly what a technician doing legitimate cloud administration runs, and what a CI agent or an infrastructure-as-code run does on every execution. The question to answer is WHOSE session it belongs to. Check the parent: Get-CimInstance Win32_Process -Filter 'ProcessId=$ppid' | Select-Object ParentProcessId, CommandLine, CreationDate   then confirm the user was at the keyboard. An interactive administration session is normal; the same command spawned from a browser, an Office application, a script host or a scheduled task is not." `
            -Target "PID:$ppid $pname" -FixAction "Info" -Group "Credential Exposure"
    }


    # ── PHASE 153: SMB SERVER + AUTHENTICATION POSTURE ────────────────────────
    Show-PhaseHeader "PHASE 153" "SMB SIGNING, GUEST AUTH AND NULL-SESSION POSTURE" "HARDENING"
    Out-Typewriter "READING THE HOST'S OWN SMB CONFIGURATION..." "HUNT"

    $srvParams = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wksParams = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $lsaKey    = 'SYSTEM\CurrentControlSet\Control\Lsa'

    # Server-side signing. "Enabled" is not "Required": a server that merely PERMITS
    # signing still completes an unsigned session when the client does not ask for it,
    # which is the precondition every relay technique depends on. Only Require closes it.
    $srvReq = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'RequireSecuritySignature'
    $srvEna = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'EnableSecuritySignature'
    if ($null -eq $srvReq -or [int]$srvReq -ne 1) {
        Out-Typewriter "  -> SMB SERVER SIGNING IS NOT REQUIRED." "CRIT"
        Add-Finding -ID "NET153_SRVSIGN" -Phase "PHASE 153" `
            -ThreatType "Credential Access / Relay" -Severity $SEV_HIGH `
            -Description "SMB server-side signing is not REQUIRED on this host (RequireSecuritySignature=$srvReq, EnableSecuritySignature=$srvEna). A server that only permits signing will still complete an unsigned session, and an unsigned SMB session can be relayed: an attacker who can coerce this machine — or any account on it — into authenticating elsewhere can forward that authentication to a third host and act as the user, without ever learning the password. Enabling signing is not sufficient; it must be required. Set it with: Set-SmbServerConfiguration -RequireSecuritySignature 1 -Force   (registry equivalent: HKLM\$srvParams\RequireSecuritySignature = 1). Set the client-side twin as well, under LanmanWorkstation. Expect a measurable throughput cost on large file transfers; that cost is the point of the control." `
            -Target "HKLM\$srvParams\RequireSecuritySignature" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> SMB SERVER SIGNING REQUIRED." "OK"
    }

    $wksReq = Get-RegVal64 -Hive LocalMachine -SubKey $wksParams -Name 'RequireSecuritySignature'
    if ($null -eq $wksReq -or [int]$wksReq -ne 1) {
        Add-Finding -ID "NET153_WKSSIGN" -Phase "PHASE 153" `
            -ThreatType "Credential Access / Relay" -Severity $SEV_INFO `
            -Description "SMB client-side signing is not required (RequireSecuritySignature=$wksReq under LanmanWorkstation). This governs sessions this machine INITIATES. Without it, a poisoned name-resolution response can steer this host to an attacker-controlled server and the resulting session can be relayed onward. Set with: Set-SmbClientConfiguration -RequireSecuritySignature 1 -Force" `
            -Target "HKLM\$wksParams\RequireSecuritySignature" -FixAction "Info" -Group "Network Exposure"
    }

    # Insecure guest logon. This is what allows an unauthenticated peer to bind as
    # 'guest' and enumerate shares; it also silently downgrades to an unsigned,
    # unauthenticated session, so anything read over it is tamperable in transit.
    $guestAuth = Get-RegVal64 -Hive LocalMachine -SubKey $wksParams -Name 'AllowInsecureGuestAuth'
    if ($null -ne $guestAuth -and [int]$guestAuth -eq 1) {
        Out-Typewriter "  -> INSECURE GUEST AUTH IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_GUESTAUTH" -Phase "PHASE 153" `
            -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
            -Description "AllowInsecureGuestAuth is enabled. Any host on the same network can open an SMB session to this machine as 'guest' with no credentials, enumerate the published share list, and read anything whose ACL grants Everyone or Guest. Guest sessions are additionally unsigned and unencrypted, so their contents can be modified in transit. Windows disables this by default; something set it. Disable with: Set-ItemProperty 'HKLM:\$wksParams' AllowInsecureGuestAuth 0   then confirm the Guest account itself is disabled (Get-LocalUser Guest)." `
            -Target "HKLM\$wksParams\AllowInsecureGuestAuth" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> INSECURE GUEST AUTH DISABLED." "OK"
    }

    # The local Guest account itself, independent of the SMB policy above.
    $guestOn = $null
    try {
        $gu = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        $guestOn = [bool]$gu.Enabled
    } catch { $guestOn = $null }
    if ($guestOn -eq $true) {
        Out-Typewriter "  -> LOCAL GUEST ACCOUNT IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_GUESTACCT" -Phase "PHASE 153" `
            -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
            -Description "The built-in Guest account is ENABLED. Windows ships it disabled. Enabled, it is an unauthenticated foothold for share access and, on some configurations, for interactive logon. Disable with: Disable-LocalUser -Name Guest   and verify no share ACL still references it (phase 154 lists those)." `
            -Target "LocalUser\Guest" -FixAction "Info" -Group "Network Exposure"
    } elseif ($guestOn -eq $false) {
        Out-Typewriter "  -> LOCAL GUEST ACCOUNT DISABLED." "OK"
    }

    # Null-session (fully anonymous) access.
    $nullSess = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'RestrictNullSessAccess'
    $restrAnon = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'RestrictAnonymous'
    $restrSam  = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'RestrictAnonymousSAM'
    if ($null -eq $nullSess -or [int]$nullSess -ne 1) {
        Add-Finding -ID "NET153_NULLSESS" -Phase "PHASE 153" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "RestrictNullSessAccess is not set to 1 (current: $nullSess). Anonymous sessions may reach the pipes and shares named in NullSessionPipes / NullSessionShares. Set: HKLM\$srvParams\RestrictNullSessAccess = 1, and empty the NullSessionPipes and NullSessionShares values unless a named application documents needing one." `
            -Target "HKLM\$srvParams\RestrictNullSessAccess" -FixAction "Info" -Group "Network Exposure"
    }
    if ($null -eq $restrSam -or [int]$restrSam -ne 1) {
        Add-Finding -ID "NET153_RESTRICTSAM" -Phase "PHASE 153" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "RestrictAnonymousSAM is not 1 (current: $restrSam; RestrictAnonymous=$restrAnon). This governs whether an anonymous session can enumerate local account NAMES — the first step of any password-guessing or spraying attempt, because it turns a blind guess into a target list. Set HKLM\$lsaKey\RestrictAnonymousSAM = 1." `
            -Target "HKLM\$lsaKey\RestrictAnonymousSAM" -FixAction "Info" -Group "Network Exposure"
    }

    # SMB1. Present-but-disabled is fine; present-and-enabled is not.
    $smb1 = $null
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
    if ($smb1 -eq $true) {
        Out-Typewriter "  -> SMB1 IS ENABLED." "CRIT"
        Add-Finding -ID "NET153_SMB1" -Phase "PHASE 153" `
            -ThreatType "Lateral Movement" -Severity $SEV_HIGH `
            -Description "SMB1 is enabled on this host. SMB1 cannot negotiate modern signing or encryption, is the transport several self-propagating families use to spread across a flat network, and has no remaining legitimate use outside specific legacy appliances. Disable with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart   then reboot. If a legacy device genuinely requires it, isolate that device instead of keeping SMB1 on general workstations." `
            -Target "SMB1Protocol" -FixAction "Info" -Group "Network Exposure"
    } elseif ($smb1 -eq $false) {
        Out-Typewriter "  -> SMB1 DISABLED." "OK"
    }

    # ── PHASE 154: SHARE INVENTORY AND SHARE-LEVEL ACL AUDIT ──────────────────
    Show-PhaseHeader "PHASE 154" "PUBLISHED SHARES AND THEIR ACCESS CONTROL" "HARDENING"
    Out-Typewriter "ENUMERATING PUBLISHED SHARES AND THEIR ACLS..." "HUNT"

    $shares = @()
    try { $shares = @(Get-SmbShare -ErrorAction Stop) } catch { $shares = @() }

    if ($shares.Count -eq 0) {
        Out-Typewriter "  -> SHARE ENUMERATION RETURNED NOTHING." "WARN"
        Add-Finding -ID "NET154_NOSHARES" -Phase "PHASE 154" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "Get-SmbShare returned no shares at all. Every Windows host normally publishes at least IPC$. Either the Server service is stopped (check: Get-Service LanmanServer) or the enumeration failed. Share posture could NOT be assessed this run." `
            -Target "Get-SmbShare" -FixAction "Info" -Group "Network Exposure"
    } else {
        # Anything that is not IPC$, ADMIN$ or a bare drive-letter admin share was
        # published deliberately and is the operator's responsibility to justify.
        $nonDefault = @($shares | Where-Object { $_.Name -notmatch '^(IPC\$|ADMIN\$|[A-Za-z]\$)$' })
        foreach ($sh in $nonDefault) {
            $shName = "$($sh.Name)"; $shPath = "$($sh.Path)"
            Out-Typewriter "  -> NON-DEFAULT SHARE: $shName -> $shPath" "WARN"
            Add-Finding -ID "NET154_SHARE_$([Math]::Abs($shName.ToLower().GetHashCode()))" -Phase "PHASE 154" `
                -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                -Description "The share '$shName' publishes '$shPath' over the network. This is not a default Windows share, so it was created deliberately — confirm it is still required. A share rooted at a user profile directory, a drive root, or a directory containing credentials, backups or configuration is a direct data-exposure path and, if writable, a route to plant a startup or shortcut file that executes when a user logs in. Review with: Get-SmbShareAccess -Name '$shName'   and remove with: Remove-SmbShare -Name '$shName'" `
                -Target "SmbShare\$shName" -FixAction "Info" -Group "Network Exposure"
        }
        if ($nonDefault.Count -eq 0) { Out-Typewriter "  -> NO NON-DEFAULT SHARES PUBLISHED." "OK" }

        # Share-level ACEs granting an anonymous or universal principal. This is the
        # ACL that actually decides whether the guest session of phase 153 can read.
        foreach ($sh in $shares) {
            $shName = "$($sh.Name)"
            if ($shName -match '^(IPC\$)$') { continue }
            $aces = @()
            try { $aces = @(Get-SmbShareAccess -Name $shName -ErrorAction Stop) } catch { continue }
            foreach ($ace in $aces) {
                $acct = "$($ace.AccountName)"
                if ($acct -notmatch '(^|\\)(Everyone|ANONYMOUS LOGON|Guest|Guests|NT AUTHORITY\\ANONYMOUS LOGON)$') { continue }
                if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
                Out-Typewriter "  -> SHARE '$shName' GRANTS $acct : $($ace.AccessRight)" "CRIT"
                Add-Finding -ID "NET154_ACE_$([Math]::Abs(($shName + $acct).ToLower().GetHashCode()))" -Phase "PHASE 154" `
                    -ThreatType "Initial Access / Exposure" -Severity $SEV_HIGH `
                    -Description "The share '$shName' grants '$acct' $($ace.AccessRight) at the SHARE level. Combined with an enabled Guest account or insecure guest logon (phase 153), this is readable — and at Change or Full, writable — by any unauthenticated host on the same network. Effective access is the MORE RESTRICTIVE of the share ACL and the NTFS ACL, so a tight NTFS ACL may still be holding the line; do not assume it is. Review: Get-SmbShareAccess -Name '$shName'   and tighten: Revoke-SmbShareAccess -Name '$shName' -AccountName '$acct' -Force" `
                    -Target "SmbShare\$shName ACE:$acct" -FixAction "Info" -Group "Network Exposure"
            }
        }

        # Administrative shares. Removing them breaks a great deal of legitimate
        # management tooling, so this is reported as posture, never as a defect.
        $autoWks = Get-RegVal64 -Hive LocalMachine -SubKey $srvParams -Name 'AutoShareWks'
        if ($null -eq $autoWks -or [int]$autoWks -ne 0) {
            Add-Finding -ID "NET154_ADMINSHARES" -Phase "PHASE 154" `
                -ThreatType "Lateral Movement" -Severity $SEV_INFO `
                -Description "Administrative shares (C\$, ADMIN\$) are enabled (AutoShareWks=$autoWks). This is the Windows default and a great deal of legitimate management and backup tooling depends on it, so it is reported as posture rather than as a fault. It is also the most-used lateral-movement path on a flat network: any credential with local administrator rights on this host can write to the whole system drive remotely. The meaningful mitigations are not removing the share but: unique local administrator passwords per host (LAPS), the local-account network-logon restriction (FilterAdministratorToken), and blocking inbound 445 from anything but management infrastructure. Disable only on a host you are certain nothing manages: HKLM\$srvParams\AutoShareWks = 0." `
                -Target "HKLM\$srvParams\AutoShareWks" -FixAction "Info" -Group "Network Exposure"
        }
    }

    # ── PHASE 155: NAME-RESOLUTION POISONING SURFACE ──────────────────────────
    Show-PhaseHeader "PHASE 155" "BROADCAST NAME RESOLUTION AND NTLM EXPOSURE" "HARDENING"
    Out-Typewriter "CHECKING THE PROTOCOLS THAT LEAK AUTHENTICATION..." "HUNT"

    # When DNS fails, Windows falls back to asking the whole local segment "who is X?".
    # Any host may answer. Answering falsely redirects the requester to the responder
    # and coerces it into authenticating there — which is why these three protocols are
    # the standard path onto a host whose inbound ports are entirely closed.
    $llmnr = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ($null -eq $llmnr -or [int]$llmnr -ne 0) {
        Out-Typewriter "  -> LLMNR IS NOT DISABLED." "CRIT"
        Add-Finding -ID "NET155_LLMNR" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "LLMNR is not disabled (EnableMulticast=$llmnr). When DNS resolution fails — a typo, a stale mapped drive, a decommissioned server name — this host broadcasts the name to the entire local segment and trusts whoever answers first. An attacker on the same segment answers every query, and the host then authenticates to them, handing over an NTLMv2 response that can be cracked offline or relayed onward immediately. This works against a host with every inbound port closed, because the host initiates it. Disable: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0 (Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution)." `
            -Target "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> LLMNR DISABLED." "OK"
    }

    # NBT-NS, per interface. Option 2 = disabled. Anything else leaks the hostname
    # pre-auth and is the second poisoning channel.
    $nbtBad = @()
    foreach ($ifc in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces')) {
        $opt = Get-RegVal64 -Hive LocalMachine -SubKey "SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$ifc" -Name 'NetbiosOptions'
        if ($null -ne $opt -and [int]$opt -ne 2) { $nbtBad += "$ifc(=$opt)" }
    }
    if ($nbtBad.Count -gt 0) {
        Out-Typewriter "  -> NetBIOS-over-TCP ENABLED ON $($nbtBad.Count) INTERFACE(S)." "CRIT"
        Add-Finding -ID "NET155_NBTNS" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "NetBIOS over TCP/IP is not disabled on: $($nbtBad -join ', ') (NetbiosOptions 2 = disabled). NBT-NS is the second broadcast name-resolution channel and is poisoned exactly as LLMNR is, with the same outcome — a coerced NTLM authentication to an attacker on the segment. It additionally discloses this machine's name to any unauthenticated peer that asks. Set NetbiosOptions = 2 on every interface under HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces, or via the adapter's IPv4 > Advanced > WINS tab." `
            -Target "NetBT\Parameters\Interfaces" -FixAction "Info" -Group "Network Exposure"
    } else {
        Out-Typewriter "  -> NetBIOS-over-TCP DISABLED ON ALL INTERFACES." "OK"
    }

    # mDNS — the third channel, and the one most often left on because it is newer
    # and is not covered by the classic LLMNR/NBT hardening guides.
    $mdns = Get-RegVal64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
    if ($null -eq $mdns -or [int]$mdns -ne 0) {
        Add-Finding -ID "NET155_MDNS" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "mDNS is not explicitly disabled (EnableMDNS=$mdns). It is the third broadcast name-resolution channel, poisonable in the same way as LLMNR and NBT-NS, and it is frequently missed because most hardening baselines predate Windows enabling it by default. It also advertises this host's name and services to the whole segment, which defeats the invisibility a closed firewall appears to provide. Disable on a machine that shares nothing: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS = 0. Note this may affect discovery of network printers and cast devices." `
            -Target "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS" -FixAction "Info" -Group "Network Exposure"
    }

    # Outbound NTLM restriction and LM compatibility — what the coerced authentication
    # is actually worth once captured.
    $ntlmOut = Get-RegVal64 -Hive LocalMachine -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
    if ($null -eq $ntlmOut -or [int]$ntlmOut -lt 1) {
        Add-Finding -ID "NET155_NTLMOUT" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_INFO `
            -Description "Outbound NTLM is unrestricted (RestrictSendingNTLMTraffic=$ntlmOut). This is what makes a poisoned name response profitable: the host will send NTLM authentication to an arbitrary peer that claims the name. Setting 1 (audit) first shows what would break; 2 (deny all) stops it. Audit before enforcing — this breaks legitimate access to anything still authenticating with NTLM. Key: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic. Also confirm LmCompatibilityLevel is 5 so LM and NTLMv1 responses are never emitted." `
            -Target "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic" -FixAction "Info" -Group "Network Exposure"
    }
    $lmcompat = Get-RegVal64 -Hive LocalMachine -SubKey $lsaKey -Name 'LmCompatibilityLevel'
    if ($null -ne $lmcompat -and [int]$lmcompat -lt 5) {
        Add-Finding -ID "NET155_LMCOMPAT" -Phase "PHASE 155" `
            -ThreatType "Credential Access" -Severity $SEV_HIGH `
            -Description "LmCompatibilityLevel is $lmcompat. Below 5 this host can emit LM or NTLMv1 responses, which are recoverable to the original password in a practical amount of time regardless of password strength — the cryptography, not the password, is the weakness. Set HKLM\$lsaKey\LmCompatibilityLevel = 5 (send NTLMv2 only, refuse LM and NTLM)." `
            -Target "HKLM\$lsaKey\LmCompatibilityLevel" -FixAction "Info" -Group "Network Exposure"
    }

    # ── PHASE 156: FIREWALL PROFILE AND ADVERTISED SERVICES ───────────────────
    Show-PhaseHeader "PHASE 156" "FIREWALL PROFILE AND WHAT THIS HOST ADVERTISES" "HARDENING"
    Out-Typewriter "READING FIREWALL PROFILES AND SERVICE ADVERTISEMENT..." "HUNT"

    # A closed firewall is a point-in-time claim. Record the profile per interface so
    # two runs can be diffed and a Public->Private flip is visible to the operator.
    try {
        foreach ($prof in @(Get-NetConnectionProfile -ErrorAction Stop)) {
            $cat = "$($prof.NetworkCategory)"; $alias = "$($prof.InterfaceAlias)"
            Out-Typewriter "  -> INTERFACE '$alias' IS IN THE '$cat' PROFILE." "INFO"
            if ($cat -eq 'Private' -or $cat -eq 'DomainAuthenticated') {
                Add-Finding -ID "NET156_PROFILE_$([Math]::Abs($alias.ToLower().GetHashCode()))" -Phase "PHASE 156" `
                    -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                    -Description "Interface '$alias' is in the '$cat' network profile. The Private profile permits file and printer sharing, network discovery and remote management rules that the Public profile blocks — so the same machine has a materially larger attack surface on this network than it would on an untrusted one. On a shared, hotel, or otherwise uncontrolled network this should be Public. Change with: Set-NetConnectionProfile -InterfaceAlias '$alias' -NetworkCategory Public. Recorded per run so a profile change between scans is visible in a comparison." `
                    -Target "NetConnectionProfile\$alias" -FixAction "Info" -Group "Network Exposure"
            }
        }
    } catch {
        Out-Typewriter "  -> COULD NOT READ NETWORK PROFILES." "WARN"
    }

    # Inbound allow rules for the protocols that matter most on a workstation.
    $riskyPorts = @{ '445' = 'SMB'; '139' = 'NetBIOS session'; '135' = 'RPC endpoint mapper';
                     '3389' = 'RDP'; '5985' = 'WinRM (HTTP)'; '5986' = 'WinRM (HTTPS)' }
    try {
        $enabledIn = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
        foreach ($rule in $enabledIn) {
            $pf = $null
            try { $pf = $rule | Get-NetFirewallPortFilter -ErrorAction Stop } catch { continue }
            foreach ($lp in @($pf.LocalPort)) {
                $lpS = "$lp"
                if (-not $riskyPorts.ContainsKey($lpS)) { continue }
                $prof = "$($rule.Profile)"
                if ($prof -notmatch 'Public|Any') { continue }
                Add-Finding -ID "NET156_INBOUND_$($lpS)_$([Math]::Abs("$($rule.Name)".ToLower().GetHashCode()))" -Phase "PHASE 156" `
                    -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
                    -Description "Inbound TCP $lpS ($($riskyPorts[$lpS])) is allowed by the enabled firewall rule '$($rule.DisplayName)' on the '$prof' profile. On the Public profile this exposes the service to every host on an untrusted network. Review with: Get-NetFirewallRule -Name '$($rule.Name)' | Get-NetFirewallPortFilter   and scope it to management infrastructure with -RemoteAddress rather than disabling it outright if the service is genuinely needed." `
                    -Target "FirewallRule\$($rule.Name):$lpS" -FixAction "Info" -Group "Network Exposure"
            }
        }
    } catch {
        Out-Typewriter "  -> COULD NOT ENUMERATE FIREWALL RULES." "WARN"
    }

    # Delivery Optimization. Peering modes advertise the machine name and an open port
    # to the whole broadcast domain, from a host that may otherwise answer nothing.
    $doMode = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode'
    if ($null -eq $doMode) {
        $doMode = Get-RegVal64 -Hive LocalMachine -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode'
    }
    if ($null -ne $doMode -and @(1,2,3) -contains [int]$doMode) {
        Out-Typewriter "  -> DELIVERY OPTIMIZATION PEERING IS ON (mode $doMode)." "WARN"
        Add-Finding -ID "NET156_DOPEER" -Phase "PHASE 156" `
            -ThreatType "Discovery / Exposure" -Severity $SEV_INFO `
            -Description "Delivery Optimization peer-to-peer is enabled (DODownloadMode=$doMode; modes 1, 2 and 3 all peer). To find peers it advertises this machine over mDNS with its hostname, both IP families and a listening TCP port (usually 7680) to the entire broadcast domain. The practical consequence is that a host whose firewall refuses every unicast probe still announces its own existence, name and an open port to anyone listening — the firewall creates an appearance of invisibility that this default-on service removes. Set DODownloadMode to 0 (HTTP only) or 99 (simple, no peering) on machines that should not be discoverable: HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode." `
            -Target "DODownloadMode" -FixAction "Info" -Group "Network Exposure"
    }

    Out-Typewriter "NETWORK-EXPOSURE BAND COMPLETE." "OK"

    # ── PHASE 157: THE REMAINING PERSISTENCE SURFACE ──────────────────────────
    # The autostart coverage in phases 20-35 and 90-105 is genuinely good. These are the
    # mechanisms it still does not reach: each is real, each is in the wild, and each
    # survives the reinstall of whatever the operator thinks the malware was.
    #
    # Every check below sits in its OWN try, so one failing registry read cannot cost
    # the other thirteen. Everything is FixAction "Info" — several of these live under
    # SYSTEM\CurrentControlSet\Control, which the remediation guard refuses outright, and
    # a CRITICAL finding with a destructive fix on a guard-protected target is
    # auto-selected in the GUI and then reported blocked on every machine (audit M1).
    Show-PhaseHeader "PHASE 157" "PROFILER, LOGON, SPOOLER AND WINSOCK PERSISTENCE" "PERSISTENCE"
    Out-Typewriter "WALKING THE PERSISTENCE MECHANISMS NOTHING ELSE CHECKS..." "HUNT"

    # 1. COR_PROFILER — loads an arbitrary DLL into EVERY .NET process on the machine.
    #    Phase 0 checks the engine's own environment; this is the machine-wide variant.
    try {
        $profSites = @(
            @{ Hive = 'LocalMachine'; Key = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; Label = 'HKLM machine environment' },
            @{ Hive = 'CurrentUser';  Key = 'Environment';                                                  Label = 'HKCU user environment' },
            @{ Hive = 'LocalMachine'; Key = 'SOFTWARE\Microsoft\.NETFramework';                             Label = 'HKLM .NETFramework' }
        )
        foreach ($ps in $profSites) {
            $enabled = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_ENABLE_PROFILING'
            $clsid   = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_PROFILER'
            $dll     = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'COR_PROFILER_PATH'
            if ($null -eq $dll) { $dll = Get-RegVal64 -Hive $ps.Hive -SubKey $ps.Key -Name 'CORECLR_PROFILER_PATH' }
            if ($null -eq $enabled -and $null -eq $clsid -and $null -eq $dll) { continue }
            $dllPath = Resolve-ScytheModulePath "$dll"
            if ($dllPath -and $dllPath -match $PERSIST_PROFILER_BENIGN_RE) {
                Out-Typewriter "  -> .NET PROFILER SET BY A KNOWN APM AGENT: $dllPath" "OK"
                continue
            }
            Out-Typewriter "  -> .NET PROFILER CONFIGURED IN $($ps.Label): $dllPath" "CRIT"
            Add-Finding -ID "PERS157_PROFILER_$([Math]::Abs("$($ps.Label)$dllPath".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_HIGH `
                -Description "A .NET profiler is configured in $($ps.Label) (COR_ENABLE_PROFILING=$enabled, COR_PROFILER=$clsid, path='$dllPath'). The CLR loads a profiler DLL into every managed process that starts while this is set, before any of that process's own code runs — so this is simultaneously persistence, privilege inheritance and injection into whatever managed service happens to launch next (MITRE T1574.012). It needs no service, no run key and no scheduled task, which is why nothing else in this scan finds it. The important benign case: application performance monitoring agents — AppDynamics, Dynatrace, New Relic, Datadog, Elastic, OpenTelemetry — set exactly this, machine-wide, on purpose, and this phase allowlists their install trees. If the path above is not one of those, resolve the DLL and check who signed it. Inspect with: Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' | Select-Object COR_*   and remove with Remove-ItemProperty on each COR_ value once you have confirmed no monitoring product owns it. Removing it takes effect for processes started afterwards; already-running processes keep the loaded profiler until they restart." `
                -Target "$($ps.Label)\COR_PROFILER" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: COR_PROFILER check failed - $($_.Exception.Message)" }

    # 2. Active Setup StubPath — runs once per user at first logon and survives a profile
    #    reset, which is what makes it outlast the usual "delete the profile" response.
    try {
        $asRoot = 'SOFTWARE\Microsoft\Active Setup\Installed Components'
        foreach ($comp in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $asRoot)) {
            $stub = Get-RegVal64 -Hive LocalMachine -SubKey "$asRoot\$comp" -Name 'StubPath'
            if ([string]::IsNullOrWhiteSpace("$stub")) { continue }
            if ("$stub" -match $PERSIST_STUBPATH_BENIGN_RE) { continue }
            $stubMod = Resolve-ScytheModulePath "$stub"
            if (-not (Test-ScytheUntrustedModule $stubMod)) { continue }
            Out-Typewriter "  -> ACTIVE SETUP STUBPATH: $comp -> $stub" "WARN"
            Add-Finding -ID "PERS157_ACTIVESETUP_$([Math]::Abs("$comp".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence" -Severity $SEV_POSSIBLE `
                -Description "Active Setup component '$comp' has StubPath = '$stub', which does not resolve to a trusted-signed binary. Active Setup runs a StubPath ONCE per user account, at that user's first logon after the component's version stamp changes, in that user's own session. Two consequences make it worth checking: it fires for users who have never logged on to this machine yet, and it survives deleting and recreating a profile — the standard cleanup step for a user-scoped compromise. The benign case is ordinary and common: Windows itself and several Microsoft products use Active Setup for per-user first-run configuration, and third-party installers do too. Read the whole entry with: Get-ItemProperty 'HKLM:\$asRoot\$comp'   and check the ComponentID and Version values alongside StubPath. If it is not explained by an installed product, record the StubPath as evidence, then remove the value with: Remove-ItemProperty 'HKLM:\$asRoot\$comp' -Name StubPath" `
                -Target "HKLM\$asRoot\$comp\StubPath" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: Active Setup check failed - $($_.Exception.Message)" }

    # 3. SilentProcessExit MonitorProcess — persistence AND an LSASS-dumping primitive,
    #    because the monitor runs with the dying process's context available to it.
    try {
        $speRoot = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
        foreach ($tgt in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $speRoot)) {
            $mon = Get-RegVal64 -Hive LocalMachine -SubKey "$speRoot\$tgt" -Name 'MonitorProcess'
            $rep = Get-RegVal64 -Hive LocalMachine -SubKey "$speRoot\$tgt" -Name 'ReportingMode'
            if ([string]::IsNullOrWhiteSpace("$mon") -and $null -eq $rep) { continue }
            Out-Typewriter "  -> SILENTPROCESSEXIT MONITOR ON '$tgt': $mon" "CRIT"
            Add-Finding -ID "PERS157_SPE_$([Math]::Abs("$tgt".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Credential Access" -Severity $SEV_HIGH `
                -Description "SilentProcessExit is configured for '$tgt' with MonitorProcess='$mon' (ReportingMode=$rep). Windows launches MonitorProcess whenever the named process exits unexpectedly, which gives an attacker two things at once: execution triggered by an event nobody watches, and — when the monitored process is lsass.exe and ReportingMode requests a dump — a full credential dump written by Windows Error Reporting itself, with no handle to LSASS ever opened by the attacker's code and therefore nothing for an EDR's LSASS-access rule to see (MITRE T1546.012, T1003.001). This key is essentially unused on a healthy workstation; almost any entry deserves an explanation. Read it with: Get-ItemProperty 'HKLM:\$speRoot\$tgt'   and, if unexplained, capture the whole subkey as evidence before removing it with: Remove-Item 'HKLM:\$speRoot\$tgt' -Recurse. If '$tgt' is lsass.exe, treat every credential on this machine as exposed and rotate accordingly." `
                -Target "HKLM\$speRoot\$tgt" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: SilentProcessExit check failed - $($_.Exception.Message)" }

    # 4. Windows Error Reporting debugger hooks — the sibling of IFEO, far less watched.
    try {
        $werSites = @(
            @{ Key = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'; Name = 'ReflectDebugger' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs'; Name = 'Debugger' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs'; Name = 'ReflectDebugger' }
        )
        foreach ($ws in $werSites) {
            $dbg = Get-RegVal64 -Hive LocalMachine -SubKey $ws.Key -Name $ws.Name
            if ([string]::IsNullOrWhiteSpace("$dbg")) { continue }
            $dbgMod = Resolve-ScytheModulePath "$dbg"
            if (-not (Test-ScytheUntrustedModule $dbgMod)) { continue }
            Out-Typewriter "  -> WER $($ws.Name) HOOK: $dbg" "CRIT"
            Add-Finding -ID "PERS157_WER_$([Math]::Abs("$($ws.Key)$($ws.Name)".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_HIGH `
                -Description "Windows Error Reporting has $($ws.Name) = '$dbg', and that command does not resolve to a trusted-signed binary. WER launches this whenever an application crashes or hangs — the same execution primitive as an Image File Execution Options Debugger, on a key that almost nothing monitors and that no autostart viewer lists (MITRE T1546.012). An attacker who can also make a chosen process crash controls when it fires. The benign case is a real debugger: Visual Studio, WinDbg and some crash-reporting products register here legitimately, which is why this phase only reports a value whose target is missing or unsigned. Inspect with: Get-ItemProperty 'HKLM:\$($ws.Key)'   and remove with: Remove-ItemProperty 'HKLM:\$($ws.Key)' -Name '$($ws.Name)'   once you have confirmed no installed debugger owns it." `
                -Target "HKLM\$($ws.Key)\$($ws.Name)" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: WER debugger check failed - $($_.Exception.Message)" }

    # 5/6/7/8/9. The DLL-loading mechanisms. Same shape for all of them: enumerate the
    #    registered modules, resolve each to a file, and report the ones that are not
    #    trusted-signed. The mechanism existing is normal; an unsigned DLL in it is not.
    try {
        $dllSites = @(
            @{ Key = 'SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'; Sub = $true;  Value = 'DllName';
               What = 'a W32Time time provider'; Tag = 'TIMEPROV';
               Why  = 'Time providers are loaded as SYSTEM inside the svchost hosting the Windows Time service, at boot, on a key nothing audits.' },
            @{ Key = 'SYSTEM\CurrentControlSet\Control\Print\Monitors';         Sub = $true;  Value = 'Driver';
               What = 'a print monitor'; Tag = 'PRINTMON';
               Why  = 'Print monitors are loaded as SYSTEM by the spooler service, which runs by default and restarts itself. This is distinct from PrintNightmare (phase 96) — it is the registration path, not the driver-install vulnerability.' },
            @{ Key = 'SOFTWARE\Microsoft\Netsh';                                Sub = $false; Value = '';
               What = 'a netsh helper DLL'; Tag = 'NETSH';
               Why  = 'A netsh helper is loaded into every netsh.exe run — including the ones administrators and management tooling perform routinely, and including several this scan itself would trigger on a differently-built tool.' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'; Sub = $false; Value = '';
               What = 'a delay-loaded shell service object'; Tag = 'SSODL';
               Why  = 'These CLSIDs are loaded into explorer.exe at every logon, in the interactive user context.' },
            @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'; Sub = $false; Value = '';
               What = 'a SharedTaskScheduler entry'; Tag = 'STS';
               Why  = 'Loaded into explorer.exe at logon. Legacy, still honoured, and absent from every modern autostart listing.' }
        )
        foreach ($ds in $dllSites) {
            $entries = @()
            if ($ds.Sub) {
                foreach ($sk in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $ds.Key)) {
                    $dv = Get-RegVal64 -Hive LocalMachine -SubKey "$($ds.Key)\$sk" -Name $ds.Value
                    if ("$dv") { $entries += @{ Name = $sk; Value = "$dv" } }
                }
            } else {
                foreach ($vn in @(Get-RegNames64 -Hive LocalMachine -SubKey $ds.Key)) {
                    $dv = Get-RegVal64 -Hive LocalMachine -SubKey $ds.Key -Name $vn
                    if ("$dv") { $entries += @{ Name = $vn; Value = "$dv" } }
                }
            }
            foreach ($en in $entries) {
                $mod = Resolve-ScytheModulePath "$($en.Value)"
                # A CLSID-valued entry (SSODL / SharedTaskScheduler) is not a path; resolve
                # it through InprocServer32 before judging it.
                if ("$($en.Value)" -match '^\{[0-9A-Fa-f-]{30,40}\}$' -or "$($en.Name)" -match '^\{[0-9A-Fa-f-]{30,40}\}$') {
                    $clsidKey = if ("$($en.Value)" -match '^\{') { "$($en.Value)" } else { "$($en.Name)" }
                    $inproc = Get-RegVal64 -Hive ClassesRoot -SubKey "CLSID\$clsidKey\InprocServer32" -Name ''
                    if ("$inproc") { $mod = Resolve-ScytheModulePath "$inproc" }
                }
                if (-not (Test-ScytheUntrustedModule $mod)) { continue }
                Out-Typewriter "  -> UNTRUSTED $($ds.Tag) MODULE: $($en.Name) -> $mod" "CRIT"
                Add-Finding -ID "PERS157_$($ds.Tag)_$([Math]::Abs("$($en.Name)$mod".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                    -Description "'$($en.Name)' registers $($ds.What) that resolves to '$mod', which is missing or is not trusted-signed. $($ds.Why) The registration itself is a normal Windows facility with legitimate users, so the signature verdict — not the mechanism — is the finding here; a signed vendor module in this slot is expected and this phase allowlists the security and virtualisation vendors that ship them. Confirm the module: Get-AuthenticodeSignature '$mod' | Format-List Status, SignerCertificate   and check when it appeared: Get-Item '$mod' | Format-List CreationTime, LastWriteTime. If it is unexplained, capture both the file and the registry key as evidence before removing the registration under 'HKLM\$($ds.Key)'. Do not simply delete the DLL while the registration remains — a missing module here can leave the spooler or Explorer failing on every start." `
                    -Target "HKLM\$($ds.Key)\$($en.Name)" -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: DLL-loading mechanism sweep failed - $($_.Exception.Message)" }

    # 8b. Winsock LSP catalogue and AutodialDLL — both inject into networked processes.
    try {
        $wsParams = 'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
        $autodial = Get-RegVal64 -Hive LocalMachine -SubKey $wsParams -Name 'AutodialDLL'
        $autoMod  = Resolve-ScytheModulePath "$autodial"
        $stockAutodial = Join-Path $global:SCYTHE_SYS32 'rasadhlp.dll'
        if ("$autodial" -and $autoMod -and ($autoMod -ne $stockAutodial) -and (Test-ScytheUntrustedModule $autoMod)) {
            Out-Typewriter "  -> AUTODIALDLL REPLACED: $autodial" "CRIT"
            Add-Finding -ID "PERS157_AUTODIAL" -Phase "PHASE 157" `
                -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                -Description "AutodialDLL is set to '$autodial' rather than the stock '$stockAutodial'. Windows loads this DLL into any process that makes a WinINet call and finds no connection — which on a normal desktop means it is loaded into browsers, updaters, Office and most management agents, in their own context (MITRE T1546). It has no legitimate third-party use that this project has seen. Confirm the current value with: Get-ItemProperty 'HKLM:\$wsParams' -Name AutodialDLL   and restore it with: Set-ItemProperty 'HKLM:\$wsParams' -Name AutodialDLL -Value '$stockAutodial'. Preserve the replacement DLL as evidence first — it is the payload, and its signature and compile timestamp are what date the intrusion." `
                -Target "HKLM\$wsParams\AutodialDLL" -FixAction "Info" -Group "Persistence Surface"
        }
        $lspRoot = "$wsParams\Protocol_Catalog9\Catalog_Entries"
        foreach ($lsp in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $lspRoot)) {
            $pe = Get-RegVal64 -Hive LocalMachine -SubKey "$lspRoot\$lsp" -Name 'PackedCatalogItem'
            if ($null -eq $pe) { continue }
            # PackedCatalogItem is a binary blob whose first field is the provider DLL path
            # as a null-terminated wide string. Decode only that leading path — no parsing
            # of attacker-controlled structure beyond the first field.
            $lspPath = ''
            try {
                $txt = [System.Text.Encoding]::Unicode.GetString([byte[]]$pe)
                $nul = $txt.IndexOf([char]0)
                $lspPath = if ($nul -gt 0) { $txt.Substring(0, $nul) } else { '' }
            } catch { $lspPath = '' }
            if ([string]::IsNullOrWhiteSpace($lspPath)) { continue }
            $lspMod = Resolve-ScytheModulePath $lspPath
            if (-not (Test-ScytheUntrustedModule $lspMod)) { continue }
            Out-Typewriter "  -> UNTRUSTED WINSOCK LSP: $lspMod" "CRIT"
            Add-Finding -ID "PERS157_LSP_$([Math]::Abs("$lspMod".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Collection" -Severity $SEV_HIGH `
                -Description "Winsock catalogue entry '$lsp' provides '$lspMod', which is missing or not trusted-signed. A layered service provider is loaded into EVERY process that opens a socket, and sits in the data path of that process's traffic — so it is simultaneously persistence, injection and a network tap that needs no driver and no hooking (MITRE T1546). Legitimate LSPs still exist (some VPN, DLP and parental-control products install them), which is why the signature verdict is the trigger rather than the entry's existence. Inventory the catalogue with: netsh winsock show catalog. If this entry is unexplained, reset the catalogue with: netsh winsock reset   then REBOOT — note that this removes every third-party LSP including legitimate ones, so record the catalogue output first, and expect VPN or filtering products to need reinstalling afterwards." `
                -Target "HKLM\$lspRoot\$lsp" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: Winsock check failed - $($_.Exception.Message)" }

    # 10/11. Two single-value hijacks: the screen saver and the RDP initial program.
    try {
        $scr = Get-RegVal64 -Hive CurrentUser -SubKey 'Control Panel\Desktop' -Name 'SCRNSAVE.EXE'
        $scrMod = Resolve-ScytheModulePath "$scr"
        if ("$scr" -and (Test-ScytheUntrustedModule $scrMod)) {
            Out-Typewriter "  -> SCREEN SAVER BINARY IS UNTRUSTED: $scr" "WARN"
            Add-Finding -ID "PERS157_SCRNSAVE" -Phase "PHASE 157" `
                -ThreatType "Persistence" -Severity $SEV_POSSIBLE `
                -Description "The screen saver is set to '$scr', which is missing or not trusted-signed. Windows executes this binary in the interactive user's session after the idle timeout — ancient, still functional, and absent from every modern autostart listing (MITRE T1546.002). It is a reliable trigger precisely because an idle workstation is when nobody is watching. Benign cases exist: corporate branded screen savers and some vendor lock screens are unsigned. Check the value with: Get-ItemProperty 'HKCU:\Control Panel\Desktop' | Select-Object SCRNSAVE.EXE, ScreenSaveActive, ScreenSaveTimeOut   and reset it by choosing a stock screen saver in Settings, or with: Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -Value 'scrnsave.scr'" `
                -Target "HKCU\Control Panel\Desktop\SCRNSAVE.EXE" -FixAction "Info" -Group "Persistence Surface"
        }
        $rdpKey = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $initProg = Get-RegVal64 -Hive LocalMachine -SubKey $rdpKey -Name 'InitialProgram'
        if (-not [string]::IsNullOrWhiteSpace("$initProg")) {
            Out-Typewriter "  -> RDP INITIALPROGRAM SET: $initProg" "CRIT"
            Add-Finding -ID "PERS157_RDPINIT" -Phase "PHASE 157" `
                -ThreatType "Persistence" -Severity $SEV_HIGH `
                -Description "The RDP listener has InitialProgram = '$initProg'. This command runs on EVERY remote desktop logon to this host, in the connecting user's session, before their shell. On a managed endpoint that means it fires whenever a technician connects — including the technician sent to investigate the machine. The value is empty on a stock Windows installation; a small number of kiosk and published-application deployments set it deliberately, and that is the benign case to rule out. Read the whole listener configuration with: Get-ItemProperty 'HKLM:\$rdpKey' | Select-Object InitialProgram, WorkDirectory, fInheritInitialProgram   and clear it with: Set-ItemProperty 'HKLM:\$rdpKey' -Name InitialProgram -Value ''   after recording the current value. Check the matching per-user Terminal Services profile settings too — the same override exists in Active Directory user properties." `
                -Target "HKLM\$rdpKey\InitialProgram" -FixAction "Info" -Group "Persistence Surface"
        }
    } catch { Write-Log "PHASE 157: screen saver / RDP check failed - $($_.Exception.Message)" }

    # 12. A service that reads as disabled but starts on an event. This is the one that
    #     defeats the "I checked, the service is disabled" conclusion.
    try {
        $svcRoot = 'SYSTEM\CurrentControlSet\Services'
        $trigCount = 0
        foreach ($svc in @(Get-RegSubKeys64 -Hive LocalMachine -SubKey $svcRoot)) {
            $start = Get-RegVal64 -Hive LocalMachine -SubKey "$svcRoot\$svc" -Name 'Start'
            if ($null -eq $start -or [int]$start -ne 4) { continue }
            $trig = @(Get-RegSubKeys64 -Hive LocalMachine -SubKey "$svcRoot\$svc\TriggerInfo")
            if ($trig.Count -eq 0) { continue }
            if ("$svc" -match $PERSIST_TRIGGER_BENIGN_RE) { continue }
            $img = Get-RegVal64 -Hive LocalMachine -SubKey "$svcRoot\$svc" -Name 'ImagePath'
            $trigCount++
            Out-Typewriter "  -> DISABLED SERVICE WITH START TRIGGERS: $svc" "WARN"
            Add-Finding -ID "PERS157_TRIGGER_$([Math]::Abs("$svc".ToLower().GetHashCode()))" -Phase "PHASE 157" `
                -ThreatType "Persistence / Defense Evasion" -Severity $SEV_POSSIBLE `
                -Description "Service '$svc' has Start=4 (Disabled) but carries $($trig.Count) TriggerInfo subkey(s). ImagePath: '$img'. A trigger-started service runs when its registered event occurs — a device arriving, an IP address appearing, a firewall port opening, an ETW event firing — regardless of what the Start value says, and the Services console displays it as Disabled the whole time. That is why this matters: 'I checked, the service is disabled' is a conclusion this configuration is specifically able to defeat. Windows itself ships several demand-start services in this shape and this phase allowlists the ones seen on stock and domain-managed builds, so treat this as a prompt to identify the service rather than as a detection. List the triggers with: sc.exe qtriggerinfo '$svc'   and inspect the image with: Get-AuthenticodeSignature '$img'. If the service is not recognised, delete the triggers with: sc.exe triggerinfo '$svc' delete   before deciding what to do with the service itself." `
                -Target "HKLM\$svcRoot\$svc\TriggerInfo" -FixAction "Info" -Group "Persistence Surface"
        }
        if ($trigCount -eq 0) { Out-Typewriter "  -> NO DISABLED-BUT-TRIGGERED SERVICES." "OK" }
    } catch { Write-Log "PHASE 157: service trigger check failed - $($_.Exception.Message)" }

    # 13. Shell file types that execute or coerce authentication when merely rendered.
    try {
        $dropRoots = @(@($env:TEMP, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:APPDATA\Microsoft\Windows\Start Menu") |
                       Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($dropRoots.Count -gt 0) {
            $dropFiles = @(Get-ScanFiles -Path $dropRoots -MaxFiles 6000 -DeadlineSecs 12)
            foreach ($df in $dropFiles) {
                if ($PERSIST_DROPPER_EXTS -notcontains "$($df.Extension)".ToLower()) { continue }
                $dfPath = "$($df.FullName)"
                $dhit = Test-ContentRules -FilePath $dfPath -Rules $PERSIST_DROPPER_RULES -MaxBytes 262144
                if (-not $dhit.Hit) { continue }
                Out-Typewriter "  -> SHELL DROPPER FILE: $dfPath ($($dhit.Name))" "CRIT"
                Add-Finding -ID "PERS157_DROPPER_$([Math]::Abs($dfPath.ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Initial Access / Execution" -Severity $SEV_HIGH `
                    -Description "'$dfPath' is a $($df.Extension) shell file whose content matches '$($dhit.Name)'. These file types are plain text, are not treated as executables by mail gateways or by the mark-of-the-web prompt, and act when the file is opened — or, for .settingcontent-ms and .library-ms, when Explorer merely renders the folder containing it. Two techniques appear here: a DeepLink or URL pointing at an executable or a script host, which is direct execution (MITRE T1204.002); and an IconFile or url pointing at a UNC path, which makes Explorer authenticate to an attacker-controlled host and hand over a net-NTLMv2 response with no user interaction at all (MITRE T1187). Open it in a text editor — it is short and readable — and look at the target. The benign case is a legitimate shortcut to an internal file server, which is why the UNC rules do not distinguish a hostile host from a corporate one; check whether the server name is yours. Preserve the file as evidence, then delete it and check the browser or mail history for where it came from." `
                    -Target $dfPath -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: shell dropper sweep failed - $($_.Exception.Message)" }

    # 14. AppDomainManager via a .config sidecar. Phase 95 covers the registry route only;
    #     the sidecar route needs no registry write at all, just a file next to the exe.
    try {
        $admRoots = @(@($env:TEMP, "$env:USERPROFILE\Downloads", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:ProgramData") |
                      Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($admRoots.Count -gt 0) {
            $cfgFiles = @(Get-ScanFiles -Path $admRoots -Filter '*.config' -MaxFiles 6000 -DeadlineSecs 12)
            foreach ($cf in $cfgFiles) {
                if ("$($cf.Name)" -notmatch '(?i)\.exe\.config$') { continue }
                $cfPath = "$($cf.FullName)"
                $cfText = ''
                try { if ($cf.Length -lt 262144) { $cfText = [System.IO.File]::ReadAllText($cfPath) } } catch { $cfText = '' }
                if ($cfText -notmatch '(?i)appDomainManager(Assembly|Type)') { continue }
                Out-Typewriter "  -> APPDOMAINMANAGER SIDECAR: $cfPath" "CRIT"
                Add-Finding -ID "PERS157_ADM_$([Math]::Abs($cfPath.ToLower().GetHashCode()))" -Phase "PHASE 157" `
                    -ThreatType "Persistence / Hijack Execution Flow" -Severity $SEV_HIGH `
                    -Description "'$cfPath' declares an appDomainManagerAssembly or appDomainManagerType. A .NET application configuration file sitting next to a managed executable can name an assembly that the CLR loads and executes BEFORE the application's own entry point, in that application's identity and with its signature intact — the executable is untouched and still verifies, so a signature check on the binary tells you nothing (MITRE T1574.014). Phase 95 covers the registry route to the same technique; this is the sidecar route, which needs no registry write at all. Legitimate uses exist but are rare outside enterprise .NET applications with custom hosting. Read the file — it is XML and short — and identify the named assembly, then check where that assembly is and who signed it. Preserve both files as evidence before removing the configuration element." `
                    -Target $cfPath -FixAction "Info" -Group "Persistence Surface"
            }
        }
    } catch { Write-Log "PHASE 157: AppDomainManager sidecar sweep failed - $($_.Exception.Message)" }


    # ── PHASE 158: SUPPLY CHAIN AND DEVELOPER TOOLING ─────────────────────────
    # Untouched by all 133 earlier phases, and on a developer or technician workstation
    # it is the softest surface in the building — it is also how an MSP gets hit THROUGH
    # its own staff. An editor extension, a git hook or a weaponised .gitconfig runs
    # arbitrary code on an ordinary, unremarkable action and appears in no autostart list.
    #
    # The false-positive problem IS this phase. A developer box has thousands of these
    # files legitimately, so almost everything here is INFO and escalates only on a
    # concrete malicious construct — an encoded command, a downloader, a raw-IP URL, a
    # pipe into a shell. A stock .git\hooks directory of .sample files and a normal
    # VS Code install must produce zero findings; the test suite asserts exactly that.
    #
    # The typosquat check named in the original brief is deliberately NOT implemented.
    # It needs a curated list of very-popular package names to be meaningful, that list
    # is a standing maintenance commitment this project has not made, and a stale one
    # produces confident false accusations about a developer's own dependencies.
    Show-PhaseHeader "PHASE 158" "EDITOR EXTENSIONS, GIT HOOKS AND PACKAGE TOOLING" "SUPPLY CHAIN"
    Out-Typewriter "AUDITING DEVELOPER TOOLING FOR EXECUTION ON ORDINARY ACTIONS..." "HUNT"

    # (a) Editor extensions. An extension runs arbitrary code at editor startup, can be
    #     sideloaded from a .vsix with no signature requirement, and nobody audits them.
    try {
        $extRoots = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)extensions$' -and (Test-Path -LiteralPath $_) })
        foreach ($er in $extRoots) {
            $extDirs = @()
            try { $extDirs = @(Get-ChildItem -LiteralPath $er -Directory -ErrorAction Stop) } catch { $extDirs = @() }
            foreach ($ed in $extDirs) {
                $pkg = Join-Path $ed.FullName 'package.json'
                if (-not (Test-Path -LiteralPath $pkg)) { continue }
                if ($pkg -match $DEVTOOL_BENIGN_RE) { continue }
                $startHit = Test-ContentRules -FilePath $pkg -Rules $DEVTOOL_STARTUP_RULES -MaxBytes 1048576
                $hookHit  = Test-ContentRules -FilePath $pkg -Rules $DEVTOOL_HOOK_RULES    -MaxBytes 1048576
                # The extension's own entry bundle, checked against the EXISTING webhook/C2
                # rule set (phase 130's) rather than a second copy of it. One file per
                # extension and size-capped on purpose: these bundles are minified and can
                # be megabytes each, and reading every file of every extension is a
                # wall-clock problem with no extra detection in it.
                $extMain = ''
                try {
                    $pkgObj = Get-Content -LiteralPath $pkg -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ("$($pkgObj.main)") { $extMain = Join-Path $ed.FullName ("$($pkgObj.main)".Replace('/','\')) }
                } catch { $extMain = '' }
                if ($extMain -and (Test-Path -LiteralPath $extMain) -and -not ($extMain -match $WEBHOOK_BENIGN_RE)) {
                    $whHit = Test-ContentRules -FilePath $extMain -Rules $WEBHOOK_C2_RULES -MaxBytes 4194304
                    if ($whHit.Hit) {
                        Out-Typewriter "  -> EXTENSION BUNDLE CARRIES A CHAT-WEBHOOK C2 URL: $extMain" "CRIT"
                        Add-Finding -ID "SUPPLY158_EXTC2_$([Math]::Abs("$extMain".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                            -ThreatType "Supply Chain / Command and Control" -Severity $SEV_HIGH `
                            -Description "The entry bundle of editor extension '$($ed.Name)' — '$extMain' — contains a URL matching '$($whHit.Name)'. A chat-platform webhook is command-and-control that needs no attacker infrastructure at all: the endpoint is a legitimate, TLS-protected, generally-allowed service, so the traffic passes egress filtering and reputation checks that would stop a purpose-built C2 domain. Inside an editor extension it is also perfectly placed — the extension already has the developer's source tree, their tokens, and their terminal. The benign case is genuine and needs ruling out: an extension that legitimately posts notifications to Slack, Discord or Teams, and any extension that merely documents a webhook in a sample. Read the surrounding code: Select-String -Path '$extMain' -Pattern 'https' -SimpleMatch | Select-Object -First 20. If the extension has no reason to talk to a chat platform, uninstall it, then treat every credential this developer holds as exposed — see phase 147 for what that means in practice." `
                            -Target $extMain -FixAction "Info" -Group "Supply Chain"
                    }
                }
                if (-not $hookHit.Hit) { continue }
                $extSev = if ("$($hookHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
                $startNote = if ($startHit.Hit) { "It also activates at editor startup ($($startHit.Name)), so it runs whether or not the user opens a matching file." } else { "Its declared activation events are narrower than startup, so it runs only for matching files." }
                Out-Typewriter "  -> EXTENSION MANIFEST MATCHES '$($hookHit.Name)': $($ed.Name)" "CRIT"
                Add-Finding -ID "SUPPLY158_EXT_$([Math]::Abs("$($ed.FullName)".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $extSev `
                    -Description "Editor extension '$($ed.Name)' has a package.json matching '$($hookHit.Name)'. $startNote Extensions execute with the full rights of the user running the editor, are installed from a marketplace with limited review, and can be sideloaded from a .vsix with no signature requirement at all — so this is a genuine code-execution surface that no autostart listing shows. The honest false-positive case is large: many legitimate extensions shell out, spawn child processes, or fetch data over HTTP as part of their normal job (linters, language servers, container and cloud tooling all do). Read the manifest yourself: Get-Content '$pkg'   then look at what the extension actually ships in its out or dist directory. Check the publisher against the marketplace listing, and check the install date — an extension that appeared without the user installing it is the finding. Remove with: code --uninstall-extension <publisher.name>" `
                    -Target "$($ed.FullName)" -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: extension sweep failed - $($_.Exception.Message)" }

    # (b) Repository-local execution: .vscode/tasks.json runOn folderOpen, git hooks,
    #     package install scripts and MSBuild inline tasks. Repository roots are found
    #     from a fixed shallow list of developer directories, never a profile walk.
    try {
        $repoRoots = @(Get-ScytheRepoRoots)
        if ($repoRoots.Count -eq 0) {
            Out-Typewriter "  -> NO LOCAL REPOSITORIES FOUND IN THE USUAL DEVELOPER DIRECTORIES." "OK"
        }
        foreach ($repo in $repoRoots) {
            # .vscode/tasks.json — opening the repository is enough to execute this.
            $tasksJson = Join-Path $repo '.vscode\tasks.json'
            if (Test-Path -LiteralPath $tasksJson) {
                $tStart = Test-ContentRules -FilePath $tasksJson -Rules $DEVTOOL_STARTUP_RULES -MaxBytes 262144
                $tHook  = Test-ContentRules -FilePath $tasksJson -Rules $DEVTOOL_HOOK_RULES    -MaxBytes 262144
                if ($tStart.Hit -or $tHook.Hit) {
                    $tSev = if ($tHook.Hit -and "$($tHook.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
                    $tWhat = if ($tHook.Hit) { "$($tHook.Name)" } else { "$($tStart.Name)" }
                    Out-Typewriter "  -> REPOSITORY TASK RUNS ON OPEN: $tasksJson" "CRIT"
                    Add-Finding -ID "SUPPLY158_TASK_$([Math]::Abs($tasksJson.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                        -ThreatType "Supply Chain / Execution" -Severity $tSev `
                        -Description "'$tasksJson' matches '$tWhat'. A task configured with runOn folderOpen executes when the repository is merely OPENED in the editor — no build, no debug, no user action beyond browsing to a folder. That makes a cloned repository a drive-by on a developer box, and it is a documented technique for exactly that (MITRE T1204.002). The benign case is real and common: many projects legitimately use folderOpen tasks to start a watcher, a dev server or a container. What separates them is the command. Read it: Get-Content '$tasksJson'. If the command downloads anything, decodes a blob, pipes into a shell, or references a raw IP address, treat the repository as hostile and do not open it again — check the clone URL and who suggested it." `
                        -Target $tasksJson -FixAction "Info" -Group "Supply Chain"
                }
            }
            # .git/hooks — a stock directory holds only .sample files and is silent here.
            $hookDir = Join-Path $repo '.git\hooks'
            if (Test-Path -LiteralPath $hookDir) {
                $hookFiles = @()
                try { $hookFiles = @(Get-ChildItem -LiteralPath $hookDir -File -ErrorAction Stop) } catch { $hookFiles = @() }
                foreach ($hf in $hookFiles) {
                    if ("$($hf.Name)" -match '(?i)\.sample$') { continue }
                    $hfPath = "$($hf.FullName)"
                    $hHit = Test-ContentRules -FilePath $hfPath -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
                    if (-not $hHit.Hit) { continue }
                    $hSev = if ("$($hHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
                    Out-Typewriter "  -> GIT HOOK MATCHES '$($hHit.Name)': $hfPath" "CRIT"
                    Add-Finding -ID "SUPPLY158_HOOK_$([Math]::Abs($hfPath.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                        -ThreatType "Supply Chain / Execution" -Severity $hSev `
                        -Description "Git hook '$($hf.Name)' in '$repo' matches '$($hHit.Name)'. Hooks execute on ordinary developer actions and nothing announces them: post-checkout and post-merge fire on git checkout and git pull, pre-commit on every commit. A hook is not transferred by git clone, so one that exists here was installed locally — by the developer, by a tool such as Husky or pre-commit, or by something else. That last case is the finding. The benign case dominates on a real developer machine and this phase is scoped to it deliberately: a stock .git\hooks directory contains only .sample files and produces nothing here. Read the hook: Get-Content '$hfPath'. Check whether a hook manager owns it — a Husky hook references .husky, a pre-commit hook references the pre-commit framework. If nothing explains it, preserve it as evidence and delete it; then check every other clone on this machine, because a hook installer usually visits more than one." `
                        -Target $hfPath -FixAction "Info" -Group "Supply Chain"
                }
            }
            # package.json install scripts — preinstall/postinstall run on npm install.
            $pkgJson = Join-Path $repo 'package.json'
            if (Test-Path -LiteralPath $pkgJson) {
                $pText = ''
                try { $pText = [System.IO.File]::ReadAllText($pkgJson) } catch { $pText = '' }
                if ($pText -match '(?i)"(preinstall|postinstall|prepare)"\s{0,4}:') {
                    $pHit = Test-ScytheTextRules -Text $pText -Rules $DEVTOOL_HOOK_RULES
                    if ($null -ne $pHit) {
                        $pSev = if ("$($pHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
                        Out-Typewriter "  -> INSTALL SCRIPT MATCHES '$($pHit.Name)': $pkgJson" "CRIT"
                        Add-Finding -ID "SUPPLY158_NPM_$([Math]::Abs($pkgJson.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                            -ThreatType "Supply Chain / Execution" -Severity $pSev `
                            -Description "'$pkgJson' declares an install script and its content matches '$($pHit.Name)'. npm runs preinstall, postinstall and prepare automatically during npm install — the developer types one command and arbitrary code from the package tree executes, which is the delivery mechanism behind most published npm compromises (MITRE T1195.001). Legitimate install scripts are extremely common: native modules compile, tools install binaries, husky installs hooks. The rule that matched is what to look at, not the presence of the script. Read it: Get-Content '$pkgJson'. If it fetches from a URL, decodes a blob or pipes into a shell, do not run npm install in this repository; check the package against the registry, and check whether node_modules already contains the result of a previous install." `
                            -Target $pkgJson -FixAction "Info" -Group "Supply Chain"
                    }
                }
            }
            # MSBuild inline tasks — <UsingTask> with an inline <Code> block compiles and
            # runs C# during an ordinary build.
            $projFiles = @()
            try { $projFiles = @(Get-ChildItem -LiteralPath $repo -File -ErrorAction Stop | Where-Object { "$($_.Extension)" -match '(?i)^\.(csproj|vbproj|targets|props)$' }) } catch { $projFiles = @() }
            foreach ($pf in $projFiles) {
                $pfPath = "$($pf.FullName)"
                $pfText = ''
                try { if ($pf.Length -lt 1048576) { $pfText = [System.IO.File]::ReadAllText($pfPath) } } catch { $pfText = '' }
                if ($pfText -notmatch '(?i)<UsingTask') { continue }
                if ($pfText -notmatch '(?i)<Code\b') { continue }
                Out-Typewriter "  -> MSBUILD INLINE TASK: $pfPath" "WARN"
                Add-Finding -ID "SUPPLY158_MSBUILD_$([Math]::Abs($pfPath.ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $SEV_POSSIBLE `
                    -Description "'$pfPath' contains a UsingTask with an inline Code block. MSBuild compiles and executes that code during an ordinary build, in the developer's context, using a Microsoft-signed host binary — which is why msbuild.exe is a standard application-allowlisting bypass and why this shape is worth reading (MITRE T1127.001). It is also a completely legitimate MSBuild feature that build systems use routinely. Read the Code block: Get-Content '$pfPath'. Judge it on what it does — a build-time code generator or version stamper is normal; anything that reaches the network, touches the registry, or writes outside the build output is not, in a project file." `
                    -Target $pfPath -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: repository sweep failed - $($_.Exception.Message)" }

    # (c) Weaponised git configuration. core.fsmonitor is the important one: it fires on
    #     EVERY git command, so it is persistence that triggers dozens of times a day.
    try {
        $gitConfigs = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)(\.gitconfig|\\git\\config)$' -and (Test-Path -LiteralPath $_) })
        foreach ($repo in @(Get-ScytheRepoRoots)) {
            $rc = Join-Path $repo '.git\config'
            if (Test-Path -LiteralPath $rc) { $gitConfigs += $rc }
        }
        foreach ($gc in @($gitConfigs | Sort-Object -Unique)) {
            $gHit = Test-ContentRules -FilePath $gc -Rules $DEVTOOL_GITCONFIG_RULES -MaxBytes 262144
            if (-not $gHit.Hit) { continue }
            $gCmd = Test-ContentRules -FilePath $gc -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
            $gSev = if ($gCmd.Hit -and "$($gCmd.Severity)" -eq 'HIGH') { $SEV_HIGH } elseif ("$($gHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
            $gExtra = if ($gCmd.Hit) { " Its command content additionally matches '$($gCmd.Name)', which is what raises this above routine configuration." } else { "" }
            Out-Typewriter "  -> GIT CONFIG EXECUTES A COMMAND ('$($gHit.Name)'): $gc" "WARN"
            Add-Finding -ID "SUPPLY158_GITCFG_$([Math]::Abs("$gc".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                -ThreatType "Supply Chain / Persistence" -Severity $gSev `
                -Description "'$gc' matches '$($gHit.Name)'.$gExtra Several git configuration keys execute a command during ordinary operations: core.fsmonitor runs on EVERY git command, core.sshCommand on every fetch and push, diff textconv on every diff of a matching file, and filter clean/smudge on every checkout and commit of one. An alias beginning with ! is a shell command. So a weaponised git config is persistence that fires dozens of times a day, in the developer's context, and appears in no autostart listing (MITRE T1546). The benign case is ordinary: Git LFS installs clean and smudge filters, delta and diff-so-fancy install a pager, corporate setups set sshCommand, and Scalar and VFS for Git set fsmonitor. Read the file — it is short: Get-Content '$gc'. Identify the tool that owns each entry. Anything you cannot attribute, remove with: git config --global --unset <key>   (or --unset for a repository-local one), and check whether the same entry exists in the other config scopes: git config --list --show-origin" `
                -Target $gc -FixAction "Info" -Group "Supply Chain"
        }
    } catch { Write-Log "PHASE 158: git config check failed - $($_.Exception.Message)" }

    # (d) Package-registry redirection. An override here silently reroutes every install.
    try {
        $regFiles = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)(\.npmrc|NuGet\.Config)$' -and (Test-Path -LiteralPath $_) })
        foreach ($repo in @(Get-ScytheRepoRoots)) {
            foreach ($rn in @('.npmrc','NuGet.Config','nuget.config')) {
                $rp = Join-Path $repo $rn
                if (Test-Path -LiteralPath $rp) { $regFiles += $rp }
            }
        }
        foreach ($rf in @($regFiles | Sort-Object -Unique)) {
            $rHit = Test-ContentRules -FilePath $rf -Rules $DEVTOOL_REGISTRY_RULES -MaxBytes 262144
            if (-not $rHit.Hit) { continue }
            $rSev = if ("$($rHit.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
            Out-Typewriter "  -> PACKAGE REGISTRY OVERRIDE ('$($rHit.Name)'): $rf" "WARN"
            Add-Finding -ID "SUPPLY158_REGISTRY_$([Math]::Abs("$rf".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                -ThreatType "Supply Chain" -Severity $rSev `
                -Description "'$rf' matches '$($rHit.Name)' — it points package installs at a registry other than the vendor default, or over plain HTTP. Every dependency this machine installs then comes from that host, including transitive ones the developer never named, which is the delivery half of a dependency-confusion or registry-hijack attack (MITRE T1195.001). The benign case is the common one in an MSP context: a corporate Artifactory, Nexus, Azure Artifacts or GitHub Packages feed, or a scoped registry for internal packages. Verify the host is one of yours. Read it: Get-Content '$rf'   and cross-check the effective configuration with: npm config list   or   dotnet nuget list source. A plain-HTTP feed is worth fixing regardless of who owns it — it is trivially interceptable on a shared network, and this machine's network posture is what phases 153-156 just measured." `
                -Target $rf -FixAction "Info" -Group "Supply Chain"
        }
    } catch { Write-Log "PHASE 158: package registry check failed - $($_.Exception.Message)" }

    # (e) Jupyter kernel specs. argv[0] is what the notebook server actually launches.
    try {
        $kernelRoots = @(@($DEVTOOL_PATHS) | Where-Object { $_ -match '(?i)\\kernels$' -and (Test-Path -LiteralPath $_) })
        foreach ($kr in $kernelRoots) {
            $kdirs = @()
            try { $kdirs = @(Get-ChildItem -LiteralPath $kr -Directory -ErrorAction Stop) } catch { $kdirs = @() }
            foreach ($kd in $kdirs) {
                $kj = Join-Path $kd.FullName 'kernel.json'
                if (-not (Test-Path -LiteralPath $kj)) { continue }
                $kHit = Test-ContentRules -FilePath $kj -Rules $DEVTOOL_HOOK_RULES -MaxBytes 262144
                if (-not $kHit.Hit) { continue }
                Out-Typewriter "  -> JUPYTER KERNEL SPEC MATCHES '$($kHit.Name)': $kj" "CRIT"
                Add-Finding -ID "SUPPLY158_KERNEL_$([Math]::Abs("$kj".ToLower().GetHashCode()))" -Phase "PHASE 158" `
                    -ThreatType "Supply Chain / Execution" -Severity $SEV_HIGH `
                    -Description "Jupyter kernel spec '$kj' matches '$($kHit.Name)'. The argv array in a kernel spec is the exact command the notebook server launches when a user selects that kernel — so replacing or adding one gives execution on an action the user reads as 'open a notebook', with no notebook content required. A kernel spec is a small JSON file in a per-user directory that nothing audits. The benign case: a kernel spec legitimately names a Python or Conda interpreter path, sometimes through a wrapper script. Read it: Get-Content '$kj'   and confirm argv[0] is an interpreter you expect. List all of them with: jupyter kernelspec list   and remove an unrecognised one with: jupyter kernelspec remove <name>" `
                    -Target $kj -FixAction "Info" -Group "Supply Chain"
            }
        }
    } catch { Write-Log "PHASE 158: jupyter kernel check failed - $($_.Exception.Message)" }


    # ── PHASE 159: UEFI / ESP INTEGRITY ───────────────────────────────────────
    # Phase 58 covers the MBR and phase 40 covers the BCD signing flags. Nothing until
    # now looked at the EFI System Partition, which is where a modern bootkit lives: it
    # is FAT32, so it carries no NTFS ACLs once mounted, it is excluded from most backup
    # and AV coverage, and code there runs before Windows — and therefore before every
    # other detection in this tool.
    #
    # THIS PHASE DOES NOT MOUNT THE ESP, and no switch is provided to make it. The
    # original F7 brief said to mount it read-only and unmount in a finally. That was
    # dropped for the same reason the F6 LAN band became host-side (see the banner at the
    # top of this file): Scythe runs on client machines under an MSP contract, assigning
    # and removing a system partition's access path is a live change to the boot volume's
    # mount state, and "leave nothing behind on a client machine" is a standing rule here
    # (audit M5/M9/M10). If the ESP already has an access path this phase reads it; if it
    # does not, it says so and hands the operator the exact commands. Everything else
    # below — Secure Boot, dbx currency, the BCD flags — is answerable without mounting
    # anything, which is most of the value.
    Show-PhaseHeader "PHASE 159" "SECURE BOOT, REVOCATION CURRENCY AND THE EFI PARTITION" "BOOT INTEGRITY"
    Out-Typewriter "READING FIRMWARE AND BOOT-CHAIN STATE..." "HUNT"

    # Firmware type first. Confirm-SecureBootUEFI THROWS on a legacy BIOS machine rather
    # than returning false, so the whole phase has to degrade cleanly on one.
    $sbState = $null
    $isUefi  = $true
    try { $sbState = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { $sbState = $null; $isUefi = $false }

    if (-not $isUefi) {
        Out-Typewriter "  -> LEGACY BIOS / NON-UEFI BOOT — ESP AND SECURE BOOT CHECKS DO NOT APPLY." "INFO"
        Add-Finding -ID "BOOT159_LEGACYBIOS" -Phase "PHASE 159" `
            -ThreatType "Boot Integrity" -Severity $SEV_INFO `
            -Description "This machine does not boot via UEFI, so Secure Boot, the dbx revocation list and the EFI System Partition do not exist here and were not assessed. That is reported rather than skipped silently, because the absence of these checks in the report would otherwise read as a pass. A legacy-BIOS/MBR machine has no Secure Boot at all: nothing verifies the boot chain, and the MBR bootkit surface that phase 58 covers is the relevant one instead. On any machine still in service this is worth planning out — converting to UEFI/GPT with MBR2GPT and enabling Secure Boot removes an entire class of pre-boot persistence, and is also a prerequisite for the virtualisation-based protections this fleet may already be licensed for." `
            -Target "FirmwareType" -FixAction "Info" -Group "Boot Integrity"
    } else {
        # 1. Secure Boot state, and the specific combination that matters.
        $blOn = $null
        try {
            $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            $blOn = ("$($blv.ProtectionStatus)" -eq 'On')
        } catch { $blOn = $null }

        if ($sbState -eq $true) {
            Out-Typewriter "  -> SECURE BOOT IS ENABLED." "OK"
        } else {
            Out-Typewriter "  -> SECURE BOOT IS DISABLED ON A UEFI MACHINE." "CRIT"
            $blNote = if ($blOn -eq $true) {
                "BitLocker is ON on this volume, and that combination is the reason this is HIGH rather than a hardening note: BitLocker's default TPM-only protector seals the key to the measured boot state, so an attacker who can turn Secure Boot off and modify the boot chain is in a position to have the TPM release the key to a chain you did not authorise. Full-volume encryption is providing markedly less protection here than the operator believes."
            } elseif ($blOn -eq $false) {
                "BitLocker is not enabled on this volume, so no key is sealed to the boot measurements — but the pre-boot execution surface is open regardless."
            } else {
                "BitLocker status could not be read this run, so the interaction between the boot chain and any sealed volume key is unknown."
            }
            Add-Finding -ID "BOOT159_SECUREBOOT_OFF" -Phase "PHASE 159" `
                -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                -Description "Secure Boot is DISABLED on a UEFI machine. With it off, the firmware executes whatever bootloader it finds on the EFI System Partition without checking a signature, which is the precondition for every modern bootkit — code that runs before Windows, before the kernel, and therefore before the driver-based protections every product in this fleet relies on. $blNote Benign causes are real and should be ruled out first: it is commonly turned off to install an unsigned driver, to dual-boot, or by an OEM firmware update that reset the setting. Re-enabling it is a firmware change, not a Windows one — reboot into UEFI setup and enable Secure Boot there. Confirm afterwards with: Confirm-SecureBootUEFI. If the machine will not boot with it on, the boot chain has been modified and that is itself the finding; repair with Windows recovery before re-enabling." `
                -Target "SecureBoot" -FixAction "Info" -Group "Boot Integrity"
        }

        # 2. dbx currency. BlackLotus and its successors depend on a stale revocation
        #    list — the vulnerable-but-signed bootloader they abuse is only stopped by a
        #    dbx entry. No exact size baseline is asserted (see the key's comment).
        try {
            $dbx = Get-SecureBootUEFI -Name dbx -ErrorAction Stop
            $dbxLen = 0
            try { $dbxLen = @($dbx.Bytes).Count } catch { $dbxLen = 0 }
            $minB = 4096
            if ($DBX_BASELINE -and $null -ne $DBX_BASELINE.MinBytes) { $minB = [int]$DBX_BASELINE.MinBytes }
            if ($dbxLen -gt 0 -and $dbxLen -lt $minB) {
                Out-Typewriter "  -> SECURE BOOT REVOCATION LIST IS A FACTORY STUB ($dbxLen bytes)." "CRIT"
                Add-Finding -ID "BOOT159_DBX_STALE" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "The Secure Boot forbidden-signature database (dbx) is $dbxLen bytes, below the $minB-byte floor at which it is unambiguously the factory stub that has never been updated. dbx is the revocation list that makes Secure Boot mean anything: the bootloaders that bootkits abuse are legitimately signed, and the only thing that stops them loading is a dbx entry revoking them. An un-updated dbx therefore leaves Secure Boot enabled, reporting healthy, and not actually blocking the attack it exists to block. Apply the current revocation updates ($($DBX_BASELINE.ReferenceKb)) — read the guidance at $($DBX_BASELINE.ReferenceUrl) BEFORE applying, because the rollout is staged and applying it to a machine that still boots older media can make that media unbootable. Measure the current size with: (Get-SecureBootUEFI dbx).Bytes.Length" `
                    -Target "SecureBootUEFI\dbx" -FixAction "Info" -Group "Boot Integrity"
            } else {
                Out-Typewriter "  -> SECURE BOOT REVOCATION LIST PRESENT ($dbxLen bytes)." "INFO"
                Add-Finding -ID "BOOT159_DBX_SIZE" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity" -Severity $SEV_INFO `
                    -Description "The Secure Boot revocation list (dbx) is $dbxLen bytes. This is reported as a MEASUREMENT, not a verdict: dbx size varies legitimately by architecture, OEM and servicing level, and this tool deliberately ships no exact baseline, because a wrong one would produce a confident false finding on every healthy machine. What to do with it: compare it against another machine of the same model and build in this fleet — a host that is materially smaller than its peers is the one that has missed the revocation updates. The relevant guidance is $($DBX_BASELINE.ReferenceKb) at $($DBX_BASELINE.ReferenceUrl). Recorded per run, so a comparison between two scans shows whether the update was actually applied." `
                    -Target "SecureBootUEFI\dbx" -FixAction "Info" -Group "Boot Integrity"
            }
        } catch {
            Out-Typewriter "  -> COULD NOT READ THE dbx UEFI VARIABLE." "WARN"
            Write-Log "PHASE 159: Get-SecureBootUEFI dbx failed - $($_.Exception.Message)"
        }

        # 3. The ESP itself, only if it is already reachable.
        $espRoot = Get-ScytheEspRoot
        if ([string]::IsNullOrWhiteSpace($espRoot)) {
            Out-Typewriter "  -> EFI SYSTEM PARTITION IS NOT MOUNTED; CONTENTS NOT INVENTORIED." "INFO"
            Add-Finding -ID "BOOT159_ESP_UNMOUNTED" -Phase "PHASE 159" `
                -ThreatType "Boot Integrity" -Severity $SEV_INFO `
                -Description "The EFI System Partition has no access path on this machine, so its contents were NOT inventoried this run and no conclusion about them appears in this report. This tool does not mount it: assigning and removing a system partition's mount point is a live change to the boot volume's state on a client machine, and leaving nothing behind is a standing rule for this product. To inventory it by hand, from an elevated prompt: mountvol S: /S   then   Get-ChildItem S:\EFI -Recurse | Select-Object FullName, Length, LastWriteTime   and finally   mountvol S: /D   to remove the access path again. What you are looking for: any directory under \EFI other than Microsoft, Boot, and your hardware vendor's own; and any .efi file whose timestamp does not match the others. If you mount it, run this scan again while it is mounted and this phase will do the comparison for you." `
                -Target "EFISystemPartition" -FixAction "Info" -Group "Boot Integrity"
        } else {
            Out-Typewriter "  -> EFI SYSTEM PARTITION REACHABLE AT $espRoot" "INFO"
            $espEfi = Join-Path $espRoot 'EFI'
            $espDirs = @()
            try { if (Test-Path -LiteralPath $espEfi) { $espDirs = @(Get-ChildItem -LiteralPath $espEfi -Directory -ErrorAction Stop) } } catch { $espDirs = @() }
            foreach ($ed in $espDirs) {
                $rel = "\EFI\$($ed.Name)"
                if (Test-ScytheNameRule -Name $rel -Rules $ESP_EXPECTED_PATHS) { continue }
                Out-Typewriter "  -> UNEXPECTED DIRECTORY ON THE ESP: $rel" "CRIT"
                Add-Finding -ID "BOOT159_ESP_UNEXPECTED_$([Math]::Abs("$rel".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "'$rel' exists on the EFI System Partition and is not one of the directories that belong there — Windows uses \EFI\Microsoft and \EFI\Boot, and hardware vendors use their own named directory for firmware update and recovery tooling. A directory outside that set holds code the firmware can be pointed at, on a FAT32 volume with no ACLs, that most backup and AV coverage never looks at. The benign cases are worth checking first and are common on real hardware: a dual-boot Linux installation (\EFI\ubuntu, \EFI\grub, \EFI\systemd), a vendor recovery tool, or leftovers from a previous operating system on a reused disk. List it: Get-ChildItem '$($ed.FullName)' -Recurse | Select-Object FullName, Length, LastWriteTime. Check the boot entry list against it: bcdedit /enum firmware. Preserve any unexplained .efi file before removing it — deleting the wrong thing here makes the machine unbootable, so change nothing until you can name what it is." `
                    -Target "$($ed.FullName)" -FixAction "Info" -Group "Boot Integrity"
            }

            # Boot binaries: the ESP copy against the servicing copy under %WINDIR%.
            $servRoot = Join-Path $env:WINDIR 'Boot\EFI'
            foreach ($bn in $ESP_BOOT_BINARIES) {
                $espCopy = Join-Path $espEfi "Microsoft\Boot\$bn"
                $srvCopy = Join-Path $servRoot $bn
                if (-not (Test-Path -LiteralPath $espCopy)) { continue }
                if (-not (Test-Path -LiteralPath $srvCopy)) { continue }
                $h1 = Get-FileHashSafe $espCopy
                $h2 = Get-FileHashSafe $srvCopy
                if ($null -eq $h1 -or $null -eq $h2) { continue }
                if ("$h1" -eq "$h2") { continue }
                Out-Typewriter "  -> BOOT BINARY DIFFERS FROM ITS SERVICING COPY: $bn" "CRIT"
                Add-Finding -ID "BOOT159_ESP_MISMATCH_$([Math]::Abs("$bn".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity / Bootkit Vector" -Severity $SEV_HIGH `
                    -Description "The ESP copy of '$bn' does not match the servicing copy under '$servRoot'. Windows servicing keeps these two in step, so a divergence means something wrote the ESP copy outside servicing — which is precisely the shape of a bootkit installation, because the ESP copy is the one the firmware actually executes and the servicing copy is the one an integrity check is most likely to look at. ESP SHA256: $h1. Servicing SHA256: $h2. The benign cases: an in-flight or interrupted feature update, a dual-boot manager that replaced the Windows loader, and some OEM recovery tooling. Verify the signature of the ESP copy before anything else: Get-AuthenticodeSignature '$espCopy' | Format-List Status, SignerCertificate. If it is not validly Microsoft-signed, treat this machine as compromised below the operating system — a bootkit survives a Windows reinstall — and rebuild it rather than cleaning it. Do not simply overwrite the ESP copy; that destroys the evidence and may leave the machine unbootable." `
                    -Target $espCopy -FixAction "Info" -Group "Boot Integrity"
            }
        }

        # 4. BCD flags phase 40 does not cover. Phase 40 already handles testsigning and
        #    nointegritychecks and this deliberately does not repeat them.
        try {
            $bcdText = (& bcdedit /enum '{current}' 2>&1 | Out-String)
            if ("$bcdText" -match '(?i)^\s*$') { $bcdText = (& bcdedit /enum 2>&1 | Out-String) }
            foreach ($bf in @($BCD_UNSAFE_FLAGS)) {
                if ($null -eq $bf) { continue }
                $bMatch = $false
                try {
                    $brx = New-Object System.Text.RegularExpressions.Regex("$($bf.Pattern)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(150))
                    $bMatch = $brx.IsMatch("$bcdText")
                } catch { $bMatch = $false }
                if (-not $bMatch) { continue }
                $bSev = if ("$($bf.Severity)" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
                Out-Typewriter "  -> BCD FLAG: $($bf.Name)" "WARN"
                Add-Finding -ID "BOOT159_BCD_$([Math]::Abs("$($bf.Name)".ToLower().GetHashCode()))" -Phase "PHASE 159" `
                    -ThreatType "Boot Integrity" -Severity $bSev `
                    -Description "The boot configuration for the current entry matches '$($bf.Name)'. Phase 40 covers testsigning and nointegritychecks; this is one of the settings it does not. The one that matters most in this set is disableelamdrivers — it stops the early-launch anti-malware driver from loading, so the endpoint's own security product is blind for exactly the part of boot that a bootkit or a malicious driver uses, while the product itself still reports healthy once Windows is up. Kernel and boot debugging flags are the next most significant: they are legitimate developer settings, and they also disable protections and allow a debugger to attach to the kernel. Read the whole store: bcdedit /enum {current}. Benign cases are real — a developer machine, a driver-signing test rig, or a machine mid-troubleshooting. If it is not explained, clear the specific flag with bcdedit (for example: bcdedit /set {current} disableelamdrivers No) and reboot. Change one setting at a time and record the original value: a wrong bcdedit write is one of the few ways to make a machine unbootable from inside Windows, which is why nothing here carries an automated fix." `
                    -Target "BCD\$($bf.Name)" -FixAction "Info" -Group "Boot Integrity"
            }
        } catch { Write-Log "PHASE 159: BCD enumeration failed - $($_.Exception.Message)" }
    }

    Out-Typewriter "PERSISTENCE, SUPPLY-CHAIN AND BOOT-INTEGRITY BAND COMPLETE." "OK"

    if (-not $global:STEALTH_MODE) {
        Write-Host "  [i] Phases 146 and 148-152 are not built in this release (parallel work package)." -ForegroundColor DarkGray
    }
    Write-Log "PHASES 146, 148-152: module stub — parallel work package not yet merged."
}
