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
#  146-152 and 157-159 remain a parallel work package (see fable-work/):
#    146      PE structural analysis                              (task F3)
#    147      cloud identity + DevOps credential theft             (task F1)
#    148-152  lateral movement, AD, credential dumping             (task F2)
#    157      remaining persistence surface                        (task F4)
#    158      supply chain + developer tooling                     (task F5)
#    159      UEFI / ESP integrity                                 (task F7)
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
if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group

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

    if (-not $global:STEALTH_MODE) {
        Write-Host "  [i] Phases 146-152 and 157-159 are not built in this release (parallel work package)." -ForegroundColor DarkGray
    }
    Write-Log "PHASES 146-152, 157-159: module stub — parallel work package not yet merged."
}
