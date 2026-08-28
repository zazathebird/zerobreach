# NOTE - Detection vocabulary in this file is deliberate.
# Terms like exfiltration, rootkit, keylogger, ransomware and credential dumping, and any
# named malware families, are detection category labels, operator-facing report text, or
# MITRE ATT&CK tactic names (a published standard). Scythe is a defensive incident-
# response tool; these strings are what it reports, not what it does. See CLAUDE.md,
# "The detection vocabulary is deliberate". Do not sanitise them.

trap { Write-RecoveredError $_; continue }   # module-level resilience (see CLAUDE.md engine-split rule)

# ══════════════════════════════════════════════════════════════════════════════
#  HUNT BAND — PHASES 160-162   ·   SYNTHESIS
#
#  No new detection. This module re-reads what the previous 159 phases already found
#  and answers the question the findings list cannot: *what happened here?*
#  It must run LAST, which is why it is a separate module dot-sourced after Phases-6.
# ══════════════════════════════════════════════════════════════════════════════
#  Three phases:
#    160  ATTACK-CHAIN CORRELATION — link findings that share a real-world entity
#         (a file, a PID, a registry key, a domain) into connected components, score
#         each component, and report the scored chains.
#    161  PATIENT ZERO — for the highest-scoring chain, find the earliest artifact on
#         disk and name it as the likely point of entry.
#    162  SUPER-TIMELINE — export every finding that resolves to a real artifact,
#         ordered by that artifact's ACTUAL timestamp rather than by phase order.
#
#  WHY THIS EXISTS. A live DEEP baseline on this project produced 734 findings. That is
#  a list, not an answer, and the operator does the analysis the tool should have done.
#  Every fact needed to say "a macro-enabled attachment ran at 14:02, Word spawned an
#  encoded PowerShell, a Run key appeared at 14:03 pointing at %APPDATA%\svc.exe, that
#  binary beaconed to a nine-day-old domain, shadow copies went at 14:07" is ALREADY
#  detected — by five different phases, presented as five unrelated rows.
#
#  IMPORTANT — WHY THIS IS ENTITY-BASED AND NOT TIME-BASED. Add-Finding stamps a finding
#  with the time the SCAN ran, not the time the artifact was created. Every finding in a
#  run therefore shares roughly one timestamp, and clustering on it would merge the whole
#  scan into a single meaningless "chain". Correlation links on shared entities; phase 162
#  is where real artifact times are recovered from the filesystem.
# ══════════════════════════════════════════════════════════════════════════════

function Get-ScytheEntities {
    # Pull the real-world objects a finding is ABOUT out of its Target and Description.
    # Returns a de-duplicated lowercase string set of "kind:value" keys. Kinds are kept
    # distinct so a PID can never collide with a path that happens to contain digits.
    param([string]$Target, [string]$Description)
    $set  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $text = "$Target`n$Description"
    # PIDs. Only from the structured "PID:<n>" form the engine emits — never a bare
    # number, which would link every finding that mentions a byte count.
    foreach ($m in [regex]::Matches($Target, 'PID:(\d+)')) { [void]$set.Add("pid:$($m.Groups[1].Value)") }
    # Absolute file paths with an extension — drive-letter AND UNC. The UNC form is not
    # optional: lateral-movement and share-worm findings name their artifacts as
    # \\server\share\payload.exe, and a drive-letter-only pattern would silently refuse to
    # correlate the entire lateral half of a chain.
    foreach ($m in [regex]::Matches($text, '(?i)\b[A-Z]:\\[^\s"''|,;<>]+\.[A-Za-z0-9]{1,6}\b')) {
        [void]$set.Add("file:$($m.Value.ToLower())")
    }
    foreach ($m in [regex]::Matches($text, '(?i)\\\\[^\s"''|,;<>\\]+\\[^\s"''|,;<>]+\.[A-Za-z0-9]{1,6}\b')) {
        [void]$set.Add("file:$($m.Value.ToLower())")
    }
    # Registry keys, both provider (HKLM:\) and reg.exe (HKLM\) spellings, normalised.
    foreach ($m in [regex]::Matches($text, '(?i)\bHK(LM|CU|CR|U|EY_[A-Z_]+):?\\[^\s"''|,;<>]+')) {
        [void]$set.Add("reg:$(($m.Value -replace ':\\','\').ToLower())")
    }
    # Domains and IPv4 literals.
    foreach ($m in [regex]::Matches($text, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) { [void]$set.Add("net:$($m.Value)") }
    foreach ($m in [regex]::Matches($text, '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|xyz|top|info|biz|online|shop|site|club|icu|cc|io|me)\b')) {
        [void]$set.Add("net:$($m.Value.ToLower())")
    }
    return ,$set
}

function Get-ScytheSeverityWeight {
    param([string]$Severity)
    switch ("$Severity") {
        'CRITICAL' { 10 } 'HIGH' { 6 } 'POSSIBLE' { 2 } default { 0 }
    }
}

if ($PhasePlan.Hunt) {
    trap { Write-RecoveredError $_; continue }   # localize faults: resume at next phase, not end-of-group

    # ── PHASE 160: ATTACK-CHAIN CORRELATION ───────────────────────────────────
    Show-PhaseHeader "PHASE 160" "ATTACK-CHAIN CORRELATION & SCORING" "SYNTHESIS"
    Out-Typewriter "LINKING FINDINGS THAT SHARE A FILE, PROCESS, REGISTRY KEY OR NETWORK PEER..." "HUNT"

    # Snapshot first: this phase ADDS findings, and enumerating a collection while it
    # grows throws (and would cost the rest of the module through the trap).
    $ccAll = @($global:AuditFindings | Where-Object { "$($_.Severity)" -ne 'INFO' })
    $ccN   = $ccAll.Count
    if ($ccN -lt 2) {
        Out-Typewriter "  -> NOTHING TO CORRELATE ($ccN actionable finding(s))." "OK"
    } else {
        # Entity index, then union-find over it. Cheap and order-independent.
        $ccEnt    = New-Object 'System.Collections.Generic.List[object]'
        $ccByEnt  = @{}
        for ($i = 0; $i -lt $ccN; $i++) {
            $e = Get-ScytheEntities -Target "$($ccAll[$i].Target)" -Description "$($ccAll[$i].Description)"
            $ccEnt.Add($e)
            foreach ($k in $e) {
                if (-not $ccByEnt.ContainsKey($k)) { $ccByEnt[$k] = New-Object 'System.Collections.Generic.List[int]' }
                $ccByEnt[$k].Add($i)
            }
        }
        $parent = New-Object int[] $ccN
        for ($i = 0; $i -lt $ccN; $i++) { $parent[$i] = $i }
        # Iterative find with path compression — recursion in PS is slow and stack-limited.
        function Get-ScytheRoot { param([int]$X)
            $r = $X
            while ($parent[$r] -ne $r) { $r = $parent[$r] }
            while ($parent[$X] -ne $r) { $n = $parent[$X]; $parent[$X] = $r; $X = $n }
            return $r
        }
        foreach ($k in $ccByEnt.Keys) {
            $members = $ccByEnt[$k]
            # An entity shared by a very large number of findings is not a link, it is a
            # common noun — 'C:\Windows\System32\cmd.exe' appears in dozens of unrelated
            # descriptions. Linking on it would fuse the whole scan into one chain.
            if ($members.Count -lt 2 -or $members.Count -gt 12) { continue }
            $a = Get-ScytheRoot $members[0]
            for ($j = 1; $j -lt $members.Count; $j++) {
                $b = Get-ScytheRoot $members[$j]
                if ($a -ne $b) { $parent[$b] = $a }
            }
        }
        $ccGroups = @{}
        for ($i = 0; $i -lt $ccN; $i++) {
            $r = Get-ScytheRoot $i
            if (-not $ccGroups.ContainsKey($r)) { $ccGroups[$r] = New-Object 'System.Collections.Generic.List[int]' }
            $ccGroups[$r].Add($i)
        }

        $ccReported = 0
        $ccRanked = @($ccGroups.Keys | ForEach-Object {
            $idx  = $ccGroups[$_]
            if ($idx.Count -lt 2) { return }
            $score = 0; $tt = @{}; $stages = @{}
            foreach ($i in $idx) {
                $f = $ccAll[$i]
                $score += (Get-ScytheSeverityWeight "$($f.Severity)")
                $tt["$($f.ThreatType)"] = $true
                foreach ($sp in @($KILLCHAIN_STAGES)) {
                    if ("$($f.ThreatType) $($f.Group) $($f.Phase)" -match "$($sp.pattern)") { $stages["$($sp.stage)"] = $true }
                }
            }
            # A chain spanning several kill-chain stages is an incident; several findings
            # about one file in one stage is just one artifact described several ways.
            $score += (($tt.Keys.Count - 1) * 3)
            $score += (($stages.Keys.Count) * 5)
            [pscustomobject]@{ Root=$_; Idx=$idx; Score=$score; Types=@($tt.Keys); Stages=@($stages.Keys) }
        } | Where-Object { $_ } | Sort-Object -Property Score -Descending)

        foreach ($chain in $ccRanked) {
            if ($ccReported -ge 12) { break }
            if ($chain.Score -lt 14) { continue }
            $ccReported++
            $members  = @($chain.Idx | ForEach-Object { $ccAll[$_] })
            $worst    = @('CRITICAL','HIGH','POSSIBLE') | Where-Object { $s = $_; @($members | Where-Object { "$($_.Severity)" -eq $s }).Count -gt 0 } | Select-Object -First 1
            $chainSev = if ("$worst" -eq 'CRITICAL' -or "$worst" -eq 'HIGH') { $SEV_HIGH } else { $SEV_POSSIBLE }
            $lines    = @($members | ForEach-Object { "[$($_.Severity)] $($_.Phase) — $($_.ThreatType): $($_.Target)" })
            $shared   = @()
            foreach ($k in $ccByEnt.Keys) {
                $mm = $ccByEnt[$k]
                if ($mm.Count -ge 2 -and $mm.Count -le 12 -and (Get-ScytheRoot $mm[0]) -eq $chain.Root) { $shared += $k }
            }
            $sharedTxt = if ($shared.Count) { ($shared | Select-Object -First 6) -join '; ' } else { 'n/a' }
            Out-Typewriter "  -> CHAIN (score $($chain.Score)): $($members.Count) findings across $(@($chain.Stages).Count) kill-chain stage(s)" "CRIT"
            foreach ($ln in ($lines | Select-Object -First 6)) { Out-Typewriter "       $ln" "WARN" }
            Add-Finding -ID "CHAIN160_$($chain.Root)_$($chain.Score)" -Phase "PHASE 160" `
                -ThreatType "Correlated Attack Chain" -Severity $chainSev `
                -Description "CORRELATED CHAIN — score $($chain.Score), $($members.Count) related findings spanning $(@($chain.Stages).Count) kill-chain stage(s) [$(@($chain.Stages) -join ', ')] and $(@($chain.Types).Count) threat type(s) [$(@($chain.Types) -join ', ')]. These findings were reported separately by different phases but refer to the same real-world objects: $sharedTxt. MEMBERS: $($lines -join ' || ') — Work this as ONE incident rather than as $($members.Count) unrelated alerts. The shared objects above are where to start; a chain that spans delivery, persistence and command-and-control is an intrusion, not a collection of coincidences. Chain scoring is heuristic and links on shared file paths, PIDs, registry keys and network peers, so confirm the relationship before you act on it." `
                -Target "Correlated chain of $($members.Count) findings" -FixAction "Info" -Group "Attack Chain"
        }
        if ($ccReported -eq 0) {
            Out-Typewriter "  -> NO CORRELATED CHAINS ABOVE THE REPORTING THRESHOLD ACROSS $ccN FINDINGS." "OK"
        } else {
            Out-Typewriter "  -> $ccReported CORRELATED CHAIN(S) REPORTED." "WARN"
        }
    }
    Stop-PhaseTiming

    # ── PHASE 161: PATIENT ZERO / EARLIEST ARTIFACT ───────────────────────────
    Show-PhaseHeader "PHASE 161" "PATIENT ZERO — EARLIEST ARTIFACT ON DISK" "SYNTHESIS"
    Out-Typewriter "RESOLVING FILE ENTITIES TO THEIR REAL CREATION TIMES..." "HUNT"
    # The finding list is ordered by PHASE, which says nothing about when anything
    # happened. Resolve every file an actionable finding names and sort by the
    # filesystem's own timestamps to get an ordering that reflects the intrusion.
    $pzSeen  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $pzItems = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in @($global:AuditFindings | Where-Object { "$($_.Severity)" -ne 'INFO' })) {
        foreach ($k in (Get-ScytheEntities -Target "$($f.Target)" -Description "$($f.Description)")) {
            if (-not $k.StartsWith('file:')) { continue }
            $path = $k.Substring(5)
            if (-not $pzSeen.Add($path)) { continue }
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $fi = $null
            try { $fi = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue } catch {}
            if ($null -eq $fi -or $fi.PSIsContainer) { continue }
            # Phase 139 exists because this timestamp is attacker-writable. Use the
            # EARLIER of creation and last-write: backdating usually moves one, not both.
            $when = if ($fi.CreationTimeUtc -lt $fi.LastWriteTimeUtc) { $fi.CreationTimeUtc } else { $fi.LastWriteTimeUtc }
            $pzItems.Add([pscustomobject]@{ Path=$path; When=$when; Sev="$($f.Severity)"; Phase="$($f.Phase)"; Type="$($f.ThreatType)" })
        }
    }
    if ($pzItems.Count -eq 0) {
        Out-Typewriter "  -> NO ACTIONABLE FINDING RESOLVES TO A FILE STILL ON DISK." "OK"
    } else {
        $pzSorted = @($pzItems | Sort-Object -Property When)
        $pz = $pzSorted[0]
        Out-Typewriter "  -> EARLIEST ARTIFACT: $($pz.When.ToString('yyyy-MM-dd HH:mm:ss')) UTC — $($pz.Path)" "CRIT"
        foreach ($it in ($pzSorted | Select-Object -First 5)) {
            Out-Typewriter "       $($it.When.ToString('yyyy-MM-dd HH:mm:ss'))  [$($it.Sev)] $($it.Path)" "WARN"
        }
        $pzList = @($pzSorted | Select-Object -First 8 | ForEach-Object { "$($_.When.ToString('yyyy-MM-dd HH:mm:ss'))Z [$($_.Sev)] $($_.Phase) $($_.Path)" })
        Add-Finding -ID "PZ161_EARLIEST" -Phase "PHASE 161" `
            -ThreatType "Incident Timeline" -Severity $SEV_INFO `
            -Description "EARLIEST ARTIFACT among $($pzItems.Count) files named by actionable findings: '$($pz.Path)', dated $($pz.When.ToString('yyyy-MM-dd HH:mm:ss')) UTC, found by $($pz.Phase) as $($pz.Type). If this intrusion has a single point of entry it is most likely at or before that moment, so that is where to pull email, proxy and EDR logs for. FIRST EIGHT BY AGE: $($pzList -join ' || ') — TWO CAVEATS, BOTH IMPORTANT. File timestamps are attacker-writable (that is exactly what phase 139 looks for), so read this alongside any timestamp-tampering findings; and this only sees files that still EXIST, so an artifact already deleted by the attacker or by an AV product will not appear here at all." `
            -Target "$($pz.Path)" -FixAction "Info" -Group "Incident Timeline"
    }
    Stop-PhaseTiming

    # ── PHASE 162: SUPER-TIMELINE EXPORT ──────────────────────────────────────
    Show-PhaseHeader "PHASE 162" "INCIDENT TIMELINE EXPORT" "SYNTHESIS"
    Out-Typewriter "WRITING A TIME-ORDERED EVIDENCE TIMELINE..." "HUNT"
    if ($pzItems.Count -eq 0) {
        Out-Typewriter "  -> NO RESOLVABLE ARTIFACTS — TIMELINE NOT WRITTEN." "OK"
    } else {
        $tlPath = Join-Path $OUT_ROOT "KrakenTimeline_$STAMP.csv"
        try {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('TimestampUTC,Severity,Phase,ThreatType,Artifact')
            foreach ($it in @($pzItems | Sort-Object -Property When)) {
                # ConvertTo-CsvSafeCell, not raw quoting: correct CSV quoting does NOT stop
                # Excel evaluating a leading = + - @ as a formula, and mailing an exported
                # findings CSV to a client is this product's actual workflow (audit H8).
                $row = @(
                    (ConvertTo-CsvSafeCell $it.When.ToString('yyyy-MM-dd HH:mm:ss')),
                    (ConvertTo-CsvSafeCell "$($it.Sev)"),
                    (ConvertTo-CsvSafeCell "$($it.Phase)"),
                    (ConvertTo-CsvSafeCell "$($it.Type)"),
                    (ConvertTo-CsvSafeCell "$($it.Path)")
                ) -join ','
                [void]$sb.AppendLine($row)
            }
            [System.IO.File]::WriteAllText($tlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
            Out-Typewriter "  -> TIMELINE WRITTEN: $tlPath ($($pzItems.Count) events)" "OK"
            Write-Log "TIMELINE: $tlPath ($($pzItems.Count) events)"
            Add-Finding -ID "TL162_EXPORT" -Phase "PHASE 162" `
                -ThreatType "Incident Timeline" -Severity $SEV_INFO `
                -Description "A time-ordered timeline of $($pzItems.Count) artifact(s) named by actionable findings was written to '$tlPath'. Each row is a file that still exists on disk, stamped with the earlier of its creation and last-write time, so the ordering reflects the intrusion rather than the order the phases happened to run in. Open it alongside the findings report when reconstructing what happened. It is a starting timeline, not a forensic super-timeline: it does not include MFT, USN journal, event log or prefetch entries, and it cannot show artifacts that were deleted before the scan." `
                -Target $tlPath -FixAction "Info" -Group "Incident Timeline"
        } catch {
            Out-Typewriter "  -> TIMELINE EXPORT FAILED: $($_.Exception.Message)" "WARN"
        }
    }
    Stop-PhaseTiming
}
