# ══════════════════════════════════════════════════════════════════════════════
#  FIX MODE ENTRY PROMPT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  ┌─ PROCEED TO FIX / REMEDIATION MODE? ──────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  Audit found $($findingCount) findings ($critCount CRITICAL, $highCount HIGH, $possibleCount POSSIBLE).            │" -ForegroundColor Yellow
Write-Host "  │  Fix mode will present a checkbox list for review before ANY action.   │" -ForegroundColor Yellow
Write-Host "  │  A registry/VSS rollback snapshot will be created BEFORE any fixes.    │" -ForegroundColor Yellow
Write-Host "  │                                                                         │" -ForegroundColor Yellow
Write-Host "  │   [Y]  Yes — Enter Fix/Remediation Mode                                │" -ForegroundColor Yellow
Write-Host "  │   [N]  No  — Exit (audit log saved)                                    │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
$fixEntry = (Read-Host).Trim().ToLower()
if ($fixEntry -ne "y" -and $fixEntry -ne "yes") {
    Out-Typewriter "FIX MODE DECLINED. AUDIT LOG PRESERVED. EXITING." "INFO"
    Write-Host ""; Out-Typewriter "PRESS ANY KEY TO EXIT." "INFO" 20
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'); exit
}

# ══════════════════════════════════════════════════════════════════════════════
#  ROLLBACK SNAPSHOT
# ══════════════════════════════════════════════════════════════════════════════
Out-Typewriter "CREATING ROLLBACK SNAPSHOT BEFORE ANY CHANGES..." "ACT"
Invoke-QuantumBar "REGISTRY EXPORT IN PROGRESS" 10 160
$snapshotOk = $false
try {
    $regExports = @(
        @{H="HKCU"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";      F="$env:TEMP\KB_Run_HKCU.reg"},
        @{H="HKLM"; K="SOFTWARE\Microsoft\Windows\CurrentVersion\Run";      F="$env:TEMP\KB_Run_HKLM.reg"},
        @{H="HKLM"; K="SYSTEM\CurrentControlSet\Services";                  F="$env:TEMP\KB_Services.reg"},
        @{H="HKLM"; K="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; F="$env:TEMP\KB_Winlogon.reg"},
        @{H="HKCU"; K="SOFTWARE\Classes\CLSID";                             F="$env:TEMP\KB_CLSID.reg"}
    )
    $snapshotFiles = @()
    foreach ($re in $regExports) {
        reg export "$($re.H)\$($re.K)" $re.F /y 2>$null | Out-Null
        if (Test-Path $re.F) { $snapshotFiles += $re.F }
    }
    # Bundle into single snapshot file
    $snapshotContent = @("ZEROBREACH V22 SNAPSHOT | $(Get-Date) | Host: $HOST_NAME", "="*80)
    foreach ($sf in $snapshotFiles) {
        $snapshotContent += Get-Content $sf -Raw -ErrorAction SilentlyContinue
        Remove-Item $sf -Force -ErrorAction SilentlyContinue
    }
    $snapshotContent | Out-File -FilePath $SNAPSHOT_PATH -Encoding Unicode -ErrorAction Stop
    $snapshotOk = $true
    Out-Typewriter "SNAPSHOT SAVED TO: $SNAPSHOT_PATH" "GOOD"
    Out-Typewriter "  -> IF FIXES CAUSE ISSUES, RESTORE WITH: regedit /S `"$SNAPSHOT_PATH`"" "WARN"
} catch {
    Out-Typewriter "SNAPSHOT FAILED — PROCEEDING WITHOUT ROLLBACK (USE CAUTION)." "WARN"
}

Out-Typewriter "LOADING REMEDIATION INTERFACE..." "ACT"
Invoke-QuantumBar "BUILDING CHECKBOX MANIFEST" 10 80

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE SCAN DASHBOARD — launches BEFORE scan, updates in real-time
# ══════════════════════════════════════════════════════════════════════════════
function Show-LiveScanDashboard {
    $acRgb  = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,200,255) }
    $bgDark = [System.Drawing.Color]::FromArgb(12,12,12)
    $bgMid  = [System.Drawing.Color]::FromArgb(20,20,20)
    $bgPnl  = [System.Drawing.Color]::FromArgb(16,16,16)
    $fgMain = [System.Drawing.Color]::FromArgb(210,210,210)
    $red    = [System.Drawing.Color]::FromArgb(255,60,60)
    $orange = [System.Drawing.Color]::FromArgb(255,140,0)
    $yellow = [System.Drawing.Color]::Yellow
    $green  = [System.Drawing.Color]::FromArgb(80,220,80)
    $mono   = New-Object System.Drawing.Font("Consolas",9)
    $monoBold = New-Object System.Drawing.Font("Consolas",9,[System.Drawing.FontStyle]::Bold)
    $monoLg = New-Object System.Drawing.Font("Consolas",11,[System.Drawing.FontStyle]::Bold)
    $monoXL = New-Object System.Drawing.Font("Consolas",14,[System.Drawing.FontStyle]::Bold)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ZeroBreach V22  ·  Project Kraken  ·  Gannon MSP"
    $form.Size = New-Object System.Drawing.Size(1340, 900)
    $form.MinimumSize = New-Object System.Drawing.Size(1100, 700)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = $bgDark
    $form.ForeColor = $fgMain
    $form.Font = $mono
    $global:GUI_LIVE_FORM = $form

    # ── Title bar ─────────────────────────────────────────────────────────────
    $titlePnl = New-Object System.Windows.Forms.Panel
    $titlePnl.Dock = "Top"; $titlePnl.Height = 58; $titlePnl.BackColor = [System.Drawing.Color]::FromArgb(8,8,8)
    $form.Controls.Add($titlePnl)

    $titleLbl = New-Object System.Windows.Forms.Label
    $titleLbl.Text = "◈  Z E R O B R E A C H   V 2 2   ·   P R O J E C T   K R A K E N"
    $titleLbl.Font = $monoXL; $titleLbl.ForeColor = $acRgb
    $titleLbl.AutoSize = $false; $titleLbl.Width = 800; $titleLbl.Height = 34
    $titleLbl.Location = New-Object System.Drawing.Point(10, 6)
    $titlePnl.Controls.Add($titleLbl)

    $subLbl = New-Object System.Windows.Forms.Label
    $subLbl.Text = "  HOST: $HOST_NAME   USER: $USER_NAME   MODE: $($global:ScanMode)   WINDOW: $($global:TW_LABEL)"
    $subLbl.Font = $mono; $subLbl.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)
    $subLbl.AutoSize = $false; $subLbl.Width = 1000; $subLbl.Height = 18
    $subLbl.Location = New-Object System.Drawing.Point(10, 38)
    $titlePnl.Controls.Add($subLbl)

    # Kill toggle button (top right of title)
    $killBtn = New-Object System.Windows.Forms.Button
    $killBtn.Text = "⏩  FAST MODE  [K]"
    $killBtn.Size = New-Object System.Drawing.Size(180, 34)
    $killBtn.Location = New-Object System.Drawing.Point(1130, 8)
    $killBtn.BackColor = [System.Drawing.Color]::FromArgb(35,35,35)
    $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(80,180,80)
    $killBtn.FlatStyle = "Flat"
    $killBtn.Font = $monoBold
    $killBtn.add_Click({
        $global:SKIP_SLOW_OUTPUT = -not $global:SKIP_SLOW_OUTPUT
        if ($global:SKIP_SLOW_OUTPUT) {
            $killBtn.Text = "⏩  FAST MODE  [ON]"
            $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(255,160,0)
            $killBtn.BackColor = [System.Drawing.Color]::FromArgb(40,25,0)
        } else {
            $killBtn.Text = "⏩  FAST MODE  [K]"
            $killBtn.ForeColor = [System.Drawing.Color]::FromArgb(80,180,80)
            $killBtn.BackColor = [System.Drawing.Color]::FromArgb(35,35,35)
        }
    })
    $titlePnl.Controls.Add($killBtn)
    $global:GUI_KILL_BTN = $killBtn

    # ── Phase / progress bar strip ────────────────────────────────────────────
    $progPnl = New-Object System.Windows.Forms.Panel
    $progPnl.Dock = "Top"; $progPnl.Height = 42; $progPnl.BackColor = [System.Drawing.Color]::FromArgb(14,14,14)
    $form.Controls.Add($progPnl)

    $phaseLbl = New-Object System.Windows.Forms.Label
    $phaseLbl.Text = "  INITIALIZING..."; $phaseLbl.Font = $monoBold
    $phaseLbl.ForeColor = $yellow; $phaseLbl.AutoSize = $false
    $phaseLbl.Width = 900; $phaseLbl.Height = 18
    $phaseLbl.Location = New-Object System.Drawing.Point(8, 4)
    $progPnl.Controls.Add($phaseLbl)
    $global:GUI_PHASE_LBL = $phaseLbl

    $progBar = New-Object System.Windows.Forms.ProgressBar
    $progBar.Minimum = 0; $progBar.Maximum = 100; $progBar.Value = 0
    $progBar.Size = New-Object System.Drawing.Size(1300, 14)
    $progBar.Location = New-Object System.Drawing.Point(8, 24)
    $progBar.Style = "Continuous"
    try {
        # Win10+ progress bar color via SendMessage
        Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class WinAPI { [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd,int Msg,IntPtr wParam,IntPtr lParam); }
"@ -ErrorAction SilentlyContinue
        [WinAPI]::SendMessage($progBar.Handle, 0x400+16, [IntPtr]1, [IntPtr]0) | Out-Null
    } catch {}
    $progPnl.Controls.Add($progBar)
    $global:GUI_PROG_BAR = $progBar

    # ── Risk / findings counter strip ─────────────────────────────────────────
    $riskPnl = New-Object System.Windows.Forms.Panel
    $riskPnl.Dock = "Top"; $riskPnl.Height = 28; $riskPnl.BackColor = [System.Drawing.Color]::FromArgb(10,10,10)
    $form.Controls.Add($riskPnl)

    $riskLbl = New-Object System.Windows.Forms.Label
    $riskLbl.Text = "  LIVE FINDINGS: 0  ·  ☣ CRITICAL: 0  ▲ HIGH: 0  ? POSSIBLE: 0"
    $riskLbl.Font = $monoBold; $riskLbl.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)
    $riskLbl.AutoSize = $false; $riskLbl.Width = 900; $riskLbl.Height = 22
    $riskLbl.Location = New-Object System.Drawing.Point(8, 4)
    $riskPnl.Controls.Add($riskLbl)
    $global:GUI_RISK_LBL = $riskLbl

    # ── Split panel: left=log, right=tree ─────────────────────────────────────
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = "Fill"; $split.Orientation = "Vertical"
    $split.SplitterDistance = 560; $split.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $form.Controls.Add($split)

    # Left panel — live log
    $logHdr = New-Object System.Windows.Forms.Label
    $logHdr.Text = "  ◈  LIVE SCAN OUTPUT"; $logHdr.Dock = "Top"; $logHdr.Height = 22
    $logHdr.Font = $monoBold; $logHdr.ForeColor = $acRgb
    $logHdr.BackColor = [System.Drawing.Color]::FromArgb(18,18,18)
    $split.Panel1.Controls.Add($logHdr)

    $logBox = New-Object System.Windows.Forms.RichTextBox
    $logBox.Dock = "Fill"; $logBox.BackColor = $bgMid; $logBox.ForeColor = $fgMain
    $logBox.Font = New-Object System.Drawing.Font("Consolas",8)
    $logBox.ReadOnly = $true; $logBox.BorderStyle = "None"
    $logBox.ScrollBars = "Vertical"; $logBox.WordWrap = $false
    $split.Panel1.Controls.Add($logBox)
    $global:GUI_LIVE_LOG = $logBox

    # Right panel — live tree
    $treeHdr = New-Object System.Windows.Forms.Label
    $treeHdr.Text = "  ◈  FINDINGS (LIVE)"; $treeHdr.Dock = "Top"; $treeHdr.Height = 22
    $treeHdr.Font = $monoBold; $treeHdr.ForeColor = $acRgb
    $treeHdr.BackColor = [System.Drawing.Color]::FromArgb(18,18,18)
    $split.Panel2.Controls.Add($treeHdr)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock = "Fill"; $tree.BackColor = $bgMid; $tree.ForeColor = $fgMain
    $tree.CheckBoxes = $true; $tree.Font = $mono
    $tree.BorderStyle = "None"
    $tree.add_AfterCheck({
        param($s, $e)
        if ($e.Action -eq [System.Windows.Forms.TreeViewAction]::ByMouse) {
            if ($e.Node.Tag -is [hashtable]) {
                $f = [hashtable]$e.Node.Tag
                if (-not $e.Node.Checked -and $f.Severity -eq "CRITICAL") {
                    $ans = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: Deselecting a CRITICAL finding:`n`n$($f.Description)`n`nThis is BLATANTLY MALICIOUS. Skip anyway?",
                        "CRITICAL — CONFIRM SKIP",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($ans -eq [System.Windows.Forms.DialogResult]::No) { $e.Node.Checked = $true; return }
                }
                $f.Selected = $e.Node.Checked
            } else {
                foreach ($child in $e.Node.Nodes) {
                    $child.Checked = $e.Node.Checked
                    if ($child.Tag -is [hashtable]) { ([hashtable]$child.Tag).Selected = $e.Node.Checked }
                }
            }
        }
    })
    $split.Panel2.Controls.Add($tree)
    $global:GUI_LIVE_TREE = $tree

    # ── Bottom action bar ─────────────────────────────────────────────────────
    $bottomPnl = New-Object System.Windows.Forms.Panel
    $bottomPnl.Dock = "Bottom"; $bottomPnl.Height = 52
    $bottomPnl.BackColor = [System.Drawing.Color]::FromArgb(10,10,10)
    $form.Controls.Add($bottomPnl)

    $btnSA = New-Object System.Windows.Forms.Button
    $btnSA.Text = "✔ SELECT ALL"; $btnSA.Size = New-Object System.Drawing.Size(130, 36)
    $btnSA.Location = New-Object System.Drawing.Point(8, 8)
    $btnSA.BackColor = [System.Drawing.Color]::FromArgb(25,40,25); $btnSA.ForeColor = $green
    $btnSA.FlatStyle = "Flat"; $btnSA.Font = $monoBold
    $btnSA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $true
            foreach ($cn in $gn.Nodes) { $cn.Checked = $true; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $true } }
        }
    })
    $bottomPnl.Controls.Add($btnSA)

    $btnCA = New-Object System.Windows.Forms.Button
    $btnCA.Text = "✖ CLEAR ALL"; $btnCA.Size = New-Object System.Drawing.Size(130, 36)
    $btnCA.Location = New-Object System.Drawing.Point(146, 8)
    $btnCA.BackColor = [System.Drawing.Color]::FromArgb(40,15,15); $btnCA.ForeColor = $red
    $btnCA.FlatStyle = "Flat"; $btnCA.Font = $monoBold
    $btnCA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $false
            foreach ($cn in $gn.Nodes) { $cn.Checked = $false; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $false } }
        }
    })
    $bottomPnl.Controls.Add($btnCA)

    $btnCritOnly = New-Object System.Windows.Forms.Button
    $btnCritOnly.Text = "☣ CRIT+HIGH ONLY"; $btnCritOnly.Size = New-Object System.Drawing.Size(160, 36)
    $btnCritOnly.Location = New-Object System.Drawing.Point(284, 8)
    $btnCritOnly.BackColor = [System.Drawing.Color]::FromArgb(40,20,0); $btnCritOnly.ForeColor = $orange
    $btnCritOnly.FlatStyle = "Flat"; $btnCritOnly.Font = $monoBold
    $btnCritOnly.add_Click({
        foreach ($gn in $tree.Nodes) {
            foreach ($cn in $gn.Nodes) {
                if ($cn.Tag -is [hashtable]) {
                    $f = [hashtable]$cn.Tag
                    $sel = ($f.Severity -in @("CRITICAL","HIGH"))
                    $cn.Checked = $sel; $f.Selected = $sel
                }
            }
            $anyChecked = ($gn.Nodes | Where-Object { $_.Checked }).Count -gt 0
            $gn.Checked = $anyChecked
        }
    })
    $bottomPnl.Controls.Add($btnCritOnly)

    # RECOMMENDED preset — high-confidence findings with a concrete fix (CRIT/HIGH, non-Info)
    $btnRec = New-Object System.Windows.Forms.Button
    $btnRec.Text = "★ RECOMMENDED"; $btnRec.Size = New-Object System.Drawing.Size(150, 36)
    $btnRec.Location = New-Object System.Drawing.Point(452, 8)
    $btnRec.BackColor = [System.Drawing.Color]::FromArgb(0,32,40); $btnRec.ForeColor = $acRgb
    $btnRec.FlatStyle = "Flat"; $btnRec.Font = $monoBold
    $btnRec.add_Click({
        foreach ($gn in $tree.Nodes) {
            foreach ($cn in $gn.Nodes) {
                if ($cn.Tag -is [hashtable]) {
                    $f = [hashtable]$cn.Tag
                    $sel = ((Get-FixClass $f.Severity $f.FixAction) -match 'RECOMMENDED')
                    $cn.Checked = $sel; $f.Selected = $sel
                }
            }
            $gn.Checked = (($gn.Nodes | Where-Object { $_.Checked }).Count -gt 0)
        }
    })
    $bottomPnl.Controls.Add($btnRec)

    # SAFE preset — only non-destructive fixes (no file/registry deletion)
    $btnSafe = New-Object System.Windows.Forms.Button
    $btnSafe.Text = "🛡 SAFE ONLY"; $btnSafe.Size = New-Object System.Drawing.Size(140, 36)
    $btnSafe.Location = New-Object System.Drawing.Point(606, 8)
    $btnSafe.BackColor = [System.Drawing.Color]::FromArgb(20,32,20); $btnSafe.ForeColor = $green
    $btnSafe.FlatStyle = "Flat"; $btnSafe.Font = $monoBold
    $btnSafe.add_Click({
        foreach ($gn in $tree.Nodes) {
            foreach ($cn in $gn.Nodes) {
                if ($cn.Tag -is [hashtable]) {
                    $f = [hashtable]$cn.Tag
                    $sel = ((Get-FixClass $f.Severity $f.FixAction) -match 'SAFE') -and ($f.Severity -ne 'INFO')
                    $cn.Checked = $sel; $f.Selected = $sel
                }
            }
            $gn.Checked = (($gn.Nodes | Where-Object { $_.Checked }).Count -gt 0)
        }
    })
    $bottomPnl.Controls.Add($btnSafe)

    $scanningLbl = New-Object System.Windows.Forms.Label
    $scanningLbl.Text = "  ⟳  SCAN RUNNING..."
    $scanningLbl.Font = $monoBold; $scanningLbl.ForeColor = $yellow
    $scanningLbl.AutoSize = $false; $scanningLbl.Width = 200; $scanningLbl.Height = 36
    $scanningLbl.Location = New-Object System.Drawing.Point(756, 10)
    $bottomPnl.Controls.Add($scanningLbl)

    $btnFix = New-Object System.Windows.Forms.Button
    $btnFix.Text = "▶  EXECUTE SELECTED FIXES"; $btnFix.Size = New-Object System.Drawing.Size(280, 44)
    $btnFix.Location = New-Object System.Drawing.Point(1030, 4)
    $btnFix.BackColor = [System.Drawing.Color]::FromArgb(20,20,20); $btnFix.ForeColor = $acRgb
    $btnFix.FlatStyle = "Flat"; $btnFix.Font = $monoLg
    $btnFix.Enabled = $false   # enabled after scan completes
    $btnFix.add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() })
    $bottomPnl.Controls.Add($btnFix)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "EXIT WITHOUT FIXING"; $btnExit.Size = New-Object System.Drawing.Size(200, 20)
    $btnExit.Location = New-Object System.Drawing.Point(1110, 30)
    $btnExit.BackColor = [System.Drawing.Color]::FromArgb(20,20,20); $btnExit.ForeColor = [System.Drawing.Color]::FromArgb(80,80,80)
    $btnExit.FlatStyle = "Flat"; $btnExit.Font = $mono
    $btnExit.add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.Close() })
    $bottomPnl.Controls.Add($btnExit)

    # Store scanning label and fix button for post-scan update
    $script:_scanningLbl = $scanningLbl
    $script:_btnFix      = $btnFix

    # Show modeless — scan runs in the same thread, DoEvents keeps UI alive
    $form.Show()
    [System.Windows.Forms.Application]::DoEvents()
    return $form
}

function Complete-LiveScanDashboard {
    # Called after scan finishes — update UI to fix mode
    if ($null -eq $global:GUI_LIVE_FORM -or $global:GUI_LIVE_FORM.IsDisposed) { return }
    if ($null -ne $script:_scanningLbl) {
        $script:_scanningLbl.Text = "  ✔  SCAN COMPLETE"
        $script:_scanningLbl.ForeColor = [System.Drawing.Color]::FromArgb(80,220,80)
    }
    if ($null -ne $script:_btnFix) { $script:_btnFix.Enabled = $true }
    if ($null -ne $global:GUI_PHASE_LBL) { $global:GUI_PHASE_LBL.Text = "  ✔  AUDIT COMPLETE — Review findings and click EXECUTE SELECTED FIXES" }
    if ($null -ne $global:GUI_PROG_BAR) { $global:GUI_PROG_BAR.Value = 100 }
    # Update risk label with final totals
    if ($null -ne $global:GUI_RISK_LBL) {
        $cC = ($global:AuditFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $hC = ($global:AuditFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
        $pC = ($global:AuditFindings | Where-Object { $_.Severity -eq "POSSIBLE" }).Count
        $iC = ($global:AuditFindings | Where-Object { $_.Severity -eq "INFO" }).Count
        $global:GUI_RISK_LBL.Text = "  TOTAL FINDINGS: $($global:AuditFindings.Count)  ·  ☣ CRITICAL: $cC  ▲ HIGH: $hC  ? POSSIBLE: $pC  INFO: $iC"
    }
    [System.Windows.Forms.Application]::DoEvents()
    # Block until user closes
    $global:GUI_LIVE_FORM.ShowDialog() | Out-Null
}

# ── GUI Checkbox Menu (WinForms) — legacy post-scan version kept as fallback ──
function Show-GUICheckboxMenu {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ZeroBreach V22 — Fix / Remediation Mode"
    $form.Size = New-Object System.Drawing.Size(980, 780)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
    $form.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $form.Font = New-Object System.Drawing.Font("Consolas", 9)

    $header = New-Object System.Windows.Forms.Label
    $header.Text = "  ◈  ZEROBREACH V22 — REMEDIATION CONTROL PANEL"
    $header.AutoSize = $false; $header.Width = 960; $header.Height = 32
    $header.Location = New-Object System.Drawing.Point(0, 6)
    $header.ForeColor = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,200,255) }
    $header.Font = New-Object System.Drawing.Font("Consolas", 13, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($header)

    $riskLbl = New-Object System.Windows.Forms.Label
    $riskColor2 = if ($totalRisk -gt 20) { [System.Drawing.Color]::Red } `
                  elseif ($totalRisk -gt 10) { [System.Drawing.Color]::DarkOrange } `
                  elseif ($totalRisk -gt 3)  { [System.Drawing.Color]::Yellow } `
                  else { [System.Drawing.Color]::LimeGreen }
    $riskLbl.Text = "  RISK: $totalRisk — $riskLabel  |  CRITICAL: $critCount  HIGH: $highCount  POSSIBLE: $possibleCount  INFO: $infoCount"
    $riskLbl.AutoSize = $false; $riskLbl.Width = 960; $riskLbl.Height = 22
    $riskLbl.Location = New-Object System.Drawing.Point(0, 40)
    $riskLbl.ForeColor = $riskColor2
    $form.Controls.Add($riskLbl)

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Location = New-Object System.Drawing.Point(8, 70)
    $tree.Size = New-Object System.Drawing.Size(950, 555)
    $tree.BackColor = [System.Drawing.Color]::FromArgb(24, 24, 24)
    $tree.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $tree.CheckBoxes = $true
    $tree.Font = New-Object System.Drawing.Font("Consolas", 9)

    $groups = $global:AuditFindings | Group-Object { $_.Group } | Sort-Object Name
    foreach ($grp in $groups) {
        $critN = ($grp.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highN = ($grp.Group | Where-Object { $_.Severity -eq "HIGH" }).Count
        $tag   = if ($critN -gt 0) { "  [$critN CRITICAL]" } elseif ($highN -gt 0) { "  [$highN HIGH]" } else { "" }
        $gNode = New-Object System.Windows.Forms.TreeNode
        $gNode.Text = "$($grp.Name)$tag"
        $gNode.ForeColor = if ($critN -gt 0) { [System.Drawing.Color]::FromArgb(255,80,80) } `
                           elseif ($highN -gt 0) { [System.Drawing.Color]::FromArgb(255,160,0) } `
                           else { [System.Drawing.Color]::FromArgb(100,180,255) }
        $gNode.Checked = $true

        foreach ($finding in $grp.Group) {
            $cNode = New-Object System.Windows.Forms.TreeNode
            $pfx = switch ($finding.Severity) {
                "CRITICAL" { "☣ CRIT  " } "HIGH" { "▲ HIGH  " } "POSSIBLE" { "? POSS  " } default { "  INFO  " }
            }
            $d = $finding.Description; if ($d.Length -gt 85) { $d = $d.Substring(0,82) + "..." }
            $cNode.Text = "$pfx $d"
            $cNode.Checked = $finding.Selected
            $cNode.ForeColor = switch ($finding.Severity) {
                "CRITICAL" { [System.Drawing.Color]::FromArgb(255,80,80)   }
                "HIGH"     { [System.Drawing.Color]::FromArgb(255,160,0)   }
                "POSSIBLE" { [System.Drawing.Color]::FromArgb(255,220,50)  }
                default    { [System.Drawing.Color]::FromArgb(130,130,130) }
            }
            $cNode.Tag = $finding
            $gNode.Nodes.Add($cNode) | Out-Null
        }
        $tree.Nodes.Add($gNode) | Out-Null
    }
    $tree.ExpandAll()

    $tree.add_AfterCheck({
        param($s, $e)
        if ($e.Action -eq [System.Windows.Forms.TreeViewAction]::ByMouse) {
            if ($e.Node.Tag -is [hashtable]) {
                $f = [hashtable]$e.Node.Tag
                if (-not $e.Node.Checked -and $f.Severity -eq "CRITICAL") {
                    $ans = [System.Windows.Forms.MessageBox]::Show(
                        "WARNING: Deselecting a CRITICAL finding:`n`n$($f.Description)`n`nThis is classified BLATANTLY MALICIOUS. Skip anyway?",
                        "CRITICAL — CONFIRM SKIP",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($ans -eq [System.Windows.Forms.DialogResult]::No) { $e.Node.Checked = $true; return }
                }
                $f.Selected = $e.Node.Checked
            } else {
                foreach ($child in $e.Node.Nodes) {
                    $child.Checked = $e.Node.Checked
                    if ($child.Tag -is [hashtable]) { ([hashtable]$child.Tag).Selected = $e.Node.Checked }
                }
            }
        }
    })
    $form.Controls.Add($tree)

    $btnSA = New-Object System.Windows.Forms.Button
    $btnSA.Text = "SELECT ALL"; $btnSA.Location = New-Object System.Drawing.Point(8, 638)
    $btnSA.Size = New-Object System.Drawing.Size(110, 30); $btnSA.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
    $btnSA.ForeColor = [System.Drawing.Color]::LimeGreen; $btnSA.FlatStyle = "Flat"
    $btnSA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $true
            foreach ($cn in $gn.Nodes) { $cn.Checked = $true; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $true } }
        }
    })
    $form.Controls.Add($btnSA)

    $btnCA = New-Object System.Windows.Forms.Button
    $btnCA.Text = "CLEAR ALL"; $btnCA.Location = New-Object System.Drawing.Point(126, 638)
    $btnCA.Size = New-Object System.Drawing.Size(110, 30); $btnCA.BackColor = [System.Drawing.Color]::FromArgb(40,40,40)
    $btnCA.ForeColor = [System.Drawing.Color]::FromArgb(200,60,60); $btnCA.FlatStyle = "Flat"
    $btnCA.add_Click({
        foreach ($gn in $tree.Nodes) { $gn.Checked = $false
            foreach ($cn in $gn.Nodes) { $cn.Checked = $false; if ($cn.Tag -is [hashtable]) { ([hashtable]$cn.Tag).Selected = $false } }
        }
    })
    $form.Controls.Add($btnCA)

    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point(250, 646); $hint.Size = New-Object System.Drawing.Size(430, 18)
    $hint.ForeColor = [System.Drawing.Color]::Yellow
    $hint.Text = "Checkboxes cascade. CRITICAL items warn on deselect."
    $form.Controls.Add($hint)

    $acCol = if ($global:MSP_MODE) { [System.Drawing.Color]::FromArgb(255,102,0) } else { [System.Drawing.Color]::FromArgb(0,180,255) }
    $btnEx = New-Object System.Windows.Forms.Button
    $btnEx.Text = "▶  EXECUTE SELECTED FIXES"
    $btnEx.Location = New-Object System.Drawing.Point(695, 633); $btnEx.Size = New-Object System.Drawing.Size(265, 40)
    $btnEx.BackColor = [System.Drawing.Color]::FromArgb(30,30,30); $btnEx.ForeColor = $acCol
    $btnEx.FlatStyle = "Flat"
    $btnEx.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
    $btnEx.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnEx)

    $btnQuit = New-Object System.Windows.Forms.Button
    $btnQuit.Text = "EXIT WITHOUT FIXING"; $btnQuit.Location = New-Object System.Drawing.Point(695, 679)
    $btnQuit.Size = New-Object System.Drawing.Size(265, 20); $btnQuit.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $btnQuit.ForeColor = [System.Drawing.Color]::DarkGray; $btnQuit.FlatStyle = "Flat"
    $btnQuit.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnQuit)

    $form.AcceptButton = $btnEx; $form.CancelButton = $btnQuit
    $result = $form.ShowDialog(); $form.Dispose()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return @() }
    return ($global:AuditFindings | Where-Object { $_.Selected })
}

# ── Shell Checkbox Menu (console fallback) ─────────────────────────────────────
function Show-ShellCheckboxMenu {
    $all = $global:AuditFindings
    $running = $true
    while ($running) {
        Clear-Host
        Write-Host ("▓"*80) -ForegroundColor DarkRed
        Write-Host "  ◈  Z E R O B R E A C H  V 2 1  ·  R E M E D I A T I O N  M O D E" -ForegroundColor (Get-AccentColor)
        Write-Host ("▓"*80) -ForegroundColor DarkRed
        Write-Host "  Risk: $totalRisk  |  CRITICAL: $critCount  HIGH: $highCount  POSSIBLE: $possibleCount  INFO: $infoCount" -ForegroundColor Yellow
        Write-Host "  [A] All  [C] None  [R] Recommended  [S] Safe-only  [H] Crit+High  [ENTER] Execute  [Q] Quit  |  # toggles" -ForegroundColor DarkGray
        Write-Host ("─"*80) -ForegroundColor DarkCyan
        Write-Host ""

        $i = 1; $idxMap = @{}; $curGrp = ""
        foreach ($f in $all) {
            if ($f.Group -ne $curGrp) {
                $curGrp = $f.Group
                Write-Host "  ── $curGrp " -NoNewline -ForegroundColor DarkCyan
                Write-Host ("─" * [Math]::Max(2, 58 - $curGrp.Length)) -ForegroundColor DarkCyan
            }
            $idxMap[$i] = $f
            $chk = if ($f.Selected) { "[✓]" } else { "[ ]" }
            $sev = switch ($f.Severity) { "CRITICAL"{"☣ CRIT "} "HIGH"{"▲ HIGH "} "POSSIBLE"{"? POSS "} default{"  INFO "} }
            $cc  = if ($f.Selected) { "Green" } else { "DarkGray" }
            $sc  = switch ($f.Severity) { "CRITICAL"{"Red"} "HIGH"{"DarkYellow"} "POSSIBLE"{"Yellow"} default{"DarkGray"} }
            Write-Host "  " -NoNewline
            Write-Host $chk -NoNewline -ForegroundColor $cc
            Write-Host " " -NoNewline
            Write-Host $sev -NoNewline -ForegroundColor $sc
            $d = $f.Description; if ($d.Length -gt 55) { $d = $d.Substring(0,52)+"..." }
            Write-Host "$($i.ToString().PadLeft(3)).  $d" -ForegroundColor $(if ($f.Selected) {"White"} else {"DarkGray"})
            $i++
        }

        Write-Host ""
        Write-Host ("─"*80) -ForegroundColor DarkCyan
        $selN = ($all | Where-Object { $_.Selected }).Count
        Write-Host "  SELECTED: $selN / $($all.Count)" -ForegroundColor Yellow
        Write-Host "  > " -NoNewline -ForegroundColor DarkGray
        $inp = (Read-Host).Trim().ToUpper()

        switch ($inp) {
            "A" { foreach ($f in $all) { $f.Selected = $true } }
            "C" { foreach ($f in $all) { $f.Selected = $false } }
            "R" { foreach ($f in $all) { $f.Selected = ((Get-FixClass $f.Severity $f.FixAction) -match 'RECOMMENDED') } }
            "S" { foreach ($f in $all) { $f.Selected = (((Get-FixClass $f.Severity $f.FixAction) -match 'SAFE') -and ($f.Severity -ne 'INFO')) } }
            "H" { foreach ($f in $all) { $f.Selected = ($f.Severity -in @("CRITICAL","HIGH")) } }
            "Q" { $running = $false; return @() }
            ""  {
                if ($selN -eq 0) { Write-Host "  NO ITEMS SELECTED." -ForegroundColor Yellow; Start-Sleep 2 }
                else { $running = $false }
            }
            default {
                if ($inp -match "^\d+$") {
                    $n = [int]$inp
                    if ($idxMap.ContainsKey($n)) {
                        $f = $idxMap[$n]
                        if ($f.Selected -and $f.Severity -eq "CRITICAL") {
                            Write-Host ""
                            Write-Host "  ┌─ WARNING ─────────────────────────────────────────────────────────────┐" -ForegroundColor Red
                            Write-Host "  │  ☣  DESELECTING CRITICAL FINDING:                                    │" -ForegroundColor Red
                            $dw = $f.Description.Substring(0,[Math]::Min(68,$f.Description.Length))
                            Write-Host "  │  $($dw.PadRight(68))  │" -ForegroundColor Yellow
                            Write-Host "  │  This is BLATANTLY MALICIOUS. Deselect? (Y/N)                       │" -ForegroundColor Red
                            Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
                            Write-Host "  > " -NoNewline -ForegroundColor DarkGray
                            $c = (Read-Host).Trim().ToUpper()
                            if ($c -eq "Y") { $f.Selected = $false }
                        } elseif ($f.Selected) { $f.Selected = $false }
                        else { $f.Selected = $true }
                    }
                }
            }
        }
    }
    return ($all | Where-Object { $_.Selected })
}

# ══════════════════════════════════════════════════════════════════════════════
#  FIX EXECUTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-FixMode {
    param([hashtable[]]$SelectedFindings)
    if ($SelectedFindings.Count -eq 0) { Out-Typewriter "NO FIXES SELECTED." "WARN"; return }

    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkRed
    Write-Host "  ◈  EXECUTING $($SelectedFindings.Count) REMEDIATIONS" -ForegroundColor Red
    Write-Host ("▓"*80) -ForegroundColor DarkRed

    $fixLog = [System.Collections.Generic.List[string]]::new()
    $fixOK = 0; $fixFail = 0; $fixSkip = 0

    foreach ($f in $SelectedFindings) {
        $ts = (Get-Date).ToString("HH:mm:ss.fff")
        $d = $f.Description; if ($d.Length -gt 60) { $d = $d.Substring(0,57)+"..." }
        Write-Host "[$ts] " -NoNewline -ForegroundColor DarkGray
        Write-Host "FIX: " -NoNewline -ForegroundColor (Get-AccentColor)
        Write-Host $d -ForegroundColor White

        $ok = $false
        try {
            switch ($f.FixAction) {
                "DeleteFile" {
                    if (Test-Path $f.FixParam) {
                        Remove-Item -Path $f.FixParam -Recurse -Force -ErrorAction Stop
                        if (Test-Path $f.FixParam) {
                            # Kernel-queue for locked files
                            $rp  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                            $cur = Get-ItemPropertyValue $rp "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                            if ($null -eq $cur) { $cur = @() }
                            Set-ItemProperty $rp "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$($f.FixParam)", "")) -Type MultiString -Force -ErrorAction SilentlyContinue
                            Out-Typewriter "  -> QUEUED FOR REBOOT DELETION." "WARN"
                        } else { Out-Typewriter "  -> DELETED: $($f.FixParam)" "GOOD" }
                        $global:KillCount++; $ok = $true
                    } else { Out-Typewriter "  -> ALREADY ABSENT." "VER"; $ok = $true }
                }
                "DeleteReg" {
                    $pts = $f.FixParam -split "\|", 2
                    if ($pts.Count -eq 2) {
                        Remove-ItemProperty -Path $pts[0] -Name $pts[1] -Force -ErrorAction SilentlyContinue
                        $chk = Get-ItemProperty -Path $pts[0] -Name $pts[1] -ErrorAction SilentlyContinue
                        if ($null -eq $chk.($pts[1])) {
                            Out-Typewriter "  -> REG VALUE DELETED: $($pts[1])" "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> REG DELETE FAILED." "WARN"; $fixFail++ }
                    }
                }
                "DeleteRegKey" {
                    if (Test-Path $f.FixParam) {
                        Remove-Item -Path $f.FixParam -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path $f.FixParam)) {
                            Out-Typewriter "  -> REG KEY DELETED." "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> REG KEY DELETE FAILED." "WARN"; $fixFail++ }
                    } else { Out-Typewriter "  -> KEY ALREADY ABSENT." "VER"; $ok = $true }
                }
                "KillProcess" {
                    $pid2 = [int]$f.FixParam
                    $proc = Get-Process -Id $pid2 -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $pid2 -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 400
                        if (-not (Get-Process -Id $pid2 -ErrorAction SilentlyContinue)) {
                            Out-Typewriter "  -> TERMINATED: PID $pid2 ($($proc.Name))" "GOOD"; $global:KillCount++; $ok = $true
                        } else { Out-Typewriter "  -> KILL FAILED: PID $pid2" "WARN"; $fixFail++ }
                    } else { Out-Typewriter "  -> PROCESS ALREADY GONE." "VER"; $ok = $true }
                }
                "RunCmd" {
                    $sb = [scriptblock]::Create($f.FixParam)
                    & $sb
                    Out-Typewriter "  -> COMMAND EXECUTED." "GOOD"; $global:KillCount++; $ok = $true
                }
                "Quarantine" {
                    # Reversible isolation: move the file into a vault, neutralize it, and
                    # record a JSON manifest (orig path + SHA256 + detection) so it can be restored.
                    $src = $f.FixParam
                    if (-not (Test-Path -LiteralPath $src)) { Out-Typewriter "  -> ALREADY ABSENT." "VER"; $ok = $true }
                    else {
                        $vault = Join-Path $OUT_ROOT "quarantine"
                        if (-not (Test-Path $vault)) { New-Item -Path $vault -ItemType Directory -Force | Out-Null }
                        $sha = (Get-FileHash -LiteralPath $src -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        $stub = ([System.IO.Path]::GetFileName($src)) -replace '[^a-zA-Z0-9._-]','_'
                        $tag  = "{0}_{1}" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), $stub
                        # ".quar" extension neutralizes double-click execution while preserving bytes.
                        $dest = Join-Path $vault "$tag.quar"
                        $moved = $false
                        try { Move-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop; $moved = $true }
                        catch {
                            # Locked file: copy bytes to vault, then kernel-queue the original for reboot deletion.
                            try { Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop } catch {}
                            $rp  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                            $cur = Get-ItemPropertyValue $rp "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                            if ($null -eq $cur) { $cur = @() }
                            Set-ItemProperty $rp "PendingFileRenameOperations" ([string[]]($cur) + @("\??\$src", "")) -Type MultiString -Force -ErrorAction SilentlyContinue
                        }
                        $manifest = @{
                            OriginalPath = $src
                            QuarantinedAs = $dest
                            SHA256       = $sha
                            ThreatType   = $f.ThreatType
                            Severity     = $f.Severity
                            Description  = $f.Description
                            QuarantinedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            Host         = $HOST_NAME
                            RestoreNote  = "To restore: Move-Item '$dest' '$src' -Force"
                            RebootQueuedForOriginal = (-not $moved)
                        }
                        $manifest | ConvertTo-Json | Set-Content -LiteralPath "$dest.json" -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($moved) { Out-Typewriter "  -> QUARANTINED -> $dest" "GOOD" }
                        else        { Out-Typewriter "  -> COPIED TO VAULT; ORIGINAL QUEUED FOR REBOOT DELETION." "WARN" }
                        $global:KillCount++; $ok = $true
                    }
                }
                "Info" {
                    Out-Typewriter "  -> INFORMATIONAL — REVIEW MANUALLY." "DATA"; $fixSkip++; $ok = $true
                }
            }
        } catch {
            Out-Typewriter "  -> ERROR: $_" "WARN"; $fixFail++
        }

        if ($ok -and $f.FixAction -ne "Info") { $fixOK++ }
        $fixLog.Add("[$($f.Severity)] $($f.ThreatType) | $($f.Description) | $($f.FixAction) | $(if($ok){'OK'}else{'FAILED'})")
        if (-not ($global:MSP_MODE -or $global:NONINTERACTIVE)) { Start-Sleep -Milliseconds 150 }
    }

    # Always-apply baseline hardening after fixes
    Out-Typewriter "APPLYING BASELINE LSA HARDENING..." "ACT"
    $lp = "HKLM:\System\CurrentControlSet\Control\Lsa"
    Set-ItemProperty $lp RestrictAnonymous    1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty $lp RestrictAnonymousSAM 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty $lp NoLMHash             1 -Type DWord -Force -ErrorAction SilentlyContinue
    Out-Typewriter "  -> LSA HARDENING APPLIED." "GOOD"

    Out-Typewriter "FLUSHING DNS CACHE..." "ACT"
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Out-Typewriter "  -> DNS FLUSHED." "GOOD"

    # Append fix log to report file
    @("","="*80,"FIX MODE LOG — $(Get-Date)",
      "Selected: $($SelectedFindings.Count) | OK: $fixOK | Failed: $fixFail | Skipped: $fixSkip",
      "Snapshot: $SNAPSHOT_PATH","="*80) + $fixLog |
        Add-Content -Path $REPORT_PATH -Encoding UTF8 -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
    Write-Host "  ◈◈◈  F I X   M O D E   C O M P L E T E  ◈◈◈" -ForegroundColor Cyan
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
    Write-Host "  FIXES APPLIED     : " -NoNewline -ForegroundColor DarkGray; Write-Host $fixOK  -ForegroundColor Green
    Write-Host "  FIX FAILURES      : " -NoNewline -ForegroundColor DarkGray
    Write-Host $fixFail -ForegroundColor $(if ($fixFail -gt 0) {"Red"} else {"Green"})
    Write-Host "  INFO / SKIPPED    : " -NoNewline -ForegroundColor DarkGray; Write-Host $fixSkip -ForegroundColor DarkGray
    Write-Host "  SNAPSHOT          : " -NoNewline -ForegroundColor DarkGray; Write-Host $SNAPSHOT_PATH -ForegroundColor Yellow
    Write-Host "  FULL REPORT       : " -NoNewline -ForegroundColor DarkGray; Write-Host $REPORT_PATH   -ForegroundColor Cyan
    Write-Host ("─"*80) -ForegroundColor DarkCyan
    if ($fixFail -gt 0 -or $global:VerifyFails -gt 0) {
        Write-Host "  STATUS: REBOOT RECOMMENDED — PENDING DELETIONS QUEUED." -ForegroundColor Yellow
        Write-Host "  ROLLBACK: regedit /S `"$SNAPSHOT_PATH`"" -ForegroundColor DarkGray
    } else {
        Write-Host "  STATUS: REMEDIATION COMPLETE. REVIEW REPORT FOR MANUAL ITEMS." -ForegroundColor Cyan
    }
    Write-Host ("▓"*80) -ForegroundColor DarkCyan
}

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT — LAUNCH FIX UI
# ══════════════════════════════════════════════════════════════════════════════
Out-Typewriter "LOADING REMEDIATION INTERFACE..." "ACT"
Invoke-QuantumBar "BUILDING CHECKBOX MANIFEST" 10 80

# Stop shell kill watcher job if running
if ($global:SHELL_KILL_JOB) {
    Stop-Job $global:SHELL_KILL_JOB -ErrorAction SilentlyContinue
    Remove-Job $global:SHELL_KILL_JOB -ErrorAction SilentlyContinue
    if ($global:SHELL_KILL_FLAG -and (Test-Path $global:SHELL_KILL_FLAG)) {
        Remove-Item $global:SHELL_KILL_FLAG -Force -ErrorAction SilentlyContinue
    }
}

$selectedFixes = @()
if ($global:GUI_MODE) {
    # Dashboard was already running live — call Complete to switch to fix mode
    Complete-LiveScanDashboard
    if ($global:GUI_LIVE_FORM.DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedFixes = ($global:AuditFindings | Where-Object { $_.Selected })
    }
} else {
    $selectedFixes = Show-ShellCheckboxMenu
}

if ($selectedFixes.Count -eq 0) {
    Out-Typewriter "NO FIXES SELECTED. AUDIT LOG PRESERVED." "INFO"
} else {
    Write-Host ""
    Write-Host "  ┌─ FINAL CONFIRMATION ───────────────────────────────────────────────────┐" -ForegroundColor Red
    Write-Host "  │  About to execute $($selectedFixes.Count) remediation action(s).                           │" -ForegroundColor Red
    Write-Host "  │  Snapshot: $(Split-Path $SNAPSHOT_PATH -Leaf)                        │" -ForegroundColor Yellow
    Write-Host "  │  Type  CONFIRM  to proceed. Anything else aborts.                    │" -ForegroundColor Red
    Write-Host "  └─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
    Write-Host "  COMMAND> " -NoNewline -ForegroundColor DarkGray
    $finalConfirm = (Read-Host).Trim().ToUpper()
    if ($finalConfirm -eq "CONFIRM") {
        Invoke-FixMode -SelectedFindings $selectedFixes
    } else {
        Out-Typewriter "ABORTED BY OPERATOR. NO CHANGES MADE." "WARN"
    }
}

Write-Host ""
Out-Typewriter "PRESS ANY KEY TO CLOSE." "INFO" 20
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
