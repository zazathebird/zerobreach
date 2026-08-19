# The runspace scripts live inside @'...'@ here-strings, so ParseFile on the outer
# file never validates them. Extract each and parse it as its own script.
$src = (Resolve-Path 'ZeroBreach-Server.ps1').Path
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($src,[ref]$t,[ref]$e)
if ($e.Count) { Write-Host "outer file has parse errors!" -ForegroundColor Red; exit 1 }

$assigns = $ast.FindAll({
    param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
              $n.Right.Extent.Text -like "@'*"
}, $true)

$bad = 0
foreach ($a in $assigns) {
    $name = $a.Left.Extent.Text
    $raw  = $a.Right.Extent.Text
    # strip the @' ... '@ wrapper
    $body = $raw.Substring(2)
    $body = $body.Substring(0, $body.LastIndexOf("'@"))
    $ee = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($body, [ref]$null, [ref]$ee)
    if ($ee.Count) {
        $bad++
        Write-Host "PARSE FAIL: $name ($($body.Split("`n").Count) lines)" -ForegroundColor Red
        $ee | Select-Object -First 5 | ForEach-Object {
            Write-Host ("   line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message)
        }
    } else {
        Write-Host ("PARSE OK  : {0}  ({1} lines)" -f $name, $body.Split("`n").Count) -ForegroundColor Green
    }
}
Write-Host ("`n{0} embedded runspace script(s) checked, {1} bad" -f $assigns.Count, $bad) -ForegroundColor $(if($bad -eq 0){'Green'}else{'Red'})
