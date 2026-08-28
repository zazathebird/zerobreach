# Extract the real guard functions from the shipped source via AST (no retyping).
$src = (Resolve-Path 'Scythe-Server.ps1').Path
$t=$null;$e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($src,[ref]$t,[ref]$e)
$want='Test-RequestAuth','Test-RequestOrigin','Add-SecurityHeaders'
$fns=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $want -contains $n.Name},$true)
foreach($f in $fns){ . ([scriptblock]::Create($f.Extent.Text)) }
Write-Host ("Extracted: " + (($fns | ForEach-Object Name) -join ', ')) -ForegroundColor Cyan

$script:AUTH_TOKEN = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
$script:ALLOWED_ORIGINS = @('http://127.0.0.1:51234')

function New-Ctx {
  param([hashtable]$Query=@{}, [hashtable]$Headers=@{})
  $q=[System.Collections.Specialized.NameValueCollection]::new()
  foreach($k in $Query.Keys){ $q.Add($k,$Query[$k]) }
  $h=[System.Collections.Specialized.NameValueCollection]::new()
  foreach($k in $Headers.Keys){ $h.Add($k,$Headers[$k]) }
  [pscustomobject]@{ Request = [pscustomobject]@{ QueryString=$q; Headers=$h } }
}

$pass=0;$fail=0
function Check($name,$actual,$expect){
  if($actual -eq $expect){ $script:pass++; Write-Host ("  PASS  {0,-58} -> {1}" -f $name,$actual) -ForegroundColor Green }
  else { $script:fail++; Write-Host ("  FAIL  {0,-58} -> got {1}, expected {2}" -f $name,$actual,$expect) -ForegroundColor Red }
}

Write-Host "`n== Test-RequestAuth ==" -ForegroundColor Yellow
Check 'no token at all (the drive-by attacker)'      (Test-RequestAuth (New-Ctx)) $false
Check 'empty token ?t='                              (Test-RequestAuth (New-Ctx @{t=''})) $false
Check 'wrong token'                                  (Test-RequestAuth (New-Ctx @{t='deadbeef'})) $false
Check 'correct token, wrong case (ordinal compare)'  (Test-RequestAuth (New-Ctx @{t='A1B2C3D4E5F60718293A4B5C6D7E8F90'})) $false
Check 'token prefix only'                            (Test-RequestAuth (New-Ctx @{t='a1b2c3d4'})) $false
Check 'token + trailing junk'                        (Test-RequestAuth (New-Ctx @{t='a1b2c3d4e5f60718293a4b5c6d7e8f90X'})) $false
Check 'correct token in ?t='                         (Test-RequestAuth (New-Ctx @{t='a1b2c3d4e5f60718293a4b5c6d7e8f90'})) $true
Check 'correct token in X-SCYTHE-Token header'           (Test-RequestAuth (New-Ctx @{} @{'X-SCYTHE-Token'='a1b2c3d4e5f60718293a4b5c6d7e8f90'})) $true
Check 'wrong token in header'                        (Test-RequestAuth (New-Ctx @{} @{'X-SCYTHE-Token'='nope'})) $false

Write-Host "`n== Test-RequestOrigin ==" -ForegroundColor Yellow
Check 'no Origin (same-origin GET / local tool)'     (Test-RequestOrigin (New-Ctx)) $true
Check 'own origin'                                   (Test-RequestOrigin (New-Ctx @{} @{Origin='http://127.0.0.1:51234'})) $true
Check 'evil.example'                                 (Test-RequestOrigin (New-Ctx @{} @{Origin='https://evil.example'})) $false
Check 'localhost alias (unbound host)'               (Test-RequestOrigin (New-Ctx @{} @{Origin='http://localhost:51234'})) $false
Check 'own IP, different port'                       (Test-RequestOrigin (New-Ctx @{} @{Origin='http://127.0.0.1:9999'})) $false
Check 'https scheme confusion'                       (Test-RequestOrigin (New-Ctx @{} @{Origin='https://127.0.0.1:51234'})) $false
Check 'prefix-extension attack'                      (Test-RequestOrigin (New-Ctx @{} @{Origin='http://127.0.0.1:51234.evil.com'})) $false
Check 'null Origin (sandboxed iframe)'               (Test-RequestOrigin (New-Ctx @{} @{Origin='null'})) $false

Write-Host "`n== Full C1 attack chain (both guards, as the router runs them) ==" -ForegroundColor Yellow
$attack = New-Ctx @{} @{Origin='https://evil.example'}
Check 'evil page POST /api/remediate: origin gate'   (Test-RequestOrigin $attack) $false
Check 'evil page POST /api/remediate: token gate'    (Test-RequestAuth   $attack) $false
$sweep = New-Ctx
Check 'tokenless GET /api/sysinfo (port oracle)'     (Test-RequestAuth $sweep) $false

Write-Host ("`n{0} passed, {1} failed" -f $pass,$fail) -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
