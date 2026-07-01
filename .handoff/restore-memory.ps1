<#
    restore-memory.ps1 — reinstate this project's Claude Code session memory on a new machine.

    Claude Code stores per-project memory at:
        %USERPROFILE%\.claude\projects\<path-hash>\memory\
    where <path-hash> is the project's ABSOLUTE path with ':' '\' '/' each replaced by '-'.
    Claude Code derives that hash from wherever the repo lives, so this script derives it the
    SAME way from its own location — meaning it works no matter where you cloned the repo.

    Run once after cloning:  powershell -ExecutionPolicy Bypass -File .handoff\restore-memory.ps1
    Then start Claude Code in the repo and the memory (MEMORY.md index + notes) auto-loads.
#>
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Split-Path -Parent $PSScriptRoot)).Path.TrimEnd('\')
$hash     = ($repoRoot -replace '[:\\/]', '-')
$dest     = Join-Path $env:USERPROFILE ".claude\projects\$hash\memory"
$src      = Join-Path $PSScriptRoot 'session-memory'

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $src '*.md') -Destination $dest -Force

Write-Host "Repo root : $repoRoot"
Write-Host "Path hash : $hash"
Write-Host "Restored  : $((Get-ChildItem $dest -Filter *.md).Count) memory file(s) -> $dest" -ForegroundColor Green
Write-Host "Now start Claude Code in this repo; MEMORY.md and the WS0/WS1/WS2 notes will load." -ForegroundColor Green
