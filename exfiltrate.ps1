$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BranchName = "quarantine-work-dump-$Timestamp"
$RepoUrl = "origin"

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " ZERO-COLLISION EXFILTRATION PROTOCOL INITIATED  " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

try {
# 1. Ensure we don't accidentally try to commit empty air
$GitStatus = git status --porcelain
if ([string]::IsNullOrWhiteSpace($GitStatus)) {
Write-Host "[INFO] No changes detected. Your working directory is clean." -ForegroundColor Green
Write-Host "Nothing to exfiltrate. Go home." -ForegroundColor Green
exit
}

Write-Host "[!] Changes detected. Staging payload..." -ForegroundColor Cyan

# 2. Create and switch to the completely isolated quarantine branch
git checkout -b $BranchName | Out-Null
Write-Host "[OK] Isolated environment created: $BranchName" -ForegroundColor Green

# 3. Add all modified, deleted, and untracked files to the staging area
git add .

# 4. Seal the container with a descriptive commit message
$CommitMsg = "Raw automated session dump from work rig - $Timestamp"
git commit -m $CommitMsg | Out-Null
Write-Host "[OK] Payload sealed locally." -ForegroundColor Green

# 5. Shove it up to GitHub. The '-u' sets the upstream link so it tracks properly.
Write-Host "[!] Pushing payload to GitHub ($RepoUrl)..." -ForegroundColor Cyan
git push -u origin $BranchName

Write-Host "=================================================" -ForegroundColor Green
Write-Host " EXFILTRATION SUCCESSFUL. CODE IS SAFE IN CLOUD. " -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host "When you get home, run: git fetch && git checkout $BranchName" -ForegroundColor Yellow


} catch {
Write-Host "[ERROR] Catastrophic failure during exfiltration sequence." -ForegroundColor Red
Write-Host $_.Exception.Message -ForegroundColor Red
Write-Host "Dropping you back to main branch..." -ForegroundColor Yellow

# Attempt to gracefully drop back to main if the branch creation failed
git checkout main | Out-Null
exit 1


}